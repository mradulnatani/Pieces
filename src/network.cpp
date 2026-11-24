#include "pieces/network.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <system_error>

#include "pieces/json.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

struct FileLockGuard {
    int fd{-1};
    explicit FileLockGuard(const fs::path& lock_path) {
        fs::create_directories(lock_path.parent_path());
        fd = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0644);
        if (fd < 0) {
            throw std::system_error(errno, std::generic_category(), "open(" + lock_path.string() + ")");
        }
        if (::flock(fd, LOCK_EX) != 0) {
            int err = errno;
            ::close(fd);
            fd = -1;
            throw std::system_error(err, std::generic_category(), "flock(" + lock_path.string() + ")");
        }
    }
    ~FileLockGuard() {
        if (fd >= 0) {
            ::flock(fd, LOCK_UN);
            ::close(fd);
        }
    }
    FileLockGuard(const FileLockGuard&) = delete;
    FileLockGuard& operator=(const FileLockGuard&) = delete;
};

JsonObject read_ipam_leases(const fs::path& leases_path) {
    std::error_code ec;
    if (!fs::is_regular_file(leases_path, ec)) {
        return {};
    }
    std::ifstream in(leases_path);
    if (!in) return {};
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    try {
        JsonValue v = JsonValue::parse(s);
        if (v.is_object()) return v.as_object();
    } catch (const std::exception&) {
    }
    return {};
}

void write_ipam_leases(const fs::path& leases_path, const JsonObject& leases) {
    fs::path tmp = leases_path;
    tmp += ".tmp." + std::to_string(::getpid());
    {
        std::ofstream out(tmp);
        if (!out) return;
        out << JsonValue(leases).dump(2) << "\n";
    }
    std::error_code ec;
    fs::rename(tmp, leases_path, ec);
}

bool command_exists(const std::string& cmd) {
    const char* path_env = std::getenv("PATH");
    if (!path_env) {
        return false;
    }
    std::string path_str(path_env);
    size_t start = 0;
    while (start <= path_str.size()) {
        size_t colon = path_str.find(':', start);
        std::string dir = (colon == std::string::npos) ? path_str.substr(start) : path_str.substr(start, colon - start);
        if (!dir.empty()) {
            fs::path candidate = fs::path(dir) / cmd;
            if (::access(candidate.c_str(), X_OK) == 0) {
                return true;
            }
        }
        if (colon == std::string::npos) {
            break;
        }
        start = colon + 1;
    }
    return false;
}

void write_proc_sysctl(const char* path, const char* value) {
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        return;
    }
    {
        std::ifstream in(path);
        std::string cur;
        if (in >> cur && cur == value) {
            return;
        }
    }
    std::ofstream out(path);
    if (out) {
        out << value << "\n";
    }
}

void ensure_nat_masquerade(const std::string& bridge_name, const std::string& subnet_cidr) {
    if (!command_exists("iptables")) {
        return;
    }
    std::vector<std::string> check_cmd = {
        "iptables", "-t", "nat", "-C", "POSTROUTING",
        "-s", subnet_cidr, "!", "-o", bridge_name, "-j", "MASQUERADE",
    };
    if (run_host_cmd(check_cmd, true) != 0) {
        check_cmd[3] = "-A";
        if (run_host_cmd(check_cmd, false) != 0) {
            std::cerr << "NETWORK: Warning: failed to add NAT masquerade rule.\n";
        }
    }
}

std::vector<std::vector<std::string>> build_port_iptables_rules(
    const ContainerNetwork& plan,
    const PortMapping& pm,
    const char* action) {
    std::string dest = plan.container_ip + ":" + std::to_string(pm.container_port);
    std::string hport = std::to_string(pm.host_port);
    std::string cport = std::to_string(pm.container_port);

    std::vector<std::string> prerouting = {
        "iptables", "-t", "nat", action, "PREROUTING",
        "!", "-i", plan.bridge_name,
        "-p", pm.protocol, "--dport", hport,
        "-j", "DNAT", "--to-destination", dest,
    };
    if (!pm.host_ip.empty()) {
        prerouting.insert(prerouting.begin() + 5, {"-d", pm.host_ip});
    }

    std::vector<std::string> output_local = {
        "iptables", "-t", "nat", action, "OUTPUT",
        "-d", pm.host_ip.empty() ? "127.0.0.1" : pm.host_ip,
        "-p", pm.protocol, "--dport", hport,
        "-j", "DNAT", "--to-destination", dest,
    };

    std::vector<std::string> forward_in = {
        "iptables", action, "FORWARD",
        "-p", pm.protocol, "-d", plan.container_ip, "--dport", cport,
        "-j", "ACCEPT",
    };

    return {prerouting, output_local, forward_in};
}

int parse_port_number(const std::string& s) {
    if (s.empty() || !std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); })) {
        throw std::invalid_argument("Invalid port number: '" + s + "'");
    }
    int port = std::stoi(s);
    if (port < 1 || port > 65535) {
        throw std::invalid_argument("Port out of range (1-65535): '" + s + "'");
    }
    return port;
}

}  // namespace

PortMapping parse_port_mapping(const std::string& spec) {
    std::string addr_part = spec;
    std::string proto = "tcp";
    auto slash = spec.rfind('/');
    if (slash != std::string::npos) {
        proto = spec.substr(slash + 1);
        for (char& c : proto) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (proto != "tcp" && proto != "udp") {
            throw std::invalid_argument("Unsupported port protocol '" + proto + "'; expected tcp or udp");
        }
        addr_part = spec.substr(0, slash);
    }

    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t colon = addr_part.find(':', start);
        if (colon == std::string::npos) {
            parts.push_back(addr_part.substr(start));
            break;
        }
        parts.push_back(addr_part.substr(start, colon - start));
        start = colon + 1;
    }

    PortMapping pm;
    pm.protocol = proto;
    if (parts.size() == 2) {
        pm.host_port = parse_port_number(parts[0]);
        pm.container_port = parse_port_number(parts[1]);
    } else if (parts.size() == 3) {
        pm.host_ip = parts[0];
        pm.host_port = parse_port_number(parts[1]);
        pm.container_port = parse_port_number(parts[2]);
    } else {
        throw std::invalid_argument(
            "Invalid port specification '" + spec + "'; expected [HOST_IP:]HOST_PORT:CONTAINER_PORT[/tcp|udp]");
    }
    return pm;
}

std::string format_port_mapping(const PortMapping& pm) {
    std::string out;
    if (!pm.host_ip.empty()) {
        out += pm.host_ip + ":";
    }
    out += std::to_string(pm.host_port) + "->" + std::to_string(pm.container_port) + "/" + pm.protocol;
    return out;
}

int run_host_cmd(const std::vector<std::string>& args, bool quiet) {
    if (args.empty()) {
        return -1;
    }
    pid_t pid = ::fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        if (quiet) {
            int devnull = ::open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                ::dup2(devnull, STDOUT_FILENO);
                ::dup2(devnull, STDERR_FILENO);
                ::close(devnull);
            }
        }
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& a : args) {
            argv.push_back(const_cast<char*>(a.c_str()));
        }
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 1;
}

bool setup_host_network(
    const std::string& bridge_name,
    const std::string& bridge_cidr,
    const std::string& subnet_cidr,
    bool enable_nat) {
    if (!command_exists("ip")) {
        std::cerr << "NETWORK: Warning: `ip` command not found; skipping host network setup.\n";
        return false;
    }

    if (run_host_cmd({"ip", "link", "show", bridge_name}, true) != 0) {
        std::cout << "HOST: Creating bridge '" << bridge_name << "' (" << bridge_cidr << ").\n";
        if (run_host_cmd({"ip", "link", "add", "name", bridge_name, "type", "bridge"}, false) != 0 ||
            run_host_cmd({"ip", "addr", "add", bridge_cidr, "dev", bridge_name}, false) != 0 ||
            run_host_cmd({"ip", "link", "set", bridge_name, "up"}, false) != 0) {
            std::cerr << "NETWORK: Warning: failed to create bridge '" << bridge_name << "'.\n";
            return false;
        }
    } else {
        run_host_cmd({"ip", "link", "set", bridge_name, "up"}, true);
    }

    if (enable_nat) {
        write_proc_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
        std::string localnet_path = "/proc/sys/net/ipv4/conf/" + bridge_name + "/route_localnet";
        write_proc_sysctl(localnet_path.c_str(), "1");
        ensure_nat_masquerade(bridge_name, subnet_cidr);
    }
    return true;
}

std::string allocate_container_ip(
    const std::string& containers_dir,
    const std::string& owner_id) {
    fs::path cdir(containers_dir);
    FileLockGuard lock(cdir / ".ipam.lock");

    std::set<std::string> used_ips;
    fs::path leases_path = cdir / ".ipam_leases.json";
    JsonObject leases = read_ipam_leases(leases_path);

    // Prune leases for containers that are no longer running and collect active ones
    JsonObject clean_leases;
    for (const auto& [cid, ip_val] : leases) {
        if (!ip_val.is_string()) continue;
        fs::path meta_path = cdir / cid / "meta.json";
        std::error_code ec;
        if (!fs::is_regular_file(meta_path, ec)) {
            continue;
        }
        std::ifstream in(meta_path);
        if (!in) continue;
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        try {
            JsonValue parsed = JsonValue::parse(content);
            const JsonValue* status = parsed.find("status");
            if (status && status->is_string() && status->as_string() == "running") {
                used_ips.insert(ip_val.as_string());
                clean_leases[cid] = ip_val;
            }
        } catch (const std::exception&) {
        }
    }

    std::error_code ec;
    if (fs::is_directory(cdir, ec)) {
        for (const auto& entry : fs::directory_iterator(cdir, ec)) {
            if (!entry.is_directory(ec)) continue;
            fs::path meta_path = entry.path() / "meta.json";
            if (!fs::is_regular_file(meta_path, ec)) continue;
            std::ifstream in(meta_path);
            if (!in) continue;
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            try {
                JsonValue parsed = JsonValue::parse(content);
                if (!parsed.is_object()) continue;
                const JsonValue* status = parsed.find("status");
                const JsonValue* ip = parsed.find("ip");
                if (status && status->is_string() && status->as_string() == "running" &&
                    ip && ip->is_string() && !ip->as_string().empty()) {
                    used_ips.insert(ip->as_string());
                }
            } catch (const std::exception&) {
            }
        }
    }

    for (int host_octet = 2; host_octet < 255; ++host_octet) {
        std::string candidate = "10.0.0." + std::to_string(host_octet);
        if (!used_ips.contains(candidate)) {
            if (!owner_id.empty()) {
                clean_leases[owner_id] = candidate;
            }
            write_ipam_leases(leases_path, clean_leases);
            return candidate;
        }
    }
    throw std::runtime_error("No free IP addresses left in 10.0.0.0/24");
}

void release_container_ip(const std::string& containers_dir, const std::string& owner_id) {
    if (owner_id.empty()) return;
    fs::path cdir(containers_dir);
    std::error_code ec;
    if (!fs::is_directory(cdir, ec)) return;
    FileLockGuard lock(cdir / ".ipam.lock");
    fs::path leases_path = cdir / ".ipam_leases.json";
    JsonObject leases = read_ipam_leases(leases_path);
    if (leases.erase(owner_id) > 0) {
        write_ipam_leases(leases_path, leases);
    }
}

ContainerNetwork build_network_plan(
    const std::string& container_id,
    const std::string& containers_dir,
    const std::vector<PortMapping>& ports) {
    std::string cleaned = container_id;
    cleaned.erase(std::remove(cleaned.begin(), cleaned.end(), '-'), cleaned.end());
    std::string short_id = cleaned.substr(0, 8);
    return {
        DEFAULT_BRIDGE,
        DEFAULT_GATEWAY_IP,
        allocate_container_ip(containers_dir, container_id),
        24,
        "vp-" + short_id,
        "vc-" + short_id,
        ports,
    };
}

bool setup_port_forwarding(const ContainerNetwork& plan) {
    if (plan.ports.empty()) {
        return true;
    }
    if (!command_exists("iptables")) {
        std::cerr << "NETWORK: Warning: `iptables` not found; skipping -p port forwarding.\n";
        return false;
    }
    write_proc_sysctl("/proc/sys/net/ipv4/conf/all/route_localnet", "1");
    for (const auto& pm : plan.ports) {
        for (const auto& cmd : build_port_iptables_rules(plan, pm, "-A")) {
            if (run_host_cmd(cmd, false) != 0) {
                std::cerr << "NETWORK: Warning: failed to apply port rule for "
                          << format_port_mapping(pm) << "\n";
                cleanup_port_forwarding(plan);
                return false;
            }
        }
    }
    return true;
}

void cleanup_port_forwarding(const ContainerNetwork& plan) {
    if (plan.ports.empty() || !command_exists("iptables")) {
        return;
    }
    for (const auto& pm : plan.ports) {
        for (const auto& cmd : build_port_iptables_rules(plan, pm, "-D")) {
            run_host_cmd(cmd, true);
        }
    }
}

bool setup_container_network(int pid, const ContainerNetwork& plan) {
    if (!command_exists("ip")) {
        return false;
    }
    std::string pid_str = std::to_string(pid);
    if (run_host_cmd({"ip", "link", "add", plan.host_veth, "type", "veth", "peer", "name", plan.peer_veth}, false) != 0 ||
        run_host_cmd({"ip", "link", "set", plan.host_veth, "master", plan.bridge_name}, false) != 0 ||
        run_host_cmd({"ip", "link", "set", plan.host_veth, "up"}, false) != 0 ||
        run_host_cmd({"ip", "link", "set", plan.peer_veth, "netns", pid_str}, false) != 0) {
        cleanup_container_network(plan.host_veth);
        return false;
    }

    std::vector<std::string> netns_prefix;
    if (command_exists("nsenter")) {
        netns_prefix = {"nsenter", "--net=/proc/" + pid_str + "/ns/net"};
    } else {
        netns_prefix = {"ip", "netns", "exec", pid_str};
    }

    auto run_in_netns = [&](std::vector<std::string> cmd) -> bool {
        std::vector<std::string> full = netns_prefix;
        full.insert(full.end(), cmd.begin(), cmd.end());
        return run_host_cmd(full, false) == 0;
    };

    std::string cidr = plan.container_ip + "/" + std::to_string(plan.prefix_len);
    if (!run_in_netns({"ip", "link", "set", "lo", "up"}) ||
        !run_in_netns({"ip", "link", "set", plan.peer_veth, "name", "eth0"}) ||
        !run_in_netns({"ip", "addr", "add", cidr, "dev", "eth0"}) ||
        !run_in_netns({"ip", "link", "set", "eth0", "up"}) ||
        !run_in_netns({"ip", "route", "add", "default", "via", plan.gateway_ip})) {
        cleanup_container_network(plan.host_veth);
        return false;
    }

    setup_port_forwarding(plan);
    return true;
}

void cleanup_container_network(const std::string& host_veth) {
    if (host_veth.empty() || !command_exists("ip")) {
        return;
    }
    run_host_cmd({"ip", "link", "del", host_veth}, true);
}

}  // namespace pieces

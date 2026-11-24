#include "pieces/network.hpp"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
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

void enable_ip_forwarding() {
    const char* fwd_path = "/proc/sys/net/ipv4/ip_forward";
    std::error_code ec;
    if (!fs::exists(fwd_path, ec)) {
        return;
    }
    {
        std::ifstream in(fwd_path);
        std::string val;
        if (in >> val && val == "1") {
            return;
        }
    }
    std::ofstream out(fwd_path);
    if (!out) {
        std::cerr << "NETWORK: Warning: could not enable IPv4 forwarding.\n";
        return;
    }
    out << "1\n";
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

}  // namespace

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
        enable_ip_forwarding();
        ensure_nat_masquerade(bridge_name, subnet_cidr);
    }
    return true;
}

std::string allocate_container_ip(const std::string& containers_dir) {
    std::set<std::string> used_ips;
    std::error_code ec;
    if (fs::is_directory(containers_dir, ec)) {
        for (const auto& entry : fs::directory_iterator(containers_dir, ec)) {
            fs::path meta_path = entry.path() / "meta.json";
            if (!fs::is_regular_file(meta_path, ec)) {
                continue;
            }
            std::ifstream in(meta_path);
            if (!in) {
                continue;
            }
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
            return candidate;
        }
    }
    throw std::runtime_error("No free IP addresses left in 10.0.0.0/24");
}

ContainerNetwork build_network_plan(const std::string& container_id, const std::string& containers_dir) {
    std::string cleaned = container_id;
    cleaned.erase(std::remove(cleaned.begin(), cleaned.end(), '-'), cleaned.end());
    std::string short_id = cleaned.substr(0, 8);
    return {
        DEFAULT_BRIDGE,
        DEFAULT_GATEWAY_IP,
        allocate_container_ip(containers_dir),
        24,
        "vp-" + short_id,
        "vc-" + short_id,
    };
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
    return true;
}

void cleanup_container_network(const std::string& host_veth) {
    if (host_veth.empty() || !command_exists("ip")) {
        return;
    }
    run_host_cmd({"ip", "link", "del", host_veth}, true);
}

}  // namespace pieces

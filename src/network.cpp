#include "pieces/network.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <system_error>

#include "pieces/filesystem.hpp"
#include "pieces/json.hpp"
#include "pieces/registry.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

struct FileLockGuard {
    int fd{-1};
    explicit FileLockGuard(const fs::path& lock_path) {
        fs::create_directories(lock_path.parent_path());
        fd = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0644);
        if (fd < 0) throw std::system_error(errno, std::generic_category(), "open(" + lock_path.string() + ")");
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

fs::path ipam_leases_path_for(const fs::path& cdir, const std::string& network_name) {
    if (network_name.empty() || network_name == "bridge") {
        return cdir / ".ipam_leases.json";
    }
    std::string safe = validate_name(network_name, "network");
    std::replace(safe.begin(), safe.end(), ':', '_');
    return cdir / (".ipam_leases_" + safe + ".json");
}

JsonObject read_ipam_leases(const fs::path& leases_path) {
    std::error_code ec;
    if (!fs::is_regular_file(leases_path, ec)) return {};
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
    if (!path_env) return false;
    std::string path_str(path_env);
    size_t start = 0;
    while (start <= path_str.size()) {
        size_t colon = path_str.find(':', start);
        std::string dir = (colon == std::string::npos) ? path_str.substr(start) : path_str.substr(start, colon - start);
        if (!dir.empty() && ::access((fs::path(dir) / cmd).c_str(), X_OK) == 0) return true;
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    return false;
}

void write_proc_sysctl(const char* path, const char* value) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return;
    {
        std::ifstream in(path);
        std::string cur;
        if (in >> cur && cur == value) return;
    }
    std::ofstream out(path);
    if (out) out << value << "\n";
}

void ensure_iptables_rule(std::vector<std::string> rule_args) {
    if (!command_exists("iptables") || rule_args.size() < 2) return;
    std::vector<std::string> check = {"iptables"};
    check.insert(check.end(), rule_args.begin(), rule_args.end());
    for (auto& arg : check) {
        if (arg == "-A" || arg == "-I") {
            arg = "-C";
            break;
        }
    }
    if (run_host_cmd(check, true) != 0) {
        std::vector<std::string> apply = {"iptables"};
        apply.insert(apply.end(), rule_args.begin(), rule_args.end());
        run_host_cmd(apply, true);
    }
}

void ensure_nat_masquerade(const std::string& bridge_name, const std::string& subnet_cidr) {
    ensure_iptables_rule({"-t", "nat", "-A", "POSTROUTING", "-s", subnet_cidr, "!", "-o", bridge_name, "-j", "MASQUERADE"});
    ensure_iptables_rule({"-A", "FORWARD", "-i", bridge_name, "-j", "ACCEPT"});
    ensure_iptables_rule({"-A", "FORWARD", "-o", bridge_name, "-j", "ACCEPT"});
}

void ensure_bridge_isolation(const std::string& bridge_name) {
    ensure_iptables_rule({"-I", "FORWARD", "-i", bridge_name, "-o", bridge_name, "-j", "DROP"});
    ensure_iptables_rule({"-I", "INPUT", "-i", bridge_name, "-j", "DROP"});
    ensure_iptables_rule({"-I", "INPUT", "-i", bridge_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT"});
    ensure_iptables_rule({"-I", "INPUT", "-i", bridge_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"});
    ensure_iptables_rule({"-I", "INPUT", "-i", bridge_name, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
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
    if (!pm.host_ip.empty()) prerouting.insert(prerouting.begin() + 5, {"-d", pm.host_ip});

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
    if (port < 1 || port > 65535) throw std::invalid_argument("Port out of range (1-65535): '" + s + "'");
    return port;
}

int run_host_cmd_with_stdin(
    const std::vector<std::string>& args,
    const std::string& stdin_data,
    bool quiet) {
    if (args.empty()) return -1;
    int in_pipe[2]{-1, -1};
    if (::pipe(in_pipe) != 0) return -1;

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(in_pipe[0]);
        ::close(in_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        ::close(in_pipe[1]);
        ::dup2(in_pipe[0], STDIN_FILENO);
        ::close(in_pipe[0]);
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
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }

    ::close(in_pipe[0]);
    size_t off = 0;
    while (off < stdin_data.size()) {
        ssize_t w = ::write(in_pipe[1], stdin_data.data() + off, stdin_data.size() - off);
        if (w <= 0) break;
        off += static_cast<size_t>(w);
    }
    ::close(in_pipe[1]);

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

class NetlinkSocket {
public:
    NetlinkSocket() {
        fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd_ < 0) throw std::system_error(errno, std::generic_category(), "socket(AF_NETLINK)");
        sockaddr_nl addr{};
        addr.nl_family = AF_NETLINK;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            int err = errno;
            ::close(fd_);
            fd_ = -1;
            throw std::system_error(err, std::generic_category(), "bind(AF_NETLINK)");
        }
    }
    ~NetlinkSocket() {
        if (fd_ >= 0) ::close(fd_);
    }
    NetlinkSocket(const NetlinkSocket&) = delete;
    NetlinkSocket& operator=(const NetlinkSocket&) = delete;

    void send_and_ack(nlmsghdr* nlh) {
        nlh->nlmsg_seq = ++seq_;
        sockaddr_nl dst{};
        dst.nl_family = AF_NETLINK;

        iovec iov{nlh, nlh->nlmsg_len};
        msghdr msg{};
        msg.msg_name = &dst;
        msg.msg_namelen = sizeof(dst);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        if (::sendmsg(fd_, &msg, 0) < 0) throw std::system_error(errno, std::generic_category(), "netlink sendmsg");

        uint8_t buf[4096];
        ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n < 0) throw std::system_error(errno, std::generic_category(), "netlink recv");
        auto* resp = reinterpret_cast<nlmsghdr*>(buf);
        if (resp->nlmsg_type == NLMSG_ERROR) {
            auto* err_msg = reinterpret_cast<nlmsgerr*>(NLMSG_DATA(resp));
            if (err_msg->error != 0) throw std::system_error(-err_msg->error, std::generic_category(), "netlink reply");
        }
    }

private:
    int fd_{-1};
    uint32_t seq_{0};
};

struct NetlinkMsgBuilder {
    uint8_t buf[4096]{};
    nlmsghdr* nlh{reinterpret_cast<nlmsghdr*>(buf)};

    NetlinkMsgBuilder(uint16_t type, uint16_t flags, size_t payload_size) {
        nlh->nlmsg_type = type;
        nlh->nlmsg_flags = flags;
        nlh->nlmsg_len = static_cast<uint32_t>(NLMSG_LENGTH(payload_size));
    }

    template <typename T>
    T* payload() {
        return reinterpret_cast<T*>(NLMSG_DATA(nlh));
    }

    void add_attr(uint16_t type, const void* data, size_t len) {
        size_t aligned = NLMSG_ALIGN(nlh->nlmsg_len);
        size_t rta_len = RTA_LENGTH(len);
        if (aligned + rta_len > sizeof(buf)) throw std::runtime_error("Netlink message buffer overflow");
        auto* rta = reinterpret_cast<rtattr*>(buf + aligned);
        rta->rta_type = type;
        rta->rta_len = static_cast<uint16_t>(rta_len);
        if (len > 0 && data != nullptr) std::memcpy(RTA_DATA(rta), data, len);
        nlh->nlmsg_len = static_cast<uint32_t>(aligned + RTA_ALIGN(rta_len));
    }

    void add_str(uint16_t type, const std::string& s) { add_attr(type, s.c_str(), s.size() + 1); }
    void add_u32(uint16_t type, uint32_t v) { add_attr(type, &v, sizeof(v)); }

    size_t begin_nested(uint16_t type) {
        size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
        add_attr(type, nullptr, 0);
        return off;
    }

    void end_nested(size_t off) {
        auto* rta = reinterpret_cast<rtattr*>(buf + off);
        rta->rta_len = static_cast<uint16_t>(nlh->nlmsg_len - off);
    }
};

uint32_t parse_ipv4_be(const std::string& ip) {
    struct in_addr addr{};
    if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        throw std::invalid_argument("Invalid IPv4 address: '" + ip + "'");
    }
    return addr.s_addr;
}

bool netlink_create_bridge(const std::string& bridge_name, const std::string& bridge_cidr) {
    try {
        auto slash = bridge_cidr.find('/');
        std::string ip = (slash == std::string::npos) ? bridge_cidr : bridge_cidr.substr(0, slash);
        uint8_t prefix = (slash == std::string::npos) ? 24 : static_cast<uint8_t>(std::stoi(bridge_cidr.substr(slash + 1)));

        NetlinkSocket nl;
        {
            NetlinkMsgBuilder req(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sizeof(ifinfomsg));
            req.payload<ifinfomsg>()->ifi_family = AF_UNSPEC;
            req.add_str(IFLA_IFNAME, bridge_name);
            size_t li = req.begin_nested(IFLA_LINKINFO);
            req.add_str(IFLA_INFO_KIND, "bridge");
            req.end_nested(li);
            nl.send_and_ack(req.nlh);
        }

        unsigned int idx = ::if_nametoindex(bridge_name.c_str());
        if (idx == 0) return false;

        {
            uint32_t ip_be = parse_ipv4_be(ip);
            NetlinkMsgBuilder req(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, sizeof(ifaddrmsg));
            auto* ifa = req.payload<ifaddrmsg>();
            ifa->ifa_family = AF_INET;
            ifa->ifa_prefixlen = prefix;
            ifa->ifa_index = idx;
            req.add_attr(IFA_LOCAL, &ip_be, sizeof(ip_be));
            req.add_attr(IFA_ADDRESS, &ip_be, sizeof(ip_be));
            nl.send_and_ack(req.nlh);
        }

        {
            NetlinkMsgBuilder req(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof(ifinfomsg));
            auto* ifi = req.payload<ifinfomsg>();
            ifi->ifi_family = AF_UNSPEC;
            ifi->ifi_index = static_cast<int>(idx);
            ifi->ifi_flags = IFF_UP;
            ifi->ifi_change = IFF_UP;
            nl.send_and_ack(req.nlh);
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool netlink_setup_host_veth(const ContainerNetwork& plan, int pid) {
    try {
        unsigned int br_idx = ::if_nametoindex(plan.bridge_name.c_str());
        if (br_idx == 0) return false;

        NetlinkSocket nl;
        {
            NetlinkMsgBuilder req(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sizeof(ifinfomsg));
            req.payload<ifinfomsg>()->ifi_family = AF_UNSPEC;
            req.add_str(IFLA_IFNAME, plan.host_veth);
            size_t li = req.begin_nested(IFLA_LINKINFO);
            req.add_str(IFLA_INFO_KIND, "veth");
            size_t ld = req.begin_nested(IFLA_INFO_DATA);
            size_t peer = req.begin_nested(VETH_INFO_PEER);
            size_t aligned = NLMSG_ALIGN(req.nlh->nlmsg_len);
            if (aligned + sizeof(ifinfomsg) > sizeof(req.buf)) return false;
            std::memset(req.buf + aligned, 0, sizeof(ifinfomsg));
            req.nlh->nlmsg_len = static_cast<uint32_t>(aligned + sizeof(ifinfomsg));
            req.add_str(IFLA_IFNAME, plan.peer_veth);
            req.end_nested(peer);
            req.end_nested(ld);
            req.end_nested(li);
            nl.send_and_ack(req.nlh);
        }

        unsigned int host_idx = ::if_nametoindex(plan.host_veth.c_str());
        unsigned int peer_idx = ::if_nametoindex(plan.peer_veth.c_str());
        if (host_idx == 0 || peer_idx == 0) return false;

        {
            NetlinkMsgBuilder req(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof(ifinfomsg));
            auto* ifi = req.payload<ifinfomsg>();
            ifi->ifi_family = AF_UNSPEC;
            ifi->ifi_index = static_cast<int>(host_idx);
            ifi->ifi_flags = IFF_UP;
            ifi->ifi_change = IFF_UP;
            req.add_u32(IFLA_MASTER, br_idx);
            nl.send_and_ack(req.nlh);
        }

        {
            NetlinkMsgBuilder req(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof(ifinfomsg));
            auto* ifi = req.payload<ifinfomsg>();
            ifi->ifi_family = AF_UNSPEC;
            ifi->ifi_index = static_cast<int>(peer_idx);
            req.add_u32(IFLA_NET_NS_PID, static_cast<uint32_t>(pid));
            nl.send_and_ack(req.nlh);
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool netlink_delete_link(const std::string& ifname) {
    unsigned int idx = ::if_nametoindex(ifname.c_str());
    if (idx == 0) return true;
    try {
        NetlinkSocket nl;
        NetlinkMsgBuilder req(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof(ifinfomsg));
        req.payload<ifinfomsg>()->ifi_family = AF_UNSPEC;
        req.payload<ifinfomsg>()->ifi_index = static_cast<int>(idx);
        nl.send_and_ack(req.nlh);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string subnet_to_prefix3(const std::string& cidr_or_gw) {
    std::string ip = cidr_or_gw;
    if (auto sl = ip.find('/'); sl != std::string::npos) ip = ip.substr(0, sl);
    auto d1 = ip.find('.');
    auto d2 = (d1 == std::string::npos) ? std::string::npos : ip.find('.', d1 + 1);
    auto d3 = (d2 == std::string::npos) ? std::string::npos : ip.find('.', d2 + 1);
    if (d3 == std::string::npos) return "10.0.0";
    return ip.substr(0, d3);
}

std::string to_lower_ascii(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

PortMapping parse_port_mapping(const std::string& spec) {
    std::string addr_part = spec;
    std::string proto = "tcp";
    auto slash = spec.rfind('/');
    if (slash != std::string::npos) {
        proto = to_lower_ascii(spec.substr(slash + 1));
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
    if (!pm.host_ip.empty()) out += pm.host_ip + ":";
    out += std::to_string(pm.host_port) + "->" + std::to_string(pm.container_port) + "/" + pm.protocol;
    return out;
}

int run_host_cmd(const std::vector<std::string>& args, bool quiet) {
    if (args.empty()) return -1;
    pid_t pid = ::fork();
    if (pid < 0) return -1;
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
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

bool setup_host_network(
    const std::string& bridge_name,
    const std::string& bridge_cidr,
    const std::string& subnet_cidr,
    bool enable_nat,
    bool isolate_containers) {
    std::string sysfs_bridge = "/sys/class/net/" + bridge_name;
    std::string marker_path = "/run/pieces/.net_ready_" + bridge_name + "_" +
                              (enable_nat ? "1" : "0") + "_" + (isolate_containers ? "1" : "0");
    if (::access(sysfs_bridge.c_str(), F_OK) == 0 && ::access(marker_path.c_str(), F_OK) == 0) {
        return true;
    }

    if (::access(sysfs_bridge.c_str(), F_OK) != 0) {
        std::cout << "HOST: Creating bridge '" << bridge_name << "' (" << bridge_cidr << ").\n";
        if (!netlink_create_bridge(bridge_name, bridge_cidr)) {
            if (!command_exists("ip")) {
                std::cerr << "NETWORK: Warning: failed to create bridge '" << bridge_name << "'.\n";
                return false;
            }
            std::string batch = "link add name " + bridge_name + " type bridge\n"
                                "addr add " + bridge_cidr + " dev " + bridge_name + "\n"
                                "link set " + bridge_name + " up\n";
            if (run_host_cmd_with_stdin({"ip", "-batch", "-"}, batch, false) != 0) {
                std::cerr << "NETWORK: Warning: failed to create bridge '" << bridge_name << "'.\n";
                return false;
            }
        }
    } else if (command_exists("ip")) {
        run_host_cmd({"ip", "link", "set", bridge_name, "up"}, true);
    }

    if (enable_nat) {
        write_proc_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
        std::string localnet_path = "/proc/sys/net/ipv4/conf/" + bridge_name + "/route_localnet";
        write_proc_sysctl(localnet_path.c_str(), "1");
        ensure_nat_masquerade(bridge_name, subnet_cidr);
    }
    if (isolate_containers) {
        ensure_bridge_isolation(bridge_name);
    }

    std::error_code ec;
    fs::create_directories("/run/pieces", ec);
    std::ofstream marker(marker_path);
    return true;
}

NetworkConfig create_network(
    const std::string& name,
    const std::string& subnet_cidr,
    bool isolate,
    const std::string& networks_dir) {
    std::string safe = validate_name(name, "network");
    if (safe == "bridge" || safe == "none" || safe == "host") {
        throw std::invalid_argument("Cannot create reserved network name '" + safe + "'");
    }
    fs::create_directories(networks_dir);
    fs::path cfg_path = fs::path(networks_dir) / (safe + ".json");
    if (fs::exists(cfg_path)) {
        throw std::runtime_error("Network '" + safe + "' already exists");
    }

    std::set<std::string> used_subnets = {DEFAULT_SUBNET_CIDR};
    for (const auto& existing : list_networks(networks_dir)) {
        if (auto it = existing.find("subnet"); it != existing.end() && it->second.is_string()) {
            used_subnets.insert(it->second.as_string());
        }
    }

    std::string chosen_subnet = subnet_cidr;
    if (chosen_subnet.empty()) {
        for (int octet = 1; octet <= 254; ++octet) {
            std::string cand = "10." + std::to_string(octet) + ".0.0/24";
            if (!used_subnets.contains(cand)) {
                chosen_subnet = cand;
                break;
            }
        }
        if (chosen_subnet.empty()) throw std::runtime_error("No available /24 subnets");
    }

    std::string pfx3 = subnet_to_prefix3(chosen_subnet);
    NetworkConfig cfg;
    cfg.name = safe;
    cfg.bridge_name = "pb-" + sha256_string(safe).substr(0, 8);
    cfg.subnet_cidr = pfx3 + ".0/24";
    cfg.gateway_ip = pfx3 + ".1";
    cfg.isolate = isolate;

    JsonObject obj;
    obj["name"] = cfg.name;
    obj["bridge"] = cfg.bridge_name;
    obj["subnet"] = cfg.subnet_cidr;
    obj["gateway"] = cfg.gateway_ip;
    obj["isolate"] = cfg.isolate;
    std::ofstream out(cfg_path);
    if (!out) throw std::runtime_error("Failed to write network config: " + cfg_path.string());
    out << JsonValue(obj).dump(2) << "\n";
    return cfg;
}

NetworkConfig load_network_config(const std::string& name, const std::string& networks_dir) {
    if (name.empty() || name == "bridge") {
        return {"bridge", DEFAULT_BRIDGE, DEFAULT_SUBNET_CIDR, DEFAULT_GATEWAY_IP, true};
    }
    std::string safe = validate_name(name, "network");
    fs::path cfg_path = fs::path(networks_dir) / (safe + ".json");
    if (!fs::is_regular_file(cfg_path)) {
        throw std::runtime_error("Network '" + name + "' not found (create with `pieces network create " + name + "`)");
    }
    std::ifstream in(cfg_path);
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    JsonValue v = JsonValue::parse(s);
    NetworkConfig cfg;
    cfg.name = safe;
    cfg.bridge_name = v.find("bridge")->as_string();
    cfg.subnet_cidr = v.find("subnet")->as_string();
    cfg.gateway_ip = v.find("gateway")->as_string();
    if (const auto* iso = v.find("isolate"); iso && iso->is_bool()) cfg.isolate = std::get<bool>(iso->data);
    return cfg;
}

std::vector<JsonObject> list_networks(const std::string& networks_dir) {
    std::vector<JsonObject> out;
    out.push_back({
        {"name", "bridge"},
        {"bridge", DEFAULT_BRIDGE},
        {"subnet", DEFAULT_SUBNET_CIDR},
        {"gateway", DEFAULT_GATEWAY_IP},
        {"isolate", true},
    });
    std::error_code ec;
    if (fs::is_directory(networks_dir, ec)) {
        for (const auto& e : fs::directory_iterator(networks_dir, ec)) {
            if (!e.is_regular_file(ec) || e.path().extension() != ".json") continue;
            std::ifstream in(e.path());
            std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            try {
                JsonValue v = JsonValue::parse(s);
                if (v.is_object()) out.push_back(v.as_object());
            } catch (const std::exception&) {
            }
        }
    }
    return out;
}

JsonObject inspect_network_json(const std::string& name, const std::string& networks_dir) {
    auto cfg = load_network_config(name, networks_dir);
    return {
        {"name", cfg.name},
        {"bridge", cfg.bridge_name},
        {"subnet", cfg.subnet_cidr},
        {"gateway", cfg.gateway_ip},
        {"isolate", cfg.isolate},
    };
}

void remove_network(const std::string& name, const std::string& networks_dir) {
    std::string safe = validate_name(name, "network");
    if (safe == "bridge" || safe == "none" || safe == "host") {
        throw std::invalid_argument("Cannot remove built-in network '" + safe + "'");
    }
    fs::path cfg_path = fs::path(networks_dir) / (safe + ".json");
    if (!fs::is_regular_file(cfg_path)) throw std::runtime_error("Network '" + name + "' not found");
    auto cfg = load_network_config(safe, networks_dir);
    cleanup_container_network(cfg.bridge_name);
    fs::remove(cfg_path);
}

std::string allocate_container_ip(
    const std::string& containers_dir,
    const std::string& owner_id,
    const std::string& network_name,
    const std::string& subnet_prefix) {
    fs::path cdir(containers_dir);
    FileLockGuard lock(cdir / ".ipam.lock");

    std::set<std::string> used_ips;
    fs::path leases_path = ipam_leases_path_for(cdir, network_name);
    std::error_code ec;
    bool had_leases_file = fs::is_regular_file(leases_path, ec);
    JsonObject leases = read_ipam_leases(leases_path);

    JsonObject clean_leases;
    for (const auto& [cid, ip_val] : leases) {
        if (!ip_val.is_string()) continue;
        fs::path meta_path = cdir / cid / "meta.json";
        if (!fs::is_regular_file(meta_path, ec)) continue;
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

    if (!had_leases_file && fs::is_directory(cdir, ec)) {
        for (const auto& entry : fs::directory_iterator(cdir, ec)) {
            if (!entry.is_directory(ec)) continue;
            fs::path meta_path = entry.path() / "meta.json";
            if (!fs::is_regular_file(meta_path, ec)) continue;
            std::ifstream in(meta_path);
            if (!in) continue;
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            try {
                JsonValue parsed = JsonValue::parse(content);
                const JsonValue* status = parsed.find("status");
                const JsonValue* ip = parsed.find("ip");
                if (status && status->is_string() && status->as_string() == "running" &&
                    ip && ip->is_string() && !ip->as_string().empty()) {
                    used_ips.insert(ip->as_string());
                    clean_leases[entry.path().filename().string()] = ip->as_string();
                }
            } catch (const std::exception&) {
            }
        }
    }

    for (int host = 2; host <= 254; ++host) {
        std::string candidate = subnet_prefix + "." + std::to_string(host);
        if (!used_ips.contains(candidate)) {
            if (!owner_id.empty()) clean_leases[owner_id] = candidate;
            write_ipam_leases(leases_path, clean_leases);
            return candidate;
        }
    }
    throw std::runtime_error("No available IP addresses left in " + subnet_prefix + ".0/24");
}

void release_container_ip(
    const std::string& containers_dir,
    const std::string& owner_id,
    const std::string& network_name) {
    if (owner_id.empty()) return;
    std::error_code ec;
    fs::path cdir(containers_dir);
    fs::path lock_path = cdir / ".ipam.lock";
    if (!fs::exists(lock_path, ec)) return;
    FileLockGuard lock(lock_path);
    fs::path leases_path = ipam_leases_path_for(cdir, network_name);
    JsonObject leases = read_ipam_leases(leases_path);
    if (leases.erase(owner_id) > 0) write_ipam_leases(leases_path, leases);
}

std::map<std::string, std::string> collect_network_peers(
    const std::string& containers_dir,
    const std::string& network_name) {
    std::map<std::string, std::string> peers;
    std::error_code ec;
    if (!fs::is_directory(containers_dir, ec)) return peers;
    for (const auto& e : fs::directory_iterator(containers_dir, ec)) {
        if (!e.is_directory(ec)) continue;
        fs::path meta_path = e.path() / "meta.json";
        if (!fs::is_regular_file(meta_path, ec)) continue;
        std::ifstream in(meta_path);
        if (!in) continue;
        std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        try {
            JsonValue v = JsonValue::parse(s);
            const auto* st = v.find("status");
            const auto* ip = v.find("ip");
            const auto* name = v.find("name");
            const auto* net = v.find("network");
            std::string rec_net = (net && net->is_string() && !net->as_string().empty()) ? net->as_string() : "bridge";
            if (st && st->is_string() && st->as_string() == "running" &&
                ip && ip->is_string() && !ip->as_string().empty() &&
                name && name->is_string() && !name->as_string().empty() &&
                rec_net == network_name) {
                peers[to_lower_ascii(name->as_string())] = ip->as_string();
            }
        } catch (const std::exception&) {
        }
    }
    return peers;
}

ContainerNetwork build_network_plan(
    const std::string& container_id,
    const std::string& containers_dir,
    const std::vector<PortMapping>& ports,
    const std::string& network_name,
    const std::string& networks_dir) {
    NetworkConfig ncfg = load_network_config(network_name, networks_dir);
    std::string pfx3 = subnet_to_prefix3(ncfg.subnet_cidr);
    std::string short_id = container_id.substr(0, std::min<size_t>(container_id.size(), 8));

    ContainerNetwork plan;
    plan.network_name = ncfg.name;
    plan.bridge_name = ncfg.bridge_name;
    plan.gateway_ip = ncfg.gateway_ip;
    plan.subnet_cidr = ncfg.subnet_cidr;
    plan.container_ip = allocate_container_ip(containers_dir, container_id, ncfg.name, pfx3);
    plan.prefix_len = 24;
    plan.host_veth = "vp-" + short_id;
    plan.peer_veth = "vc-" + short_id;
    plan.ports = ports;
    return plan;
}

bool configure_container_netns_netlink(const ContainerNetwork& plan) {
    try {
        NetlinkSocket nl;

        unsigned int lo_idx = ::if_nametoindex("lo");
        if (lo_idx == 0) return false;
        {
            NetlinkMsgBuilder req(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof(ifinfomsg));
            auto* ifi = req.payload<ifinfomsg>();
            ifi->ifi_family = AF_UNSPEC;
            ifi->ifi_index = static_cast<int>(lo_idx);
            ifi->ifi_flags = IFF_UP;
            ifi->ifi_change = IFF_UP;
            nl.send_and_ack(req.nlh);
        }

        unsigned int eth_idx = ::if_nametoindex(plan.peer_veth.c_str());
        if (eth_idx == 0) eth_idx = ::if_nametoindex("eth0");
        if (eth_idx == 0) return false;

        {
            NetlinkMsgBuilder req(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof(ifinfomsg));
            auto* ifi = req.payload<ifinfomsg>();
            ifi->ifi_family = AF_UNSPEC;
            ifi->ifi_index = static_cast<int>(eth_idx);
            req.add_str(IFLA_IFNAME, "eth0");
            nl.send_and_ack(req.nlh);
        }

        {
            NetlinkMsgBuilder req(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof(ifinfomsg));
            auto* ifi = req.payload<ifinfomsg>();
            ifi->ifi_family = AF_UNSPEC;
            ifi->ifi_index = static_cast<int>(eth_idx);
            ifi->ifi_flags = IFF_UP;
            ifi->ifi_change = IFF_UP;
            nl.send_and_ack(req.nlh);
        }

        {
            uint32_t ip_be = parse_ipv4_be(plan.container_ip);
            NetlinkMsgBuilder req(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, sizeof(ifaddrmsg));
            auto* ifa = req.payload<ifaddrmsg>();
            ifa->ifa_family = AF_INET;
            ifa->ifa_prefixlen = static_cast<uint8_t>(plan.prefix_len);
            ifa->ifa_index = eth_idx;
            req.add_attr(IFA_LOCAL, &ip_be, sizeof(ip_be));
            req.add_attr(IFA_ADDRESS, &ip_be, sizeof(ip_be));
            nl.send_and_ack(req.nlh);
        }

        {
            uint32_t gw_be = parse_ipv4_be(plan.gateway_ip);
            NetlinkMsgBuilder req(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, sizeof(rtmsg));
            auto* rtm = req.payload<rtmsg>();
            rtm->rtm_family = AF_INET;
            rtm->rtm_table = RT_TABLE_MAIN;
            rtm->rtm_protocol = RTPROT_BOOT;
            rtm->rtm_scope = RT_SCOPE_UNIVERSE;
            rtm->rtm_type = RTN_UNICAST;
            req.add_attr(RTA_GATEWAY, &gw_be, sizeof(gw_be));
            req.add_u32(RTA_OIF, eth_idx);
            nl.send_and_ack(req.nlh);
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool setup_port_forwarding(const ContainerNetwork& plan) {
    if (plan.ports.empty() || plan.container_ip.empty()) return true;
    if (!command_exists("iptables")) return false;
    for (const auto& pm : plan.ports) {
        for (const auto& cmd : build_port_iptables_rules(plan, pm, "-A")) {
            if (run_host_cmd(cmd, true) != 0) return false;
        }
    }
    return true;
}

void cleanup_port_forwarding(const ContainerNetwork& plan) {
    if (plan.ports.empty() || plan.container_ip.empty() || !command_exists("iptables")) return;
    for (const auto& pm : plan.ports) {
        for (const auto& cmd : build_port_iptables_rules(plan, pm, "-D")) {
            run_host_cmd(cmd, true);
        }
    }
}

bool setup_container_network(int pid, const ContainerNetwork& plan) {
    if (netlink_setup_host_veth(plan, pid)) {
        setup_port_forwarding(plan);
        return true;
    }

    if (!command_exists("ip")) return false;
    std::string pid_str = std::to_string(pid);

    std::string host_batch =
        "link add " + plan.host_veth + " type veth peer name " + plan.peer_veth + "\n"
        "link set " + plan.host_veth + " master " + plan.bridge_name + "\n"
        "link set " + plan.host_veth + " up\n"
        "link set " + plan.peer_veth + " netns " + pid_str + "\n";
    if (run_host_cmd_with_stdin({"ip", "-batch", "-"}, host_batch, false) != 0) {
        cleanup_container_network(plan.host_veth);
        return false;
    }

    std::vector<std::string> netns_batch_cmd = command_exists("nsenter")
        ? std::vector<std::string>{"nsenter", "--net=/proc/" + pid_str + "/ns/net", "ip", "-batch", "-"}
        : std::vector<std::string>{"ip", "netns", "exec", pid_str, "ip", "-batch", "-"};

    std::string cidr = plan.container_ip + "/" + std::to_string(plan.prefix_len);
    std::string netns_batch =
        "link set lo up\n"
        "link set " + plan.peer_veth + " name eth0\n"
        "addr add " + cidr + " dev eth0\n"
        "link set eth0 up\n"
        "route add default via " + plan.gateway_ip + "\n";

    if (run_host_cmd_with_stdin(netns_batch_cmd, netns_batch, false) != 0) {
        cleanup_container_network(plan.host_veth);
        return false;
    }

    setup_port_forwarding(plan);
    return true;
}

void cleanup_container_network(const std::string& host_veth) {
    if (host_veth.empty()) return;
    if (netlink_delete_link(host_veth)) return;
    if (command_exists("ip")) run_host_cmd({"ip", "link", "del", host_veth}, true);
}

int setup_rootless_userspace_network(int target_pid, const std::vector<PortMapping>& ports) {
    if (target_pid <= 0) return -1;
    std::string pid_s = std::to_string(target_pid);

    std::vector<std::string> cmd;
    if (command_exists("pasta")) {
        cmd = {"pasta", "--config-net", "--foreground"};
        for (const auto& pm : ports) {
            cmd.push_back(pm.protocol == "udp" ? "-u" : "-t");
            cmd.push_back(std::to_string(pm.host_port) + ":" + std::to_string(pm.container_port));
        }
        cmd.push_back(pid_s);
    } else if (command_exists("slirp4netns")) {
        cmd = {"slirp4netns", "--configure", "--mtu=65520", pid_s, "tap0"};
    } else {
        return -1;
    }

    pid_t helper = ::fork();
    if (helper < 0) return -1;
    if (helper == 0) {
        int dn = ::open("/dev/null", O_RDWR);
        if (dn >= 0) {
            ::dup2(dn, STDIN_FILENO);
            ::dup2(dn, STDOUT_FILENO);
            ::dup2(dn, STDERR_FILENO);
            ::close(dn);
        }
        std::vector<char*> argv;
        for (auto& s : cmd) argv.push_back(s.data());
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }
    return helper;
}

void cleanup_rootless_userspace_network(int helper_pid) {
    if (helper_pid <= 0) return;
    ::kill(helper_pid, SIGTERM);
    int st = 0;
    ::waitpid(helper_pid, &st, 0);
}

std::vector<uint8_t> build_dns_response(
    const std::vector<uint8_t>& query_packet,
    const std::map<std::string, std::string>& hostname_to_ip) {
    if (query_packet.size() < 12) return {};

    // Parse QNAME cleanly starting at offset 12
    size_t pos = 12;
    std::string qname;
    while (pos < query_packet.size()) {
        uint8_t len = query_packet[pos++];
        if (len == 0) break;
        if (pos + len > query_packet.size()) return {};
        if (!qname.empty()) qname.push_back('.');
        qname.append(reinterpret_cast<const char*>(&query_packet[pos]), len);
        pos += len;
    }
    if (pos + 4 > query_packet.size()) return {};
    uint16_t qtype = static_cast<uint16_t>((query_packet[pos] << 8) | query_packet[pos + 1]);
    uint16_t qclass = static_cast<uint16_t>((query_packet[pos + 2] << 8) | query_packet[pos + 3]);
    size_t q_end = pos + 4;

    std::string lookup = to_lower_ascii(qname);
    if (lookup.size() > 7 && lookup.compare(lookup.size() - 7, 7, ".pieces") == 0) {
        lookup = lookup.substr(0, lookup.size() - 7);
    }

    struct in_addr ip_addr{};
    bool found = (qtype == 1 && qclass == 1);
    if (found) {
        auto it = hostname_to_ip.find(lookup);
        found = (it != hostname_to_ip.end() && ::inet_pton(AF_INET, it->second.c_str(), &ip_addr) == 1);
    }

    std::vector<uint8_t> resp(query_packet.begin(), query_packet.begin() + static_cast<std::ptrdiff_t>(q_end));
    resp[2] = 0x81;  // QR=1, AA/RD
    resp[3] = found ? 0x80 : 0x83;  // NOERROR (0) or NXDOMAIN (3)
    resp[4] = 0x00; resp[5] = 0x01;  // QDCOUNT = 1
    resp[6] = 0x00; resp[7] = found ? 0x01 : 0x00;  // ANCOUNT
    resp[8] = 0x00; resp[9] = 0x00;
    resp[10] = 0x00; resp[11] = 0x00;

    if (found) {
        resp.push_back(0xC0); resp.push_back(0x0C);  // Name pointer to offset 12
        resp.push_back(0x00); resp.push_back(0x01);  // TYPE A
        resp.push_back(0x00); resp.push_back(0x01);  // CLASS IN
        resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x00); resp.push_back(0x05);  // TTL=5s
        resp.push_back(0x00); resp.push_back(0x04);  // RDLENGTH=4
        const auto* bytes = reinterpret_cast<const uint8_t*>(&ip_addr.s_addr);
        resp.insert(resp.end(), bytes, bytes + 4);
    }
    return resp;
}

EmbeddedDnsServer::EmbeddedDnsServer(
    std::string listen_ip,
    uint16_t port,
    std::string containers_dir,
    std::string network_name)
    : listen_ip_(std::move(listen_ip)),
      requested_port_(port),
      containers_dir_(std::move(containers_dir)),
      network_name_(std::move(network_name)) {}

EmbeddedDnsServer::~EmbeddedDnsServer() {
    stop();
}

bool EmbeddedDnsServer::start() {
    if (running_.load()) return true;
    sock_fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock_fd_ < 0) return false;

    int reuse = 1;
    ::setsockopt(sock_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(requested_port_);
    if (::inet_pton(AF_INET, listen_ip_.c_str(), &addr.sin_addr) != 1) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    if (::bind(sock_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    socklen_t len = sizeof(addr);
    if (::getsockname(sock_fd_, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
        bound_port_ = ntohs(addr.sin_port);
    }

    running_.store(true);
    worker_ = std::thread([this]() {
        uint8_t buf[512];
        while (running_.load()) {
            pollfd pfd{sock_fd_, POLLIN, 0};
            if (::poll(&pfd, 1, 100) <= 0) continue;
            if (!(pfd.revents & POLLIN)) continue;
            sockaddr_in cli{};
            socklen_t clen = sizeof(cli);
            ssize_t n = ::recvfrom(sock_fd_, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&cli), &clen);
            if (n <= 0) continue;
            std::vector<uint8_t> q(buf, buf + n);
            auto peers = collect_network_peers(containers_dir_, network_name_);
            auto resp = build_dns_response(q, peers);
            if (!resp.empty()) {
                (void)::sendto(sock_fd_, resp.data(), resp.size(), 0, reinterpret_cast<sockaddr*>(&cli), clen);
            }
        }
    });
    return true;
}

void EmbeddedDnsServer::stop() {
    running_.store(false);
    if (worker_.joinable()) worker_.join();
    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }
}

}  // namespace pieces

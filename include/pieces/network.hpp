#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "pieces/json.hpp"

namespace pieces {

inline constexpr const char* DEFAULT_BRIDGE = "pieces-br0";
inline constexpr const char* DEFAULT_BRIDGE_CIDR = "10.0.0.1/24";
inline constexpr const char* DEFAULT_SUBNET_CIDR = "10.0.0.0/24";
inline constexpr const char* DEFAULT_GATEWAY_IP = "10.0.0.1";

struct PortMapping {
    std::string host_ip;
    int host_port{0};
    int container_port{0};
    std::string protocol{"tcp"};
};

struct NetworkConfig {
    std::string name;
    std::string bridge_name;
    std::string subnet_cidr;
    std::string gateway_ip;
    bool isolate{false};
};

struct ContainerNetwork {
    std::string network_name{"bridge"};
    std::string bridge_name;
    std::string gateway_ip;
    std::string subnet_cidr;
    std::string container_ip;
    int prefix_len{24};
    std::string host_veth;
    std::string peer_veth;
    std::vector<PortMapping> ports;
};

[[nodiscard]] PortMapping parse_port_mapping(const std::string& spec);
[[nodiscard]] std::string format_port_mapping(const PortMapping& pm);

int run_host_cmd(const std::vector<std::string>& args, bool quiet = true);
bool setup_host_network(
    const std::string& bridge_name = DEFAULT_BRIDGE,
    const std::string& bridge_cidr = DEFAULT_BRIDGE_CIDR,
    const std::string& subnet_cidr = DEFAULT_SUBNET_CIDR,
    bool enable_nat = true,
    bool isolate_containers = true);

// Custom user-defined networks
NetworkConfig create_network(
    const std::string& name,
    const std::string& subnet_cidr = "",
    bool isolate = false,
    const std::string& networks_dir = ".pieces/networks");
[[nodiscard]] NetworkConfig load_network_config(
    const std::string& name,
    const std::string& networks_dir = ".pieces/networks");
[[nodiscard]] std::vector<JsonObject> list_networks(const std::string& networks_dir = ".pieces/networks");
[[nodiscard]] JsonObject inspect_network_json(
    const std::string& name,
    const std::string& networks_dir = ".pieces/networks");
void remove_network(const std::string& name, const std::string& networks_dir = ".pieces/networks");

// Per-network flock IPAM & peer discovery
[[nodiscard]] std::string allocate_container_ip(
    const std::string& containers_dir,
    const std::string& owner_id = "",
    const std::string& network_name = "bridge",
    const std::string& subnet_prefix = "10.0.0");
void release_container_ip(
    const std::string& containers_dir,
    const std::string& owner_id,
    const std::string& network_name = "bridge");
[[nodiscard]] std::map<std::string, std::string> collect_network_peers(
    const std::string& containers_dir,
    const std::string& network_name);

[[nodiscard]] ContainerNetwork build_network_plan(
    const std::string& container_id,
    const std::string& containers_dir,
    const std::vector<PortMapping>& ports = {},
    const std::string& network_name = "bridge",
    const std::string& networks_dir = ".pieces/networks");
bool setup_container_network(int pid, const ContainerNetwork& plan);
bool configure_container_netns_netlink(const ContainerNetwork& plan);
bool setup_port_forwarding(const ContainerNetwork& plan);
void cleanup_port_forwarding(const ContainerNetwork& plan);
void cleanup_container_network(const std::string& host_veth);

// Rootless userspace networking (pasta / slirp4netns)
int setup_rootless_userspace_network(int target_pid, const std::vector<PortMapping>& ports);
void cleanup_rootless_userspace_network(int helper_pid);

// Lightweight embedded UDP DNS responder for container service discovery
[[nodiscard]] std::vector<uint8_t> build_dns_response(
    const std::vector<uint8_t>& query_packet,
    const std::map<std::string, std::string>& hostname_to_ip);

class EmbeddedDnsServer {
public:
    EmbeddedDnsServer(
        std::string listen_ip,
        uint16_t port,
        std::string containers_dir,
        std::string network_name);
    ~EmbeddedDnsServer();

    bool start();
    void stop();
    [[nodiscard]] uint16_t bound_port() const { return bound_port_; }

private:
    std::string listen_ip_;
    uint16_t requested_port_;
    uint16_t bound_port_{0};
    std::string containers_dir_;
    std::string network_name_;
    int sock_fd_{-1};
    std::atomic<bool> running_{false};
    std::thread worker_;
};

}  // namespace pieces

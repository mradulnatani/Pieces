#pragma once

#include <string>
#include <vector>

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

struct ContainerNetwork {
    std::string bridge_name;
    std::string gateway_ip;
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
    bool enable_nat = true);

[[nodiscard]] std::string allocate_container_ip(
    const std::string& containers_dir,
    const std::string& owner_id = "");
void release_container_ip(const std::string& containers_dir, const std::string& owner_id);

[[nodiscard]] ContainerNetwork build_network_plan(
    const std::string& container_id,
    const std::string& containers_dir,
    const std::vector<PortMapping>& ports = {});
bool setup_container_network(int pid, const ContainerNetwork& plan);
bool setup_port_forwarding(const ContainerNetwork& plan);
void cleanup_port_forwarding(const ContainerNetwork& plan);
void cleanup_container_network(const std::string& host_veth);

}  // namespace pieces

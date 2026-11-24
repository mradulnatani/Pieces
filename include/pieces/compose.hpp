#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "pieces/filesystem.hpp"

namespace pieces {

struct ComposeService {
    std::string name;
    std::string image;
    std::string build_context;
    std::string build_file;
    std::string container_name;
    std::vector<std::string> ports;
    std::vector<std::string> volumes;
    std::vector<std::string> environment;
    std::vector<std::string> env_files;
    std::vector<std::string> depends_on;
    std::vector<std::string> cap_add;
    std::vector<std::string> cap_drop;
    std::vector<std::string> security_opts;
    std::vector<std::string> tmpfs;
    std::vector<std::string> dns;
    std::vector<std::string> networks;
    std::vector<std::string> command;
    std::optional<std::string> working_dir;
    std::optional<std::string> user;
    std::optional<std::string> mem_limit;
    std::optional<double> cpus;
    std::optional<int> pids_limit;
    std::string restart{"no"};
    bool read_only{false};
    bool privileged{false};
};

struct ComposeProject {
    std::string project_name;
    std::vector<ComposeService> services;
    std::vector<std::string> networks;
    std::vector<std::string> volumes;
};

[[nodiscard]] std::string resolve_compose_file(
    const std::string& explicit_path = "",
    const std::string& dir = ".");
[[nodiscard]] ComposeProject parse_compose_yaml(
    const std::string& content,
    const std::string& project_name = "pieces");
[[nodiscard]] ComposeProject parse_compose_file(const std::string& path);
[[nodiscard]] std::vector<std::string> topo_sort_services(const std::vector<ComposeService>& services);

int compose_up(
    const std::string& compose_path,
    bool detach,
    bool force_build,
    const std::string& image_dir = IMAGE_DIR,
    const std::string& containers_dir = CONTAINERS_DIR,
    const std::string& volumes_dir = VOLUMES_DIR,
    const std::string& networks_dir = NETWORKS_DIR);
int compose_down(
    const std::string& compose_path,
    const std::string& containers_dir = CONTAINERS_DIR,
    const std::string& networks_dir = NETWORKS_DIR);
int compose_ps(
    const std::string& compose_path,
    const std::string& containers_dir = CONTAINERS_DIR);
int compose_logs(
    const std::string& compose_path,
    bool follow = false,
    int tail_lines = -1,
    const std::string& containers_dir = CONTAINERS_DIR);

}  // namespace pieces

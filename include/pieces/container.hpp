#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "pieces/filesystem.hpp"
#include "pieces/json.hpp"

namespace pieces {

struct ContainerRunConfig {
    std::string image;
    std::vector<std::string> cmd_args;
    std::optional<std::string> name;
    bool auto_remove{false};
    bool detach{false};
    bool rootless{false};
    std::string network_mode{"bridge"};
    std::vector<std::string> env_specs;
    std::vector<std::string> volume_specs;
    std::vector<std::string> port_specs;
    std::optional<std::string> memory_limit;
    std::optional<double> cpu_limit;
    std::optional<int> pids_limit;
    std::optional<std::string> hostname;
    std::optional<std::string> workdir;
    std::string image_dir{IMAGE_DIR};
    std::string containers_dir{CONTAINERS_DIR};
};

[[nodiscard]] JsonObject load_image_metadata(const std::string& image_path);
[[nodiscard]] std::vector<std::string> resolve_command(
    const std::vector<std::string>& cli_cmd,
    const JsonObject& metadata);
[[nodiscard]] std::map<std::string, std::string> build_container_env(
    const JsonObject& metadata,
    const std::vector<std::string>& env_specs,
    const std::string& hostname);

[[nodiscard]] std::vector<JsonObject> list_containers(
    bool show_all = false,
    const std::string& containers_dir = CONTAINERS_DIR);
std::string remove_container(
    const std::string& identifier,
    bool force = false,
    const std::string& containers_dir = CONTAINERS_DIR);
int stop_container(
    const std::string& identifier,
    int timeout_sec = 10,
    const std::string& containers_dir = CONTAINERS_DIR);
int show_container_logs(
    const std::string& identifier,
    bool follow = false,
    int tail_lines = -1,
    const std::string& containers_dir = CONTAINERS_DIR);
int exec_in_container(
    const std::string& identifier,
    const std::vector<std::string>& cmd_args,
    const std::vector<std::string>& env_specs = {},
    const std::optional<std::string>& workdir = std::nullopt,
    const std::string& containers_dir = CONTAINERS_DIR);
int run_container(const ContainerRunConfig& config);

}  // namespace pieces

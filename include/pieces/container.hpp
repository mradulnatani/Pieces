#pragma once

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "pieces/filesystem.hpp"
#include "pieces/json.hpp"

namespace pieces {

enum class RestartPolicy {
    No,
    OnFailure,
    Always,
    UnlessStopped,
};

struct ContainerRunConfig {
    std::string image;
    std::vector<std::string> cmd_args;
    std::optional<std::string> name;
    bool auto_remove{false};
    bool detach{false};
    bool interactive{false};
    bool allocate_tty{false};
    bool rootless{false};
    bool privileged{false};
    bool readonly_rootfs{false};
    bool full_copy{false};
    bool run_as_non_root{false};
    bool isolate_net{true};
    bool timing{false};
    RestartPolicy restart_policy{RestartPolicy::No};
    std::size_t log_max_bytes{10ULL * 1024ULL * 1024ULL};
    int log_max_files{3};
    std::string network_mode{"bridge"};
    std::optional<std::string> user_spec;
    std::optional<std::string> seccomp_profile;
    std::optional<std::string> entrypoint_override;
    std::vector<std::string> security_opts;
    std::vector<std::string> env_specs;
    std::vector<std::string> env_files;
    std::vector<std::string> volume_specs;
    std::vector<std::string> tmpfs_specs;
    std::vector<std::string> port_specs;
    std::vector<std::string> add_hosts;
    std::vector<std::string> dns_servers;
    std::vector<std::string> cap_add;
    std::vector<std::string> cap_drop;
    std::optional<std::string> memory_limit;
    std::optional<double> cpu_limit;
    std::optional<int> pids_limit;
    std::optional<std::string> hostname;
    std::optional<std::string> workdir;
    std::string image_dir{IMAGE_DIR};
    std::string containers_dir{CONTAINERS_DIR};
    std::string volumes_dir{VOLUMES_DIR};
    std::string networks_dir{NETWORKS_DIR};
};

class RotatingLogWriter {
public:
    RotatingLogWriter(std::string base_path, std::size_t max_bytes, int max_files);
    void write(const char* data, std::size_t len);
    void flush();

private:
    void rotate();

    std::string base_path_;
    std::size_t max_bytes_;
    int max_files_;
    std::size_t current_bytes_{0};
    int fd_{-1};
};

[[nodiscard]] RestartPolicy parse_restart_policy(const std::string& spec);
[[nodiscard]] std::string restart_policy_to_string(RestartPolicy policy);
[[nodiscard]] std::size_t parse_byte_size(const std::string& spec);
[[nodiscard]] std::vector<std::string> load_env_file(const std::string& path);

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
[[nodiscard]] JsonObject inspect_container_json(
    const std::string& identifier,
    const std::string& containers_dir = CONTAINERS_DIR);
[[nodiscard]] JsonObject inspect_any_json(
    const std::string& identifier,
    const std::string& image_dir = IMAGE_DIR,
    const std::string& containers_dir = CONTAINERS_DIR);
void copy_between_host_and_container(
    const std::string& src_spec,
    const std::string& dst_spec,
    const std::string& image_dir = IMAGE_DIR,
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
    bool allocate_tty = false,
    const std::string& containers_dir = CONTAINERS_DIR);
int show_container_stats(
    const std::string& identifier,
    const std::string& containers_dir = CONTAINERS_DIR,
    const std::string& cgroup_root = "/sys/fs/cgroup");
int run_container(const ContainerRunConfig& config);

}  // namespace pieces

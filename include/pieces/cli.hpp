#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace pieces {

enum class CliCommand {
    Help,
    Build,
    Pull,
    Run,
    Images,
    Ps,
    Stop,
    Logs,
    Exec,
    Rm,
    Rmi,
    Prune,
    Stats,
    Inspect,
    Tag,
    Cp,
    Volume,
    Network,
    Login,
    Compose,
    Serve,
    // OCI Runtime Specification commands (runc/crun-compatible)
    OciSpec,
    OciCreate,
    OciStart,
    OciState,
    OciKill,
    OciDelete,
};

struct CliArgs {
    CliCommand command{CliCommand::Help};

    // build
    std::string context;
    std::optional<std::string> tag;
    std::string build_file;
    std::map<std::string, std::string> build_args;
    bool no_cache{false};

    // pull / login
    std::string pull_ref;
    std::string login_registry;
    std::string login_username;
    std::string login_password;
    bool password_stdin{false};

    // run
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
    std::string restart_policy{"no"};
    std::string log_max_size{"10m"};
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
    std::string image;
    std::vector<std::string> cmd_args;

    // ps
    bool show_all{false};

    // stop
    int timeout_sec{10};

    // logs / exec / stats / inspect / tag / cp
    bool follow{false};
    int tail_lines{-1};
    std::string target_container;
    std::string src_arg;
    std::string dst_arg;

    // volume / network
    std::string sub_action;
    std::string subnet_cidr;
    std::vector<std::string> extra_args;

    // compose / serve
    std::string compose_file;
    bool compose_build{false};
    std::string socket_path{"/run/pieces/docker.sock"};

    // rm
    bool force{false};
    std::vector<std::string> containers;

    // rmi
    std::vector<std::string> images;

    // OCI runtime commands
    std::string oci_bundle{"."};
    std::string oci_pid_file;
    std::string oci_state_root;
    std::string oci_signal{"SIGTERM"};
};

void print_help();
[[nodiscard]] CliArgs parse_command_args(int argc, const char* const* argv);
[[nodiscard]] CliArgs parse_command_args(const std::vector<std::string>& args);

}  // namespace pieces

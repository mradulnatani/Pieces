#pragma once

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
};

struct CliArgs {
    CliCommand command{CliCommand::Help};

    // build
    std::string context;
    std::optional<std::string> tag;
    bool no_cache{false};

    // pull
    std::string pull_ref;

    // run
    std::optional<std::string> name;
    bool auto_remove{false};
    bool detach{false};
    bool interactive{false};
    bool allocate_tty{false};
    bool rootless{false};
    bool privileged{false};
    std::string restart_policy{"no"};
    std::string log_max_size{"10m"};
    int log_max_files{3};
    std::string network_mode{"bridge"};
    std::vector<std::string> env_specs;
    std::vector<std::string> volume_specs;
    std::vector<std::string> port_specs;
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

    // logs
    bool follow{false};
    int tail_lines{-1};
    std::string target_container;

    // rm
    bool force{false};
    std::vector<std::string> containers;

    // rmi
    std::vector<std::string> images;
};

void print_help();
[[nodiscard]] CliArgs parse_command_args(int argc, const char* const* argv);
[[nodiscard]] CliArgs parse_command_args(const std::vector<std::string>& args);

}  // namespace pieces

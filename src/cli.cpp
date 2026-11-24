#include "pieces/cli.hpp"

#include <iostream>
#include <stdexcept>

namespace pieces {

namespace {

std::string require_value(const std::vector<std::string>& args, size_t& i, const std::string& flag) {
    if (i + 1 >= args.size()) {
        throw std::invalid_argument("Option '" + flag + "' requires an argument");
    }
    return args[++i];
}

}  // namespace

void print_help() {
    std::cout <<
        "usage: pieces [-h] <command> ...\n\n"
        "Pieces: A hardened Linux & OCI-compatible container runtime in C++20.\n\n"
        "native commands:\n"
        "  build               Build an image from a Piecefile (executes COPY/RUN in order).\n"
        "  pull                Pull an OCI image from a non-Docker-Hub registry.\n"
        "  run                 Run a command inside a new container.\n"
        "  images              List built/pulled images.\n"
        "  ps                  List containers.\n"
        "  stop                Stop one or more running containers.\n"
        "  logs                View logs from a detached container.\n"
        "  exec                Execute a command inside a running container.\n"
        "  stats               Print cgroup v2 memory/CPU/PIDs telemetry for a container.\n"
        "  rm                  Remove one or more containers.\n"
        "  rmi                 Remove one or more images.\n"
        "  prune               Remove stopped containers and cached download artifacts.\n\n"
        "OCI runtime commands (containerd / Kubernetes-compatible):\n"
        "  spec                Generate a default OCI config.json in the current directory.\n"
        "  create              Create a container from an OCI bundle.\n"
        "  start               Start a previously created OCI container.\n"
        "  state               Output OCI state JSON for a container.\n"
        "  kill                Send a signal to an OCI container.\n"
        "  delete              Delete a stopped OCI container.\n";
}

CliArgs parse_command_args(int argc, const char* const* argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    return parse_command_args(args);
}

CliArgs parse_command_args(const std::vector<std::string>& args) {
    if (args.empty()) throw std::invalid_argument("Missing subcommand (try --help)");

    CliArgs parsed;
    size_t idx = 0;
    // Allow global OCI `--root <state_root>` flag before subcommand (used by containerd)
    if (args[0] == "--root") {
        parsed.oci_state_root = require_value(args, idx, "--root");
        ++idx;
        if (idx >= args.size()) throw std::invalid_argument("Missing subcommand after --root");
    }

    const std::string& sub = args[idx];
    if (sub == "-h" || sub == "--help") {
        parsed.command = CliCommand::Help;
        return parsed;
    }

    if (sub == "build") {
        parsed.command = CliCommand::Build;
        bool has_context = false;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            const std::string& tok = args[i];
            if (tok == "-t" || tok == "--tag") parsed.tag = require_value(args, i, tok);
            else if (tok == "--no-cache") parsed.no_cache = true;
            else if (tok == "-h" || tok == "--help") { parsed.command = CliCommand::Help; return parsed; }
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown build option: " + tok);
            else if (!has_context) { parsed.context = tok; has_context = true; }
            else throw std::invalid_argument("Unexpected extra argument to build: " + tok);
        }
        if (!has_context) throw std::invalid_argument("build requires <context> directory");
        return parsed;
    }

    if (sub == "pull") {
        parsed.command = CliCommand::Pull;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            const std::string& tok = args[i];
            if (tok == "-t" || tok == "--tag") parsed.tag = require_value(args, i, tok);
            else if (tok == "-h" || tok == "--help") { parsed.command = CliCommand::Help; return parsed; }
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown pull option: " + tok);
            else if (parsed.pull_ref.empty()) parsed.pull_ref = tok;
            else throw std::invalid_argument("Unexpected extra argument to pull: " + tok);
        }
        if (parsed.pull_ref.empty()) throw std::invalid_argument("pull requires <image_ref>");
        return parsed;
    }

    if (sub == "run") {
        parsed.command = CliCommand::Run;
        size_t i = idx + 1;
        while (i < args.size()) {
            const std::string& tok = args[i];
            if (tok == "-h" || tok == "--help") { parsed.command = CliCommand::Help; return parsed; }
            else if (tok == "--name") parsed.name = require_value(args, i, tok);
            else if (tok == "--rm") parsed.auto_remove = true;
            else if (tok == "-d" || tok == "--detach") parsed.detach = true;
            else if (tok == "-i" || tok == "--interactive") parsed.interactive = true;
            else if (tok == "-t" || tok == "--tty") parsed.allocate_tty = true;
            else if (tok == "-it" || tok == "-ti") { parsed.interactive = true; parsed.allocate_tty = true; }
            else if (tok == "--rootless" || tok == "--userns") parsed.rootless = true;
            else if (tok == "--privileged") parsed.privileged = true;
            else if (tok == "--read-only") parsed.readonly_rootfs = true;
            else if (tok == "--full-copy") parsed.full_copy = true;
            else if (tok == "--run-as-non-root") parsed.run_as_non_root = true;
            else if (tok == "--no-isolate-net") parsed.isolate_net = false;
            else if (tok == "--timing") parsed.timing = true;
            else if (tok == "-u" || tok == "--user") parsed.user_spec = require_value(args, i, tok);
            else if (tok == "--seccomp-profile") parsed.seccomp_profile = require_value(args, i, tok);
            else if (tok == "--security-opt") parsed.security_opts.push_back(require_value(args, i, tok));
            else if (tok == "--restart") parsed.restart_policy = require_value(args, i, tok);
            else if (tok == "--log-max-size") parsed.log_max_size = require_value(args, i, tok);
            else if (tok == "--log-max-files") parsed.log_max_files = std::stoi(require_value(args, i, tok));
            else if (tok == "--cap-add") parsed.cap_add.push_back(require_value(args, i, tok));
            else if (tok == "--cap-drop") parsed.cap_drop.push_back(require_value(args, i, tok));
            else if (tok == "--net") {
                std::string mode = require_value(args, i, tok);
                if (mode != "bridge" && mode != "none") {
                    throw std::invalid_argument("Invalid --net mode '" + mode + "'; expected bridge or none");
                }
                parsed.network_mode = mode;
            } else if (tok == "-e" || tok == "--env") parsed.env_specs.push_back(require_value(args, i, tok));
            else if (tok == "-v" || tok == "--volume") parsed.volume_specs.push_back(require_value(args, i, tok));
            else if (tok == "-p" || tok == "--publish") parsed.port_specs.push_back(require_value(args, i, tok));
            else if (tok == "--memory") parsed.memory_limit = require_value(args, i, tok);
            else if (tok == "--cpus") parsed.cpu_limit = std::stod(require_value(args, i, tok));
            else if (tok == "--pids-max") parsed.pids_limit = std::stoi(require_value(args, i, tok));
            else if (tok == "--hostname") parsed.hostname = require_value(args, i, tok);
            else if (tok == "-w" || tok == "--workdir") parsed.workdir = require_value(args, i, tok);
            else if (tok == "--") {
                ++i;
                if (i >= args.size()) throw std::invalid_argument("run requires <image>");
                parsed.image = args[i++];
                break;
            } else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown run option: " + tok);
            else { parsed.image = tok; ++i; break; }
            ++i;
        }
        if (parsed.image.empty()) throw std::invalid_argument("run requires <image>");
        if (i < args.size() && args[i] == "--") ++i;
        while (i < args.size()) parsed.cmd_args.push_back(args[i++]);
        return parsed;
    }

    if (sub == "images") { parsed.command = CliCommand::Images; return parsed; }

    if (sub == "ps") {
        parsed.command = CliCommand::Ps;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            if (args[i] == "-a" || args[i] == "--all") parsed.show_all = true;
            else throw std::invalid_argument("Unknown ps option: " + args[i]);
        }
        return parsed;
    }

    if (sub == "stop") {
        parsed.command = CliCommand::Stop;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            const std::string& tok = args[i];
            if (tok == "-t" || tok == "--time") parsed.timeout_sec = std::stoi(require_value(args, i, tok));
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown stop option: " + tok);
            else parsed.containers.push_back(tok);
        }
        if (parsed.containers.empty()) throw std::invalid_argument("stop requires at least one container ID or name");
        return parsed;
    }

    if (sub == "logs") {
        parsed.command = CliCommand::Logs;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            const std::string& tok = args[i];
            if (tok == "-f" || tok == "--follow") parsed.follow = true;
            else if (tok == "-n" || tok == "--tail") parsed.tail_lines = std::stoi(require_value(args, i, tok));
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown logs option: " + tok);
            else if (parsed.target_container.empty()) parsed.target_container = tok;
            else throw std::invalid_argument("Unexpected extra argument to logs: " + tok);
        }
        if (parsed.target_container.empty()) throw std::invalid_argument("logs requires <container>");
        return parsed;
    }

    if (sub == "exec") {
        parsed.command = CliCommand::Exec;
        size_t i = idx + 1;
        while (i < args.size()) {
            const std::string& tok = args[i];
            if (tok == "-i" || tok == "--interactive") parsed.interactive = true;
            else if (tok == "-t" || tok == "--tty") parsed.allocate_tty = true;
            else if (tok == "-it" || tok == "-ti") { parsed.interactive = true; parsed.allocate_tty = true; }
            else if (tok == "-e" || tok == "--env") parsed.env_specs.push_back(require_value(args, i, tok));
            else if (tok == "-w" || tok == "--workdir") parsed.workdir = require_value(args, i, tok);
            else if (tok == "--") {
                ++i;
                if (i >= args.size()) throw std::invalid_argument("exec requires <container> <command>");
                parsed.target_container = args[i++];
                break;
            } else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown exec option: " + tok);
            else { parsed.target_container = tok; ++i; break; }
            ++i;
        }
        if (parsed.target_container.empty()) throw std::invalid_argument("exec requires <container> <command>");
        while (i < args.size()) parsed.cmd_args.push_back(args[i++]);
        if (parsed.cmd_args.empty()) throw std::invalid_argument("exec requires a command to run inside the container");
        return parsed;
    }

    if (sub == "stats") {
        parsed.command = CliCommand::Stats;
        if (idx + 1 >= args.size()) throw std::invalid_argument("stats requires <container>");
        parsed.target_container = args[idx + 1];
        return parsed;
    }

    if (sub == "rm") {
        parsed.command = CliCommand::Rm;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            if (args[i] == "-f" || args[i] == "--force") parsed.force = true;
            else if (!args[i].empty() && args[i][0] == '-') throw std::invalid_argument("Unknown rm option: " + args[i]);
            else parsed.containers.push_back(args[i]);
        }
        if (parsed.containers.empty()) throw std::invalid_argument("rm requires at least one container ID or name");
        return parsed;
    }

    if (sub == "rmi") {
        parsed.command = CliCommand::Rmi;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            if (!args[i].empty() && args[i][0] == '-') throw std::invalid_argument("Unknown rmi option: " + args[i]);
            parsed.images.push_back(args[i]);
        }
        if (parsed.images.empty()) throw std::invalid_argument("rmi requires at least one image name");
        return parsed;
    }

    if (sub == "prune") { parsed.command = CliCommand::Prune; return parsed; }

    // OCI Runtime Spec subcommands
    if (sub == "spec") {
        parsed.command = CliCommand::OciSpec;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            if (args[i] == "--rootless") parsed.rootless = true;
            else throw std::invalid_argument("Unknown spec option: " + args[i]);
        }
        return parsed;
    }

    if (sub == "create") {
        parsed.command = CliCommand::OciCreate;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            const std::string& tok = args[i];
            if (tok == "-b" || tok == "--bundle") parsed.oci_bundle = require_value(args, i, tok);
            else if (tok == "--pid-file") parsed.oci_pid_file = require_value(args, i, tok);
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown create option: " + tok);
            else if (parsed.target_container.empty()) parsed.target_container = tok;
            else throw std::invalid_argument("Unexpected argument to create: " + tok);
        }
        if (parsed.target_container.empty()) throw std::invalid_argument("create requires <container-id>");
        return parsed;
    }

    if (sub == "start") {
        parsed.command = CliCommand::OciStart;
        if (idx + 1 >= args.size()) throw std::invalid_argument("start requires <container-id>");
        parsed.target_container = args[idx + 1];
        return parsed;
    }

    if (sub == "state") {
        parsed.command = CliCommand::OciState;
        if (idx + 1 >= args.size()) throw std::invalid_argument("state requires <container-id>");
        parsed.target_container = args[idx + 1];
        return parsed;
    }

    if (sub == "kill") {
        parsed.command = CliCommand::OciKill;
        if (idx + 1 >= args.size()) throw std::invalid_argument("kill requires <container-id> [SIGNAL]");
        parsed.target_container = args[idx + 1];
        if (idx + 2 < args.size()) parsed.oci_signal = args[idx + 2];
        return parsed;
    }

    if (sub == "delete") {
        parsed.command = CliCommand::OciDelete;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            if (args[i] == "-f" || args[i] == "--force") parsed.force = true;
            else if (!args[i].empty() && args[i][0] == '-') throw std::invalid_argument("Unknown delete option: " + args[i]);
            else if (parsed.target_container.empty()) parsed.target_container = args[i];
        }
        if (parsed.target_container.empty()) throw std::invalid_argument("delete requires <container-id>");
        return parsed;
    }

    throw std::invalid_argument("Unknown command: " + sub);
}

}  // namespace pieces

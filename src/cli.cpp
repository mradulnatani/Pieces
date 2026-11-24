#include "pieces/cli.hpp"

#include <iostream>
#include <stdexcept>

namespace pieces {

namespace {

// Read an option value from either `--flag=value` (in split form) or the next argv element.
std::string consume_value(
    const std::vector<std::string>& args,
    size_t& i,
    const std::string& raw_tok,
    std::optional<std::string>& inline_val) {
    if (inline_val.has_value()) {
        std::string v = *inline_val;
        inline_val.reset();
        return v;
    }
    if (i + 1 >= args.size()) {
        throw std::invalid_argument("Option '" + raw_tok + "' requires an argument");
    }
    return args[++i];
}

void split_eq_flag(const std::string& raw, std::string& opt, std::optional<std::string>& inline_val) {
    inline_val.reset();
    if (raw.rfind("--", 0) == 0 && raw.size() > 2) {
        auto eq = raw.find('=');
        if (eq != std::string::npos) {
            opt = raw.substr(0, eq);
            inline_val = raw.substr(eq + 1);
            return;
        }
    }
    opt = raw;
}

bool try_parse_combined_short_run_flags(const std::string& tok, CliArgs& parsed, bool allow_detach) {
    if (tok.size() < 2 || tok[0] != '-' || tok[1] == '-') return false;
    for (size_t k = 1; k < tok.size(); ++k) {
        char ch = tok[k];
        if (ch != 'i' && ch != 't' && !(allow_detach && ch == 'd')) return false;
    }
    for (size_t k = 1; k < tok.size(); ++k) {
        if (tok[k] == 'i') parsed.interactive = true;
        else if (tok[k] == 't') parsed.allocate_tty = true;
        else if (tok[k] == 'd') parsed.detach = true;
    }
    return true;
}

}  // namespace

void print_help() {
    std::cout <<
        "usage: pieces [-h] <command> ...\n\n"
        "Pieces: A hardened Linux & OCI-compatible container runtime in C++20.\n\n"
        "native commands:\n"
        "  build               Build an image from a Piecefile/Dockerfile (supports multi-stage & layer cache).\n"
        "  pull                Pull an OCI image from a non-Docker-Hub registry.\n"
        "  login               Save credentials for a non-Docker-Hub OCI registry.\n"
        "  tag                 Create a target image tag from a source image.\n"
        "  run                 Run a command inside a new container.\n"
        "  images              List built/pulled images.\n"
        "  ps                  List containers.\n"
        "  inspect             Print detailed JSON metadata for a container or image.\n"
        "  stop                Stop one or more running containers.\n"
        "  logs                View logs from a detached container.\n"
        "  exec                Execute a command inside a running container.\n"
        "  cp                  Copy files/directories between host and container.\n"
        "  stats               Print cgroup v2 memory/CPU/PIDs telemetry for a container.\n"
        "  rm                  Remove one or more containers.\n"
        "  rmi                 Remove one or more images.\n"
        "  prune               Remove stopped containers and cached download artifacts.\n"
        "  volume              Manage named volumes (create, ls, inspect, rm).\n"
        "  network             Manage container networks & embedded DNS (create, ls, inspect, rm).\n"
        "  compose             Manage multi-container apps via compose.yaml (up, down, ps, logs).\n"
        "  serve               Start an optional Docker-compatible REST Unix socket server.\n\n"
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
    std::string root_opt;
    std::optional<std::string> root_val;
    split_eq_flag(args[0], root_opt, root_val);
    if (root_opt == "--root") {
        parsed.oci_state_root = consume_value(args, idx, root_opt, root_val);
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
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "-t" || tok == "--tag") parsed.tag = consume_value(args, i, tok, eqv);
            else if (tok == "-f" || tok == "--file") parsed.build_file = consume_value(args, i, tok, eqv);
            else if (tok == "--build-arg") {
                std::string kv = consume_value(args, i, tok, eqv);
                auto eq = kv.find('=');
                if (eq == std::string::npos || eq == 0) {
                    throw std::invalid_argument("--build-arg expects KEY=VAL, got '" + kv + "'");
                }
                parsed.build_args[kv.substr(0, eq)] = kv.substr(eq + 1);
            } else if (tok == "--no-cache") parsed.no_cache = true;
            else if (tok == "-h" || tok == "--help") { parsed.command = CliCommand::Help; return parsed; }
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown build option: " + tok);
            else if (!has_context) { parsed.context = args[i]; has_context = true; }
            else throw std::invalid_argument("Unexpected extra argument to build: " + args[i]);
        }
        if (!has_context) throw std::invalid_argument("build requires <context> directory");
        return parsed;
    }

    if (sub == "pull") {
        parsed.command = CliCommand::Pull;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "-t" || tok == "--tag") parsed.tag = consume_value(args, i, tok, eqv);
            else if (tok == "-h" || tok == "--help") { parsed.command = CliCommand::Help; return parsed; }
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown pull option: " + tok);
            else if (parsed.pull_ref.empty()) parsed.pull_ref = args[i];
            else throw std::invalid_argument("Unexpected extra argument to pull: " + args[i]);
        }
        if (parsed.pull_ref.empty()) throw std::invalid_argument("pull requires <image_ref>");
        return parsed;
    }

    if (sub == "login") {
        parsed.command = CliCommand::Login;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "-u" || tok == "--username") parsed.login_username = consume_value(args, i, tok, eqv);
            else if (tok == "-p" || tok == "--password") parsed.login_password = consume_value(args, i, tok, eqv);
            else if (tok == "--password-stdin") parsed.password_stdin = true;
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown login option: " + tok);
            else if (parsed.login_registry.empty()) parsed.login_registry = args[i];
            else throw std::invalid_argument("Unexpected extra argument to login: " + args[i]);
        }
        if (parsed.login_registry.empty()) throw std::invalid_argument("login requires <registry>");
        return parsed;
    }

    if (sub == "tag") {
        parsed.command = CliCommand::Tag;
        if (idx + 2 >= args.size()) throw std::invalid_argument("tag requires <source_image> <target_image>");
        parsed.src_arg = args[idx + 1];
        parsed.dst_arg = args[idx + 2];
        return parsed;
    }

    if (sub == "inspect") {
        parsed.command = CliCommand::Inspect;
        if (idx + 1 >= args.size()) throw std::invalid_argument("inspect requires <container|image>");
        parsed.target_container = args[idx + 1];
        return parsed;
    }

    if (sub == "cp") {
        parsed.command = CliCommand::Cp;
        if (idx + 2 >= args.size()) throw std::invalid_argument("cp requires <src> <dst>");
        parsed.src_arg = args[idx + 1];
        parsed.dst_arg = args[idx + 2];
        return parsed;
    }

    if (sub == "volume" || sub == "network") {
        parsed.command = (sub == "volume") ? CliCommand::Volume : CliCommand::Network;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "--subnet" && parsed.command == CliCommand::Network) {
                parsed.subnet_cidr = consume_value(args, i, tok, eqv);
            } else if (!tok.empty() && tok[0] == '-') {
                throw std::invalid_argument("Unknown " + sub + " option: " + tok);
            } else if (parsed.sub_action.empty()) {
                parsed.sub_action = args[i];
            } else {
                parsed.extra_args.push_back(args[i]);
            }
        }
        if (parsed.sub_action.empty()) {
            throw std::invalid_argument(sub + " requires a subcommand (create|ls|inspect|rm)");
        }
        return parsed;
    }

    if (sub == "compose") {
        parsed.command = CliCommand::Compose;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "-f" || tok == "--file") parsed.compose_file = consume_value(args, i, tok, eqv);
            else if (tok == "-d" || tok == "--detach") parsed.detach = true;
            else if (tok == "--build") parsed.compose_build = true;
            else if (tok == "--follow") parsed.follow = true;
            else if (tok == "-n" || tok == "--tail") parsed.tail_lines = std::stoi(consume_value(args, i, tok, eqv));
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown compose option: " + tok);
            else if (parsed.sub_action.empty()) parsed.sub_action = args[i];
            else parsed.extra_args.push_back(args[i]);
        }
        if (parsed.sub_action.empty()) parsed.sub_action = "up";
        return parsed;
    }

    if (sub == "serve") {
        parsed.command = CliCommand::Serve;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "--socket") parsed.socket_path = consume_value(args, i, tok, eqv);
            else throw std::invalid_argument("Unknown serve option: " + tok);
        }
        return parsed;
    }

    if (sub == "run") {
        parsed.command = CliCommand::Run;
        size_t i = idx + 1;
        while (i < args.size()) {
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);

            if (tok == "-h" || tok == "--help") { parsed.command = CliCommand::Help; return parsed; }
            else if (tok == "--name") parsed.name = consume_value(args, i, tok, eqv);
            else if (tok == "--rm") parsed.auto_remove = true;
            else if (tok == "-d" || tok == "--detach") parsed.detach = true;
            else if (tok == "-i" || tok == "--interactive") parsed.interactive = true;
            else if (tok == "-t" || tok == "--tty") parsed.allocate_tty = true;
            else if (try_parse_combined_short_run_flags(args[i], parsed, true)) {}
            else if (tok == "--rootless" || tok == "--userns") parsed.rootless = true;
            else if (tok == "--privileged") parsed.privileged = true;
            else if (tok == "--read-only") parsed.readonly_rootfs = true;
            else if (tok == "--full-copy") parsed.full_copy = true;
            else if (tok == "--run-as-non-root") parsed.run_as_non_root = true;
            else if (tok == "--no-isolate-net") parsed.isolate_net = false;
            else if (tok == "--timing") parsed.timing = true;
            else if (tok == "-u" || tok == "--user") parsed.user_spec = consume_value(args, i, tok, eqv);
            else if (tok == "--seccomp-profile") parsed.seccomp_profile = consume_value(args, i, tok, eqv);
            else if (tok == "--entrypoint") parsed.entrypoint_override = consume_value(args, i, tok, eqv);
            else if (tok == "--security-opt") parsed.security_opts.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "--restart") parsed.restart_policy = consume_value(args, i, tok, eqv);
            else if (tok == "--log-max-size") parsed.log_max_size = consume_value(args, i, tok, eqv);
            else if (tok == "--log-max-files") parsed.log_max_files = std::stoi(consume_value(args, i, tok, eqv));
            else if (tok == "--cap-add") parsed.cap_add.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "--cap-drop") parsed.cap_drop.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "--net" || tok == "--network") parsed.network_mode = consume_value(args, i, tok, eqv);
            else if (tok == "-e" || tok == "--env") parsed.env_specs.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "--env-file") parsed.env_files.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "-v" || tok == "--volume") parsed.volume_specs.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "--tmpfs") parsed.tmpfs_specs.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "-p" || tok == "--publish") parsed.port_specs.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "--add-host") parsed.add_hosts.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "--dns") parsed.dns_servers.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "--memory") parsed.memory_limit = consume_value(args, i, tok, eqv);
            else if (tok == "--cpus") parsed.cpu_limit = std::stod(consume_value(args, i, tok, eqv));
            else if (tok == "--pids-max") parsed.pids_limit = std::stoi(consume_value(args, i, tok, eqv));
            else if (tok == "--hostname") parsed.hostname = consume_value(args, i, tok, eqv);
            else if (tok == "-w" || tok == "--workdir") parsed.workdir = consume_value(args, i, tok, eqv);
            else if (tok == "--") {
                ++i;
                if (i >= args.size()) throw std::invalid_argument("run requires <image>");
                parsed.image = args[i++];
                break;
            } else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown run option: " + tok);
            else { parsed.image = args[i++]; break; }
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
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "-t" || tok == "--time") parsed.timeout_sec = std::stoi(consume_value(args, i, tok, eqv));
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown stop option: " + tok);
            else parsed.containers.push_back(args[i]);
        }
        if (parsed.containers.empty()) throw std::invalid_argument("stop requires at least one container ID or name");
        return parsed;
    }

    if (sub == "logs") {
        parsed.command = CliCommand::Logs;
        for (size_t i = idx + 1; i < args.size(); ++i) {
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "-f" || tok == "--follow") parsed.follow = true;
            else if (tok == "-n" || tok == "--tail") parsed.tail_lines = std::stoi(consume_value(args, i, tok, eqv));
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown logs option: " + tok);
            else if (parsed.target_container.empty()) parsed.target_container = args[i];
            else throw std::invalid_argument("Unexpected extra argument to logs: " + args[i]);
        }
        if (parsed.target_container.empty()) throw std::invalid_argument("logs requires <container>");
        return parsed;
    }

    if (sub == "exec") {
        parsed.command = CliCommand::Exec;
        size_t i = idx + 1;
        while (i < args.size()) {
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "-i" || tok == "--interactive") parsed.interactive = true;
            else if (tok == "-t" || tok == "--tty") parsed.allocate_tty = true;
            else if (try_parse_combined_short_run_flags(args[i], parsed, false)) {}
            else if (tok == "-e" || tok == "--env") parsed.env_specs.push_back(consume_value(args, i, tok, eqv));
            else if (tok == "-w" || tok == "--workdir") parsed.workdir = consume_value(args, i, tok, eqv);
            else if (tok == "--") {
                ++i;
                if (i >= args.size()) throw std::invalid_argument("exec requires <container> <command>");
                parsed.target_container = args[i++];
                break;
            } else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown exec option: " + tok);
            else { parsed.target_container = args[i++]; break; }
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
            std::string tok;
            std::optional<std::string> eqv;
            split_eq_flag(args[i], tok, eqv);
            if (tok == "-b" || tok == "--bundle") parsed.oci_bundle = consume_value(args, i, tok, eqv);
            else if (tok == "--pid-file") parsed.oci_pid_file = consume_value(args, i, tok, eqv);
            else if (!tok.empty() && tok[0] == '-') throw std::invalid_argument("Unknown create option: " + tok);
            else if (parsed.target_container.empty()) parsed.target_container = args[i];
            else throw std::invalid_argument("Unexpected argument to create: " + args[i]);
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

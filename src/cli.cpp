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
        "usage: pieces [-h] {build,run,images,ps,rm,rmi} ...\n\n"
        "Pieces: A lightweight Linux container runtime in C++.\n\n"
        "positional arguments:\n"
        "  {build,run,images,ps,rm,rmi}\n"
        "    build               Build an image from a Piecefile.\n"
        "    run                 Run a command inside a new container.\n"
        "    images              List built images.\n"
        "    ps                  List containers.\n"
        "    rm                  Remove one or more containers.\n"
        "    rmi                 Remove one or more images.\n\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n";
}

CliArgs parse_command_args(int argc, const char* const* argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    return parse_command_args(args);
}

CliArgs parse_command_args(const std::vector<std::string>& args) {
    if (args.empty()) {
        throw std::invalid_argument("Missing subcommand (try --help)");
    }

    CliArgs parsed;
    const std::string& sub = args[0];
    if (sub == "-h" || sub == "--help") {
        parsed.command = CliCommand::Help;
        return parsed;
    }

    if (sub == "build") {
        parsed.command = CliCommand::Build;
        bool has_context = false;
        for (size_t i = 1; i < args.size(); ++i) {
            const std::string& tok = args[i];
            if (tok == "-t" || tok == "--tag") {
                parsed.tag = require_value(args, i, tok);
            } else if (tok == "-h" || tok == "--help") {
                parsed.command = CliCommand::Help;
                return parsed;
            } else if (!tok.empty() && tok[0] == '-') {
                throw std::invalid_argument("Unknown build option: " + tok);
            } else if (!has_context) {
                parsed.context = tok;
                has_context = true;
            } else {
                throw std::invalid_argument("Unexpected extra argument to build: " + tok);
            }
        }
        if (!has_context) {
            throw std::invalid_argument("build requires <context> directory");
        }
        return parsed;
    }

    if (sub == "run") {
        parsed.command = CliCommand::Run;
        size_t i = 1;
        while (i < args.size()) {
            const std::string& tok = args[i];
            if (tok == "-h" || tok == "--help") {
                parsed.command = CliCommand::Help;
                return parsed;
            } else if (tok == "--name") {
                parsed.name = require_value(args, i, tok);
            } else if (tok == "--rm") {
                parsed.auto_remove = true;
            } else if (tok == "--net") {
                std::string mode = require_value(args, i, tok);
                if (mode != "bridge" && mode != "none") {
                    throw std::invalid_argument("Invalid --net mode '" + mode + "'; expected bridge or none");
                }
                parsed.network_mode = mode;
            } else if (tok == "-e" || tok == "--env") {
                parsed.env_specs.push_back(require_value(args, i, tok));
            } else if (tok == "-v" || tok == "--volume") {
                parsed.volume_specs.push_back(require_value(args, i, tok));
            } else if (tok == "--memory") {
                parsed.memory_limit = require_value(args, i, tok);
            } else if (tok == "--cpus") {
                parsed.cpu_limit = std::stod(require_value(args, i, tok));
            } else if (tok == "--pids-max") {
                parsed.pids_limit = std::stoi(require_value(args, i, tok));
            } else if (tok == "--hostname") {
                parsed.hostname = require_value(args, i, tok);
            } else if (tok == "-w" || tok == "--workdir") {
                parsed.workdir = require_value(args, i, tok);
            } else if (tok == "--") {
                ++i;
                if (i >= args.size()) {
                    throw std::invalid_argument("run requires <image>");
                }
                parsed.image = args[i++];
                break;
            } else if (!tok.empty() && tok[0] == '-') {
                throw std::invalid_argument("Unknown run option: " + tok);
            } else {
                parsed.image = tok;
                ++i;
                break;
            }
            ++i;
        }
        if (parsed.image.empty()) {
            throw std::invalid_argument("run requires <image>");
        }
        if (i < args.size() && args[i] == "--") {
            ++i;
        }
        while (i < args.size()) {
            parsed.cmd_args.push_back(args[i++]);
        }
        return parsed;
    }

    if (sub == "images") {
        parsed.command = CliCommand::Images;
        return parsed;
    }

    if (sub == "ps") {
        parsed.command = CliCommand::Ps;
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "-a" || args[i] == "--all") {
                parsed.show_all = true;
            } else {
                throw std::invalid_argument("Unknown ps option: " + args[i]);
            }
        }
        return parsed;
    }

    if (sub == "rm") {
        parsed.command = CliCommand::Rm;
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "-f" || args[i] == "--force") {
                parsed.force = true;
            } else if (!args[i].empty() && args[i][0] == '-') {
                throw std::invalid_argument("Unknown rm option: " + args[i]);
            } else {
                parsed.containers.push_back(args[i]);
            }
        }
        if (parsed.containers.empty()) {
            throw std::invalid_argument("rm requires at least one container ID or name");
        }
        return parsed;
    }

    if (sub == "rmi") {
        parsed.command = CliCommand::Rmi;
        for (size_t i = 1; i < args.size(); ++i) {
            if (!args[i].empty() && args[i][0] == '-') {
                throw std::invalid_argument("Unknown rmi option: " + args[i]);
            }
            parsed.images.push_back(args[i]);
        }
        if (parsed.images.empty()) {
            throw std::invalid_argument("rmi requires at least one image name");
        }
        return parsed;
    }

    throw std::invalid_argument("Unknown command: " + sub);
}

}  // namespace pieces

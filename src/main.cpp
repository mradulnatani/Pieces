#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>

#include "pieces/cli.hpp"
#include "pieces/container.hpp"
#include "pieces/filesystem.hpp"
#include "pieces/parser.hpp"

namespace fs = std::filesystem;

namespace {

int handle_build(const pieces::CliArgs& args) {
    std::cout << "BUILD: Building from context directory: " << args.context << "\n";
    fs::create_directories(pieces::IMAGE_DIR);

    std::string piecefile_path = (fs::path(args.context) / "Piecefile").string();
    auto spec = pieces::parse_piecefile(piecefile_path);
    if (!spec.has_value()) {
        std::cerr << "BUILD: Failed to parse Piecefile.\n";
        return 1;
    }

    std::string image_name;
    std::string image_path;
    try {
        image_name = pieces::derive_image_name(*spec, args.tag.value_or(""));
        image_path = pieces::resolve_image_path(image_name, pieces::IMAGE_DIR);
    } catch (const std::exception& exc) {
        std::cerr << "BUILD: Error: " << exc.what() << "\n";
        return 1;
    }

    std::cout << "BUILD: Creating image '" << image_name << "'...\n";
    return pieces::build_image(*spec, image_path, args.context) ? 0 : 1;
}

int handle_run(const pieces::CliArgs& args) {
    try {
        pieces::ContainerRunConfig cfg;
        cfg.image = args.image;
        cfg.cmd_args = args.cmd_args;
        cfg.name = args.name;
        cfg.auto_remove = args.auto_remove;
        cfg.network_mode = args.network_mode;
        cfg.env_specs = args.env_specs;
        cfg.volume_specs = args.volume_specs;
        cfg.memory_limit = args.memory_limit;
        cfg.cpu_limit = args.cpu_limit;
        cfg.pids_limit = args.pids_limit;
        cfg.hostname = args.hostname;
        cfg.workdir = args.workdir;
        return pieces::run_container(cfg);
    } catch (const std::exception& exc) {
        std::cerr << "RUN: Error: " << exc.what() << "\n";
        return 1;
    }
}

int handle_images() {
    auto imgs = pieces::list_images();
    if (imgs.empty()) {
        std::cout << "No images found.\n";
        return 0;
    }
    std::cout << std::left
              << std::setw(28) << "IMAGE" << " "
              << std::setw(30) << "DEFAULT CMD" << " PATH\n";
    for (const auto& img : imgs) {
        std::string cmd_str = "-";
        auto it = img.meta.find("cmd");
        if (it != img.meta.end()) {
            if (it->second.is_string()) {
                cmd_str = it->second.as_string();
            } else if (it->second.is_array()) {
                cmd_str.clear();
                const auto& arr = it->second.as_array();
                for (size_t i = 0; i < arr.size(); ++i) {
                    if (arr[i].is_string()) {
                        if (!cmd_str.empty()) cmd_str += ' ';
                        cmd_str += arr[i].as_string();
                    }
                }
                if (cmd_str.empty()) cmd_str = "-";
            }
        }
        std::cout << std::left
                  << std::setw(28) << img.name << " "
                  << std::setw(30) << cmd_str << " "
                  << img.path << "\n";
    }
    return 0;
}

std::string get_str(const pieces::JsonObject& obj, const std::string& key, const std::string& fallback = "") {
    auto it = obj.find(key);
    if (it != obj.end() && it->second.is_string() && !it->second.as_string().empty()) {
        return it->second.as_string();
    }
    return fallback;
}

int handle_ps(const pieces::CliArgs& args) {
    auto containers = pieces::list_containers(args.show_all);
    if (containers.empty()) {
        std::cout << "No containers found.\n";
        return 0;
    }
    std::cout << std::left
              << std::setw(14) << "CONTAINER ID" << " "
              << std::setw(16) << "NAME" << " "
              << std::setw(18) << "IMAGE" << " "
              << std::setw(10) << "STATUS" << " "
              << std::setw(15) << "IP" << " COMMAND\n";
    for (const auto& c : containers) {
        std::cout << std::left
                  << std::setw(14) << get_str(c, "id") << " "
                  << std::setw(16) << get_str(c, "name") << " "
                  << std::setw(18) << get_str(c, "image") << " "
                  << std::setw(10) << get_str(c, "status") << " "
                  << std::setw(15) << get_str(c, "ip", "-") << " "
                  << get_str(c, "command") << "\n";
    }
    return 0;
}

int handle_rm(const pieces::CliArgs& args) {
    int rc = 0;
    for (const auto& ident : args.containers) {
        try {
            std::string removed_id = pieces::remove_container(ident, args.force);
            std::cout << "Removed container " << removed_id << "\n";
        } catch (const std::exception& exc) {
            std::cerr << "rm: " << exc.what() << "\n";
            rc = 1;
        }
    }
    return rc;
}

int handle_rmi(const pieces::CliArgs& args) {
    int rc = 0;
    for (const auto& img : args.images) {
        try {
            pieces::remove_image(img);
            std::cout << "Removed image " << img << "\n";
        } catch (const std::exception& exc) {
            std::cerr << "rmi: " << exc.what() << "\n";
            rc = 1;
        }
    }
    return rc;
}

}  // namespace

int main(int argc, char* argv[]) {
    pieces::CliArgs args;
    try {
        args = pieces::parse_command_args(argc, argv);
    } catch (const std::exception& exc) {
        std::cerr << "pieces: " << exc.what() << "\n";
        return 2;
    }

    switch (args.command) {
        case pieces::CliCommand::Help:
            pieces::print_help();
            return 0;
        case pieces::CliCommand::Build:
            return handle_build(args);
        case pieces::CliCommand::Run:
            return handle_run(args);
        case pieces::CliCommand::Images:
            return handle_images();
        case pieces::CliCommand::Ps:
            return handle_ps(args);
        case pieces::CliCommand::Rm:
            return handle_rm(args);
        case pieces::CliCommand::Rmi:
            return handle_rmi(args);
    }
    return 1;
}

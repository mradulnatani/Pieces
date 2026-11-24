#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include "pieces/cli.hpp"
#include "pieces/container.hpp"
#include "pieces/filesystem.hpp"
#include "pieces/oci_runtime.hpp"
#include "pieces/parser.hpp"
#include "pieces/registry.hpp"

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
    return pieces::build_image(*spec, image_path, args.context, nullptr, nullptr, nullptr, args.no_cache) ? 0 : 1;
}

int handle_pull(const pieces::CliArgs& args) {
    try {
        fs::create_directories(pieces::IMAGE_DIR);
        std::string local_name;
        if (args.tag.has_value()) {
            local_name = *args.tag;
            std::replace(local_name.begin(), local_name.end(), ':', '-');
            std::replace(local_name.begin(), local_name.end(), '/', '-');
            local_name = pieces::validate_name(local_name, "image");
        } else {
            local_name = pieces::parse_image_reference(args.pull_ref).default_local_name();
        }
        std::string image_path = pieces::resolve_image_path(local_name, pieces::IMAGE_DIR);
        return pieces::pull_oci_image(args.pull_ref, image_path) ? 0 : 1;
    } catch (const std::exception& exc) {
        std::cerr << "PULL: Error: " << exc.what() << "\n";
        return 1;
    }
}

int handle_run(const pieces::CliArgs& args) {
    try {
        pieces::ContainerRunConfig cfg;
        cfg.image = args.image;
        cfg.cmd_args = args.cmd_args;
        cfg.name = args.name;
        cfg.auto_remove = args.auto_remove;
        cfg.detach = args.detach;
        cfg.interactive = args.interactive;
        cfg.allocate_tty = args.allocate_tty;
        cfg.rootless = args.rootless;
        cfg.privileged = args.privileged;
        cfg.readonly_rootfs = args.readonly_rootfs;
        cfg.full_copy = args.full_copy;
        cfg.run_as_non_root = args.run_as_non_root;
        cfg.isolate_net = args.isolate_net;
        cfg.timing = args.timing;
        cfg.restart_policy = pieces::parse_restart_policy(args.restart_policy);
        cfg.log_max_bytes = pieces::parse_byte_size(args.log_max_size);
        cfg.log_max_files = args.log_max_files;
        cfg.network_mode = args.network_mode;
        cfg.user_spec = args.user_spec;
        cfg.seccomp_profile = args.seccomp_profile;
        cfg.security_opts = args.security_opts;
        cfg.env_specs = args.env_specs;
        cfg.volume_specs = args.volume_specs;
        cfg.port_specs = args.port_specs;
        cfg.cap_add = args.cap_add;
        cfg.cap_drop = args.cap_drop;
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
            if (it->second.is_string()) cmd_str = it->second.as_string();
            else if (it->second.is_array()) {
                cmd_str.clear();
                for (const auto& item : it->second.as_array()) {
                    if (item.is_string()) {
                        if (!cmd_str.empty()) cmd_str += ' ';
                        cmd_str += item.as_string();
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
    if (it != obj.end() && it->second.is_string() && !it->second.as_string().empty()) return it->second.as_string();
    return fallback;
}

std::string get_ports_str(const pieces::JsonObject& obj) {
    auto it = obj.find("ports");
    if (it == obj.end() || !it->second.is_array() || it->second.as_array().empty()) return "-";
    std::string out;
    for (const auto& item : it->second.as_array()) {
        if (item.is_string()) {
            if (!out.empty()) out += ',';
            out += item.as_string();
        }
    }
    return out.empty() ? "-" : out;
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
              << std::setw(15) << "IP" << " "
              << std::setw(18) << "PORTS" << " COMMAND\n";
    for (const auto& c : containers) {
        std::cout << std::left
                  << std::setw(14) << get_str(c, "id") << " "
                  << std::setw(16) << get_str(c, "name") << " "
                  << std::setw(18) << get_str(c, "image") << " "
                  << std::setw(10) << get_str(c, "status") << " "
                  << std::setw(15) << get_str(c, "ip", "-") << " "
                  << std::setw(18) << get_ports_str(c) << " "
                  << get_str(c, "command") << "\n";
    }
    return 0;
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

    try {
        switch (args.command) {
            case pieces::CliCommand::Help:
                pieces::print_help();
                return 0;
            case pieces::CliCommand::Build:
                return handle_build(args);
            case pieces::CliCommand::Pull:
                return handle_pull(args);
            case pieces::CliCommand::Run:
                return handle_run(args);
            case pieces::CliCommand::Images:
                return handle_images();
            case pieces::CliCommand::Ps:
                return handle_ps(args);
            case pieces::CliCommand::Stop: {
                int rc = 0;
                for (const auto& ident : args.containers) {
                    if (pieces::stop_container(ident, args.timeout_sec) != 0) rc = 1;
                }
                return rc;
            }
            case pieces::CliCommand::Logs:
                return pieces::show_container_logs(args.target_container, args.follow, args.tail_lines);
            case pieces::CliCommand::Exec:
                return pieces::exec_in_container(
                    args.target_container, args.cmd_args, args.env_specs, args.workdir, args.allocate_tty);
            case pieces::CliCommand::Stats:
                return pieces::show_container_stats(args.target_container);
            case pieces::CliCommand::Rm: {
                for (const auto& ident : args.containers) {
                    std::cout << "Removed container " << pieces::remove_container(ident, args.force) << "\n";
                }
                return 0;
            }
            case pieces::CliCommand::Rmi: {
                for (const auto& img : args.images) {
                    pieces::remove_image(img);
                    std::cout << "Removed image " << img << "\n";
                }
                return 0;
            }
            case pieces::CliCommand::Prune: {
                int removed = pieces::prune_unused_data();
                std::cout << "Pruned " << removed << " unused container/cache item(s).\n";
                return 0;
            }
            case pieces::CliCommand::OciSpec: {
                auto spec_obj = pieces::generate_default_oci_spec_json(args.rootless);
                std::ofstream out("config.json");
                out << pieces::JsonValue(spec_obj).dump(2) << "\n";
                std::cout << "Generated OCI config.json\n";
                return 0;
            }
            case pieces::CliCommand::OciCreate:
                return pieces::oci_create(
                    args.target_container, args.oci_bundle, args.oci_pid_file, args.oci_state_root);
            case pieces::CliCommand::OciStart:
                return pieces::oci_start(args.target_container, args.oci_state_root);
            case pieces::CliCommand::OciState:
                return pieces::oci_print_state(args.target_container, args.oci_state_root);
            case pieces::CliCommand::OciKill:
                return pieces::oci_kill(args.target_container, args.oci_signal, args.oci_state_root);
            case pieces::CliCommand::OciDelete:
                return pieces::oci_delete(args.target_container, args.force, args.oci_state_root);
        }
    } catch (const std::exception& exc) {
        std::cerr << "pieces: " << exc.what() << "\n";
        return 1;
    }
    return 1;
}

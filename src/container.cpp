#include "pieces/container.hpp"

#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include "pieces/cgroup.hpp"
#include "pieces/namespaces.hpp"
#include "pieces/network.hpp"
#include "pieces/parser.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

constexpr const char* DEFAULT_CONTAINER_PATH =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

std::string generate_container_id() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    uint64_t val = gen();
    std::ostringstream oss;
    oss << std::hex << std::setw(12) << std::setfill('0') << (val & 0xFFFFFFFFFFFFULL);
    return oss.str();
}

std::string utc_timestamp_iso() {
    std::time_t now = std::time(nullptr);
    std::tm tm_utc{};
    ::gmtime_r(&now, &tm_utc);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    return std::string(buf);
}

std::vector<std::string> coerce_cmd_list(const JsonValue* val) {
    if (!val) {
        return {};
    }
    if (val->is_array()) {
        std::vector<std::string> out;
        for (const auto& item : val->as_array()) {
            if (item.is_string()) {
                out.push_back(item.as_string());
            }
        }
        return out;
    }
    if (val->is_string()) {
        return split_shell_words(val->as_string());
    }
    return {};
}

void write_container_meta(const std::string& container_dir, const JsonObject& meta) {
    fs::create_directories(container_dir);
    fs::path meta_path = fs::path(container_dir) / "meta.json";
    std::ofstream out(meta_path);
    if (out) {
        out << JsonValue(meta).dump(2) << "\n";
    }
}

std::optional<std::string> find_container_dir(const std::string& identifier, const std::string& containers_dir) {
    std::error_code ec;
    if (!fs::is_directory(containers_dir, ec)) {
        return std::nullopt;
    }
    fs::path direct = fs::path(containers_dir) / identifier;
    if (fs::is_directory(direct, ec)) {
        return direct.string();
    }
    for (const auto& entry : fs::directory_iterator(containers_dir, ec)) {
        if (!entry.is_directory(ec)) {
            continue;
        }
        std::string dirname = entry.path().filename().string();
        if (dirname.rfind(identifier, 0) == 0) {
            return entry.path().string();
        }
        fs::path meta_path = entry.path() / "meta.json";
        if (!fs::is_regular_file(meta_path, ec)) {
            continue;
        }
        std::ifstream in(meta_path);
        if (!in) {
            continue;
        }
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        try {
            JsonValue parsed = JsonValue::parse(content);
            const JsonValue* name_val = parsed.find("name");
            if (name_val && name_val->is_string() && name_val->as_string() == identifier) {
                return entry.path().string();
            }
        } catch (const std::exception&) {
        }
    }
    return std::nullopt;
}

int waitstatus_to_exitcode(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

std::string join_args(const std::vector<std::string>& args) {
    std::string out;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i > 0) out += ' ';
        out += args[i];
    }
    return out;
}

}  // namespace

JsonObject load_image_metadata(const std::string& image_path) {
    fs::path meta_path = fs::path(image_path) / ".pieces_meta.json";
    std::error_code ec;
    if (!fs::is_regular_file(meta_path, ec)) {
        return {};
    }
    std::ifstream in(meta_path);
    if (!in) {
        return {};
    }
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    try {
        JsonValue parsed = JsonValue::parse(content);
        if (parsed.is_object()) {
            return parsed.as_object();
        }
    } catch (const std::exception&) {
    }
    return {};
}

std::vector<std::string> resolve_command(
    const std::vector<std::string>& cli_cmd,
    const JsonObject& metadata) {
    auto ep_it = metadata.find("entrypoint");
    auto cmd_it = metadata.find("cmd");
    std::vector<std::string> entrypoint = (ep_it != metadata.end()) ? coerce_cmd_list(&ep_it->second) : std::vector<std::string>{};
    std::vector<std::string> default_cmd = (cmd_it != metadata.end()) ? coerce_cmd_list(&cmd_it->second) : std::vector<std::string>{};

    if (!cli_cmd.empty()) {
        if (!entrypoint.empty()) {
            entrypoint.insert(entrypoint.end(), cli_cmd.begin(), cli_cmd.end());
            return entrypoint;
        }
        return cli_cmd;
    }
    if (!entrypoint.empty() && !default_cmd.empty()) {
        entrypoint.insert(entrypoint.end(), default_cmd.begin(), default_cmd.end());
        return entrypoint;
    }
    if (!entrypoint.empty()) {
        return entrypoint;
    }
    if (!default_cmd.empty()) {
        return default_cmd;
    }
    return {"/bin/sh"};
}

std::map<std::string, std::string> build_container_env(
    const JsonObject& metadata,
    const std::vector<std::string>& env_specs,
    const std::string& hostname) {
    const char* host_term = std::getenv("TERM");
    std::map<std::string, std::string> env = {
        {"PATH", DEFAULT_CONTAINER_PATH},
        {"HOME", "/root"},
        {"TERM", host_term ? host_term : "xterm"},
        {"HOSTNAME", hostname},
    };

    auto env_it = metadata.find("env");
    if (env_it != metadata.end() && env_it->second.is_object()) {
        for (const auto& [k, v] : env_it->second.as_object()) {
            if (v.is_string()) {
                env[k] = v.as_string();
            }
        }
    }

    for (const auto& spec : env_specs) {
        auto eq = spec.find('=');
        if (eq != std::string::npos) {
            std::string key = spec.substr(0, eq);
            std::string val = spec.substr(eq + 1);
            if (key.empty()) {
                throw std::invalid_argument("Invalid environment variable specification: '" + spec + "'");
            }
            env[key] = val;
        } else {
            if (spec.empty()) {
                throw std::invalid_argument("Environment variable name cannot be empty");
            }
            if (const char* host_val = std::getenv(spec.c_str())) {
                env[spec] = host_val;
            }
        }
    }
    return env;
}

std::vector<JsonObject> list_containers(bool show_all, const std::string& containers_dir) {
    std::vector<JsonObject> records;
    std::error_code ec;
    if (!fs::is_directory(containers_dir, ec)) {
        return records;
    }

    for (const auto& entry : fs::directory_iterator(containers_dir, ec)) {
        fs::path meta_path = entry.path() / "meta.json";
        if (!fs::is_regular_file(meta_path, ec)) {
            continue;
        }
        std::ifstream in(meta_path);
        if (!in) {
            continue;
        }
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        try {
            JsonValue parsed = JsonValue::parse(content);
            if (!parsed.is_object()) continue;
            const JsonValue* status = parsed.find("status");
            bool is_running = status && status->is_string() && status->as_string() == "running";
            if (!show_all && !is_running) {
                continue;
            }
            records.push_back(parsed.as_object());
        } catch (const std::exception&) {
        }
    }

    std::sort(records.begin(), records.end(), [](const JsonObject& a, const JsonObject& b) {
        auto it_a = a.find("created_at");
        auto it_b = b.find("created_at");
        std::string sa = (it_a != a.end() && it_a->second.is_string()) ? it_a->second.as_string() : "";
        std::string sb = (it_b != b.end() && it_b->second.is_string()) ? it_b->second.as_string() : "";
        return sa > sb;
    });
    return records;
}

std::string remove_container(const std::string& identifier, bool force, const std::string& containers_dir) {
    auto target_opt = find_container_dir(identifier, containers_dir);
    if (!target_opt.has_value()) {
        throw std::runtime_error("Container '" + identifier + "' not found");
    }
    const std::string& target = *target_opt;
    std::string method = "copy";

    fs::path meta_path = fs::path(target) / "meta.json";
    std::error_code ec;
    if (fs::is_regular_file(meta_path, ec)) {
        std::ifstream in(meta_path);
        if (in) {
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            try {
                JsonValue parsed = JsonValue::parse(content);
                const JsonValue* status = parsed.find("status");
                if (status && status->is_string() && status->as_string() == "running" && !force) {
                    throw std::runtime_error(
                        "Container '" + identifier + "' is marked running; stop it or pass --force.");
                }
                const JsonValue* meth = parsed.find("rootfs_method");
                if (meth && meth->is_string()) {
                    method = meth->as_string();
                }
            } catch (const std::runtime_error&) {
                throw;
            } catch (const std::exception&) {
            }
        }
    }

    cleanup_container_rootfs(target, method);
    fs::remove_all(target);
    return fs::path(target).filename().string();
}

int run_container(const ContainerRunConfig& config) {
    std::string image_path = resolve_image_path(config.image, config.image_dir);
    if (!fs::is_directory(image_path)) {
        std::cerr << "Error: Image '" << config.image << "' not found. Did you build it first?\n";
        return 1;
    }

    if (config.name.has_value()) {
        (void)validate_name(*config.name, "container");
        if (find_container_dir(*config.name, config.containers_dir).has_value()) {
            std::cerr << "Error: Container name '" << *config.name << "' is already in use.\n";
            return 1;
        }
    }

    std::string container_id = generate_container_id();
    std::string container_name = config.name.value_or(container_id);
    std::string hostname = config.hostname.value_or(container_name);
    std::string container_dir = (fs::path(config.containers_dir) / container_id).string();

    JsonObject metadata = load_image_metadata(image_path);
    std::vector<std::string> command = resolve_command(config.cmd_args, metadata);
    std::map<std::string, std::string> env_map = build_container_env(metadata, config.env_specs, hostname);

    std::string workdir = "/";
    if (config.workdir.has_value()) {
        workdir = *config.workdir;
    } else if (auto wd_it = metadata.find("workdir"); wd_it != metadata.end() && wd_it->second.is_string()) {
        workdir = wd_it->second.as_string();
    }

    std::vector<VolumeMount> volumes;
    volumes.reserve(config.volume_specs.size());
    for (const auto& vs : config.volume_specs) {
        volumes.push_back(parse_volume_spec(vs));
    }

    CgroupManager cgroup_mgr(container_id, config.memory_limit, config.cpu_limit, config.pids_limit);

    std::optional<ContainerNetwork> net_plan;
    if (config.network_mode == "bridge" && setup_host_network()) {
        net_plan = build_network_plan(container_id, config.containers_dir);
    }

    std::cout << "RUN: Starting container '" << container_name << "' (" << container_id
              << ") from '" << config.image << "'...\n" << std::flush;

    RootfsSetup rootfs = prepare_container_rootfs(image_path, container_dir, hostname);

    JsonObject meta_record;
    meta_record["id"] = container_id;
    meta_record["name"] = container_name;
    meta_record["image"] = config.image;
    meta_record["command"] = join_args(command);
    meta_record["status"] = "running";
    meta_record["ip"] = net_plan.has_value() ? net_plan->container_ip : "";
    meta_record["rootfs_method"] = rootfs.method;
    meta_record["created_at"] = utc_timestamp_iso();
    meta_record["exit_code"] = nullptr;
    write_container_meta(container_dir, meta_record);

    int ready_pipe[2]{-1, -1};
    int go_pipe[2]{-1, -1};
    if (::pipe(ready_pipe) != 0 || ::pipe(go_pipe) != 0) {
        if (ready_pipe[0] >= 0) { ::close(ready_pipe[0]); ::close(ready_pipe[1]); }
        cleanup_container_rootfs(container_dir, rootfs.method);
        throw std::system_error(errno, std::generic_category(), "pipe");
    }

    // Pre-build argv and envp before fork() to keep child async-signal-safe.
    std::vector<std::string> env_entries;
    env_entries.reserve(env_map.size());
    for (const auto& [k, v] : env_map) {
        env_entries.push_back(k + "=" + v);
    }

    int exit_code = 1;
    pid_t pid1 = ::fork();
    if (pid1 < 0) {
        ::close(ready_pipe[0]); ::close(ready_pipe[1]);
        ::close(go_pipe[0]); ::close(go_pipe[1]);
        cleanup_container_rootfs(container_dir, rootfs.method);
        throw std::system_error(errno, std::generic_category(), "fork");
    }

    if (pid1 == 0) {
        ::close(ready_pipe[0]);
        ::close(go_pipe[1]);
        try {
            int ns_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC;
            unshare_namespaces(ns_flags);

            pid_t pid2 = ::fork();
            if (pid2 < 0) {
                throw std::system_error(errno, std::generic_category(), "fork(pid2)");
            }

            if (pid2 == 0) {
                ::close(ready_pipe[1]);
                try {
                    char buf = 0;
                    [[maybe_unused]] ssize_t n = ::read(go_pipe[0], &buf, 1);
                    ::close(go_pipe[0]);

                    checked_sethostname(hostname);
                    setup_container_mounts(rootfs.rootfs_dir, volumes);
                    if (!workdir.empty() && workdir != "/") {
                        fs::create_directories(workdir);
                        if (::chdir(workdir.c_str()) != 0) {
                            throw std::system_error(errno, std::generic_category(), "chdir(" + workdir + ")");
                        }
                    }

                    std::vector<char*> argv_ptrs;
                    argv_ptrs.reserve(command.size() + 1);
                    for (auto& arg : command) {
                        argv_ptrs.push_back(arg.data());
                    }
                    argv_ptrs.push_back(nullptr);

                    std::vector<char*> env_ptrs;
                    env_ptrs.reserve(env_entries.size() + 1);
                    for (auto& e : env_entries) {
                        env_ptrs.push_back(e.data());
                    }
                    env_ptrs.push_back(nullptr);

                    ::execvpe(argv_ptrs[0], argv_ptrs.data(), env_ptrs.data());
                    int err = errno;
                    std::cerr << "CONTAINER ERROR: execvpe(" << command[0] << ") failed: "
                              << std::strerror(err) << "\n";
                    ::_exit(err == ENOENT ? 127 : 126);
                } catch (const std::exception& exc) {
                    std::cerr << "CONTAINER ERROR: " << exc.what() << "\n";
                    ::_exit(1);
                }
            } else {
                ::close(go_pipe[0]);
                std::string pid_msg = std::to_string(pid2) + "\n";
                [[maybe_unused]] ssize_t written = ::write(ready_pipe[1], pid_msg.data(), pid_msg.size());
                ::close(ready_pipe[1]);

                int status2 = 0;
                ::waitpid(pid2, &status2, 0);
                ::_exit(waitstatus_to_exitcode(status2));
            }
        } catch (const std::exception& exc) {
            std::cerr << "CHILD ERROR: " << exc.what() << "\n";
            ::close(ready_pipe[1]);
            ::close(go_pipe[0]);
            ::_exit(1);
        }
    }

    // Parent process
    ::close(ready_pipe[1]);
    ::close(go_pipe[0]);

    std::string raw_pid;
    char buf[64];
    while (true) {
        ssize_t n = ::read(ready_pipe[0], buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        raw_pid.append(buf, static_cast<size_t>(n));
    }
    ::close(ready_pipe[0]);

    while (!raw_pid.empty() && (raw_pid.back() == '\n' || raw_pid.back() == '\r')) {
        raw_pid.pop_back();
    }
    if (!raw_pid.empty() && std::all_of(raw_pid.begin(), raw_pid.end(), [](unsigned char c) { return std::isdigit(c); })) {
        int grandchild_pid = std::stoi(raw_pid);
        cgroup_mgr.setup(grandchild_pid);
        if (net_plan.has_value()) {
            if (!setup_container_network(grandchild_pid, *net_plan)) {
                meta_record["ip"] = "";
                write_container_meta(container_dir, meta_record);
            }
        }
    }

    [[maybe_unused]] ssize_t gw = ::write(go_pipe[1], "1", 1);
    ::close(go_pipe[1]);

    int status1 = 0;
    if (::waitpid(pid1, &status1, 0) >= 0) {
        exit_code = waitstatus_to_exitcode(status1);
    }

    if (net_plan.has_value()) {
        cleanup_container_network(net_plan->host_veth);
    }
    cgroup_mgr.cleanup();
    cleanup_container_rootfs(container_dir, rootfs.method);

    if (config.auto_remove) {
        std::error_code ec;
        fs::remove_all(container_dir, ec);
    } else {
        meta_record["status"] = "exited";
        meta_record["exit_code"] = static_cast<int64_t>(exit_code);
        write_container_meta(container_dir, meta_record);
    }

    std::cout << "RUN: Container '" << container_name << "' exited with code " << exit_code << ".\n";
    return exit_code;
}

}  // namespace pieces

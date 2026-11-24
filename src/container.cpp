#include "pieces/container.hpp"

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
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
#include <thread>

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

std::optional<JsonObject> read_meta_object(const fs::path& meta_path) {
    std::error_code ec;
    if (!fs::is_regular_file(meta_path, ec)) {
        return std::nullopt;
    }
    std::ifstream in(meta_path);
    if (!in) {
        return std::nullopt;
    }
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    try {
        JsonValue parsed = JsonValue::parse(content);
        if (parsed.is_object()) {
            return parsed.as_object();
        }
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

bool is_pid_alive(int pid) {
    if (pid <= 0) {
        return false;
    }
    if (::kill(pid, 0) == 0) {
        return true;
    }
    return errno == EPERM;
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
        auto meta = read_meta_object(entry.path() / "meta.json");
        if (meta.has_value()) {
            auto it = meta->find("name");
            if (it != meta->end() && it->second.is_string() && it->second.as_string() == identifier) {
                return entry.path().string();
            }
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

int execute_container_supervisor(
    const ContainerRunConfig& config,
    const std::string& container_id,
    const std::string& container_name,
    const std::string& hostname,
    const std::string& container_dir,
    const RootfsSetup& rootfs,
    const std::vector<std::string>& command,
    const std::map<std::string, std::string>& env_map,
    const std::string& workdir,
    const std::vector<VolumeMount>& volumes,
    const std::optional<ContainerNetwork>& net_plan,
    CgroupManager& cgroup_mgr,
    bool rootless,
    JsonObject& meta_record,
    int notify_parent_fd) {
    uid_t host_uid = ::getuid();
    gid_t host_gid = ::getgid();

    int log_fd = -1;
    int null_fd = -1;
    if (config.detach) {
        fs::path log_path = fs::path(container_dir) / "container.log";
        log_fd = ::open(log_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        null_fd = ::open("/dev/null", O_RDONLY);
    }

    int ready_pipe[2]{-1, -1};
    int go_pipe[2]{-1, -1};
    if (::pipe(ready_pipe) != 0 || ::pipe(go_pipe) != 0) {
        if (ready_pipe[0] >= 0) { ::close(ready_pipe[0]); ::close(ready_pipe[1]); }
        if (log_fd >= 0) ::close(log_fd);
        if (null_fd >= 0) ::close(null_fd);
        if (notify_parent_fd >= 0) {
            [[maybe_unused]] ssize_t w = ::write(notify_parent_fd, "ERR\n", 4);
            ::close(notify_parent_fd);
        }
        return 1;
    }

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
        if (log_fd >= 0) ::close(log_fd);
        if (null_fd >= 0) ::close(null_fd);
        if (notify_parent_fd >= 0) {
            [[maybe_unused]] ssize_t w = ::write(notify_parent_fd, "ERR\n", 4);
            ::close(notify_parent_fd);
        }
        return 1;
    }

    if (pid1 == 0) {
        ::close(ready_pipe[0]);
        ::close(go_pipe[1]);
        if (notify_parent_fd >= 0) {
            ::close(notify_parent_fd);
        }
        try {
            int ns_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC;
            if (rootless) {
                ns_flags |= CLONE_NEWUSER;
            }
            unshare_namespaces(ns_flags);
            if (rootless) {
                write_user_namespace_maps("/proc/self", host_uid, host_gid);
            }

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

                    if (log_fd >= 0) {
                        ::dup2(log_fd, STDOUT_FILENO);
                        ::dup2(log_fd, STDERR_FILENO);
                        ::close(log_fd);
                    }
                    if (null_fd >= 0) {
                        ::dup2(null_fd, STDIN_FILENO);
                        ::close(null_fd);
                    }

                    checked_sethostname(hostname);
                    setup_container_mounts(rootfs.rootfs_dir, volumes, rootless);
                    if (!workdir.empty() && workdir != "/") {
                        fs::create_directories(workdir);
                        if (::chdir(workdir.c_str()) != 0) {
                            throw std::system_error(errno, std::generic_category(), "chdir(" + workdir + ")");
                        }
                    }

                    std::vector<char*> argv_ptrs;
                    argv_ptrs.reserve(command.size() + 1);
                    for (auto& arg : const_cast<std::vector<std::string>&>(command)) {
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
                if (log_fd >= 0) ::close(log_fd);
                if (null_fd >= 0) ::close(null_fd);
                std::string pid_msg = std::to_string(pid2) + "\n";
                [[maybe_unused]] ssize_t written = ::write(ready_pipe[1], pid_msg.data(), pid_msg.size());
                ::close(ready_pipe[1]);

                int status2 = 0;
                ::waitpid(pid2, &status2, 0);
                ::_exit(waitstatus_to_exitcode(status2));
            }
        } catch (const std::exception& exc) {
            std::cerr << "CHILD ERROR: " << exc.what() << "\n";
            if (log_fd >= 0) ::close(log_fd);
            if (null_fd >= 0) ::close(null_fd);
            ::close(ready_pipe[1]);
            ::close(go_pipe[0]);
            ::_exit(1);
        }
    }

    // Supervisor (or parent in foreground mode)
    ::close(ready_pipe[1]);
    ::close(go_pipe[0]);
    if (log_fd >= 0) ::close(log_fd);
    if (null_fd >= 0) ::close(null_fd);

    std::string raw_pid;
    char buf[64];
    while (true) {
        ssize_t n = ::read(ready_pipe[0], buf, sizeof(buf));
        if (n <= 0) break;
        raw_pid.append(buf, static_cast<size_t>(n));
    }
    ::close(ready_pipe[0]);

    while (!raw_pid.empty() && (raw_pid.back() == '\n' || raw_pid.back() == '\r')) {
        raw_pid.pop_back();
    }

    int grandchild_pid = 0;
    if (!raw_pid.empty() && std::all_of(raw_pid.begin(), raw_pid.end(), [](unsigned char c) { return std::isdigit(c); })) {
        grandchild_pid = std::stoi(raw_pid);
        cgroup_mgr.setup(grandchild_pid);
        if (net_plan.has_value()) {
            if (!setup_container_network(grandchild_pid, *net_plan)) {
                meta_record["ip"] = "";
                meta_record["ports"] = JsonArray{};
            }
        }
        meta_record["pid"] = static_cast<int64_t>(grandchild_pid);
        write_container_meta(container_dir, meta_record);
    }

    [[maybe_unused]] ssize_t gw = ::write(go_pipe[1], "1", 1);
    ::close(go_pipe[1]);

    if (notify_parent_fd >= 0) {
        std::string msg = (grandchild_pid > 0) ? ("OK:" + container_id + "\n") : "ERR\n";
        [[maybe_unused]] ssize_t nw = ::write(notify_parent_fd, msg.data(), msg.size());
        ::close(notify_parent_fd);
    }

    int status1 = 0;
    if (::waitpid(pid1, &status1, 0) >= 0) {
        exit_code = waitstatus_to_exitcode(status1);
    }

    if (net_plan.has_value()) {
        cleanup_port_forwarding(*net_plan);
        cleanup_container_network(net_plan->host_veth);
    }
    cgroup_mgr.cleanup();
    cleanup_container_rootfs(container_dir, rootfs.method);

    if (config.auto_remove) {
        std::error_code ec;
        fs::remove_all(container_dir, ec);
    } else {
        meta_record["status"] = "exited";
        meta_record["pid"] = static_cast<int64_t>(0);
        meta_record["exit_code"] = static_cast<int64_t>(exit_code);
        write_container_meta(container_dir, meta_record);
    }

    if (!config.detach) {
        std::cout << "RUN: Container '" << container_name << "' exited with code " << exit_code << ".\n";
    }
    return exit_code;
}

}  // namespace

JsonObject load_image_metadata(const std::string& image_path) {
    auto obj = read_meta_object(fs::path(image_path) / ".pieces_meta.json");
    return obj.value_or(JsonObject{});
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
        auto obj_opt = read_meta_object(meta_path);
        if (!obj_opt.has_value()) {
            continue;
        }
        JsonObject obj = std::move(*obj_opt);
        auto status_it = obj.find("status");
        bool is_running = (status_it != obj.end() && status_it->second.is_string() &&
                           status_it->second.as_string() == "running");
        if (is_running) {
            auto pid_it = obj.find("pid");
            if (pid_it != obj.end() && pid_it->second.is_int() && pid_it->second.as_int() > 0) {
                if (!is_pid_alive(static_cast<int>(pid_it->second.as_int()))) {
                    obj["status"] = "exited";
                    obj["pid"] = static_cast<int64_t>(0);
                    is_running = false;
                }
            }
        }
        if (!show_all && !is_running) {
            continue;
        }
        records.push_back(std::move(obj));
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

    if (auto meta = read_meta_object(fs::path(target) / "meta.json"); meta.has_value()) {
        auto status_it = meta->find("status");
        auto pid_it = meta->find("pid");
        bool marked_running = status_it != meta->end() && status_it->second.is_string() &&
                              status_it->second.as_string() == "running";
        bool alive = (pid_it != meta->end() && pid_it->second.is_int() &&
                      is_pid_alive(static_cast<int>(pid_it->second.as_int())));
        if (marked_running && alive && !force) {
            throw std::runtime_error(
                "Container '" + identifier + "' is running; stop it or pass --force.");
        }
        if (auto meth = meta->find("rootfs_method"); meth != meta->end() && meth->second.is_string()) {
            method = meth->second.as_string();
        }
    }

    cleanup_container_rootfs(target, method);
    fs::remove_all(target);
    return fs::path(target).filename().string();
}

int stop_container(const std::string& identifier, int timeout_sec, const std::string& containers_dir) {
    auto target_opt = find_container_dir(identifier, containers_dir);
    if (!target_opt.has_value()) {
        throw std::runtime_error("Container '" + identifier + "' not found");
    }
    auto meta = read_meta_object(fs::path(*target_opt) / "meta.json");
    if (!meta.has_value()) {
        throw std::runtime_error("Container metadata missing for '" + identifier + "'");
    }
    auto pid_it = meta->find("pid");
    if (pid_it == meta->end() || !pid_it->second.is_int() || pid_it->second.as_int() <= 0) {
        std::cout << "Container '" << identifier << "' is not running.\n";
        return 0;
    }
    int pid = static_cast<int>(pid_it->second.as_int());
    if (!is_pid_alive(pid)) {
        (*meta)["status"] = "exited";
        (*meta)["pid"] = static_cast<int64_t>(0);
        write_container_meta(*target_opt, *meta);
        std::cout << "Container '" << identifier << "' already exited.\n";
        return 0;
    }

    if (::kill(pid, SIGTERM) != 0 && errno != ESRCH) {
        throw std::system_error(errno, std::generic_category(), "kill(SIGTERM)");
    }

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(std::max(0, timeout_sec));
    while (std::chrono::steady_clock::now() < deadline) {
        if (!is_pid_alive(pid)) {
            std::cout << "Stopped container " << identifier << "\n";
            return 0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (is_pid_alive(pid)) {
        ::kill(pid, SIGKILL);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "Stopped container " << identifier << "\n";
    return 0;
}

int show_container_logs(
    const std::string& identifier,
    bool follow,
    int tail_lines,
    const std::string& containers_dir) {
    auto target_opt = find_container_dir(identifier, containers_dir);
    if (!target_opt.has_value()) {
        throw std::runtime_error("Container '" + identifier + "' not found");
    }
    fs::path log_path = fs::path(*target_opt) / "container.log";
    std::error_code ec;
    if (!fs::is_regular_file(log_path, ec)) {
        if (!follow) {
            return 0;
        }
    }

    std::streamoff offset = 0;
    if (fs::is_regular_file(log_path, ec)) {
        std::ifstream in(log_path, std::ios::binary);
        if (tail_lines >= 0) {
            std::vector<std::string> lines;
            std::string line;
            while (std::getline(in, line)) {
                lines.push_back(line);
            }
            size_t start = (lines.size() > static_cast<size_t>(tail_lines))
                               ? (lines.size() - static_cast<size_t>(tail_lines))
                               : 0;
            for (size_t i = start; i < lines.size(); ++i) {
                std::cout << lines[i] << "\n";
            }
            std::cout << std::flush;
        } else {
            std::cout << in.rdbuf() << std::flush;
        }
        offset = static_cast<std::streamoff>(fs::file_size(log_path, ec));
    }

    while (follow) {
        if (fs::is_regular_file(log_path, ec)) {
            auto cur_size = static_cast<std::streamoff>(fs::file_size(log_path, ec));
            if (cur_size > offset) {
                std::ifstream in(log_path, std::ios::binary);
                in.seekg(offset);
                std::cout << in.rdbuf() << std::flush;
                offset = cur_size;
            }
        }
        auto meta = read_meta_object(fs::path(*target_opt) / "meta.json");
        bool still_running = false;
        if (meta.has_value()) {
            auto st = meta->find("status");
            auto p = meta->find("pid");
            if (st != meta->end() && st->second.is_string() && st->second.as_string() == "running" &&
                p != meta->end() && p->second.is_int() && is_pid_alive(static_cast<int>(p->second.as_int()))) {
                still_running = true;
            }
        }
        if (!still_running) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return 0;
}

int exec_in_container(
    const std::string& identifier,
    const std::vector<std::string>& cmd_args,
    const std::vector<std::string>& env_specs,
    const std::optional<std::string>& workdir,
    const std::string& containers_dir) {
    if (cmd_args.empty()) {
        throw std::invalid_argument("exec requires a command to run inside the container");
    }
    auto target_opt = find_container_dir(identifier, containers_dir);
    if (!target_opt.has_value()) {
        throw std::runtime_error("Container '" + identifier + "' not found");
    }
    auto meta = read_meta_object(fs::path(*target_opt) / "meta.json");
    if (!meta.has_value()) {
        throw std::runtime_error("Container metadata missing for '" + identifier + "'");
    }
    auto pid_it = meta->find("pid");
    if (pid_it == meta->end() || !pid_it->second.is_int() || pid_it->second.as_int() <= 0) {
        throw std::runtime_error("Container '" + identifier + "' is not running");
    }
    int target_pid = static_cast<int>(pid_it->second.as_int());
    if (!is_pid_alive(target_pid)) {
        throw std::runtime_error("Container '" + identifier + "' process is not alive");
    }

    std::string hostname = identifier;
    if (auto hn = meta->find("name"); hn != meta->end() && hn->second.is_string()) {
        hostname = hn->second.as_string();
    }
    auto env_map = build_container_env(*meta, env_specs, hostname);
    std::vector<std::string> env_entries;
    env_entries.reserve(env_map.size());
    for (const auto& [k, v] : env_map) {
        env_entries.push_back(k + "=" + v);
    }

    enter_container_namespaces(target_pid);

    pid_t child = ::fork();
    if (child < 0) {
        throw std::system_error(errno, std::generic_category(), "fork(exec)");
    }
    if (child == 0) {
        if (workdir.has_value() && !workdir->empty()) {
            if (::chdir(workdir->c_str()) != 0) {
                std::cerr << "EXEC ERROR: chdir(" << *workdir << ") failed: " << std::strerror(errno) << "\n";
                ::_exit(1);
            }
        }
        std::vector<char*> argv_ptrs;
        argv_ptrs.reserve(cmd_args.size() + 1);
        for (auto& a : const_cast<std::vector<std::string>&>(cmd_args)) {
            argv_ptrs.push_back(a.data());
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
        std::cerr << "EXEC ERROR: execvpe(" << cmd_args[0] << ") failed: " << std::strerror(err) << "\n";
        ::_exit(err == ENOENT ? 127 : 126);
    }

    int status = 0;
    if (::waitpid(child, &status, 0) < 0) {
        return 1;
    }
    return waitstatus_to_exitcode(status);
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

    std::vector<PortMapping> ports;
    ports.reserve(config.port_specs.size());
    for (const auto& ps : config.port_specs) {
        ports.push_back(parse_port_mapping(ps));
    }

    bool rootless = config.rootless || (::geteuid() != 0);
    CgroupManager cgroup_mgr(container_id, config.memory_limit, config.cpu_limit, config.pids_limit);

    std::optional<ContainerNetwork> net_plan;
    if (config.network_mode == "bridge") {
        if (rootless) {
            if (!ports.empty()) {
                std::cerr << "NETWORK: Warning: -p port forwarding requires root/CAP_NET_ADMIN; skipped in rootless mode.\n";
            }
        } else if (setup_host_network()) {
            net_plan = build_network_plan(container_id, config.containers_dir, ports);
        }
    }

    if (!config.detach) {
        std::cout << "RUN: Starting container '" << container_name << "' (" << container_id
                  << ") from '" << config.image << "'" << (rootless ? " [rootless]" : "") << "...\n"
                  << std::flush;
    }

    RootfsSetup rootfs = prepare_container_rootfs(image_path, container_dir, hostname);

    JsonArray port_arr;
    if (net_plan.has_value()) {
        for (const auto& pm : net_plan->ports) {
            port_arr.emplace_back(format_port_mapping(pm));
        }
    }

    JsonObject meta_record;
    meta_record["id"] = container_id;
    meta_record["name"] = container_name;
    meta_record["image"] = config.image;
    meta_record["command"] = join_args(command);
    meta_record["status"] = "running";
    meta_record["pid"] = static_cast<int64_t>(0);
    meta_record["ip"] = net_plan.has_value() ? net_plan->container_ip : "";
    meta_record["ports"] = std::move(port_arr);
    meta_record["rootless"] = rootless;
    meta_record["rootfs_method"] = rootfs.method;
    meta_record["created_at"] = utc_timestamp_iso();
    meta_record["exit_code"] = nullptr;
    write_container_meta(container_dir, meta_record);

    if (!config.detach) {
        return execute_container_supervisor(
            config, container_id, container_name, hostname, container_dir, rootfs,
            command, env_map, workdir, volumes, net_plan, cgroup_mgr, rootless, meta_record, -1);
    }

    // Detached mode: fork background supervisor and wait until container child is launched
    int sup_pipe[2]{-1, -1};
    if (::pipe(sup_pipe) != 0) {
        cleanup_container_rootfs(container_dir, rootfs.method);
        throw std::system_error(errno, std::generic_category(), "pipe(detach)");
    }

    pid_t sup_pid = ::fork();
    if (sup_pid < 0) {
        ::close(sup_pipe[0]); ::close(sup_pipe[1]);
        cleanup_container_rootfs(container_dir, rootfs.method);
        throw std::system_error(errno, std::generic_category(), "fork(detach)");
    }

    if (sup_pid == 0) {
        ::close(sup_pipe[0]);
        ::setsid();
        int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            ::close(devnull);
        }
        int rc = execute_container_supervisor(
            config, container_id, container_name, hostname, container_dir, rootfs,
            command, env_map, workdir, volumes, net_plan, cgroup_mgr, rootless, meta_record, sup_pipe[1]);
        ::_exit(rc);
    }

    ::close(sup_pipe[1]);
    std::string reply;
    char buf[64];
    while (true) {
        ssize_t n = ::read(sup_pipe[0], buf, sizeof(buf));
        if (n <= 0) break;
        reply.append(buf, static_cast<size_t>(n));
    }
    ::close(sup_pipe[0]);

    if (reply.rfind("OK:", 0) == 0) {
        std::cout << container_id << "\n";
        return 0;
    }
    std::cerr << "RUN: Detached container failed to start.\n";
    return 1;
}

}  // namespace pieces

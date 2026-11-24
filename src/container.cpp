#include "pieces/container.hpp"

#include <fcntl.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pty.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
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
#include "pieces/oci_runtime.hpp"
#include "pieces/parser.hpp"
#include "pieces/security.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

constexpr const char* DEFAULT_CONTAINER_PATH =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

volatile sig_atomic_t g_winch_received = 0;
volatile sig_atomic_t g_forward_signal = 0;

void handle_sigwinch(int) {
    g_winch_received = 1;
}

void handle_forward_signal(int sig) {
    g_forward_signal = sig;
}

struct TerminalRawGuard {
    bool active{false};
    struct termios orig{};
    TerminalRawGuard() {
        if (::isatty(STDIN_FILENO) && ::tcgetattr(STDIN_FILENO, &orig) == 0) {
            struct termios raw = orig;
            ::cfmakeraw(&raw);
            if (::tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) active = true;
        }
    }
    ~TerminalRawGuard() {
        if (active) ::tcsetattr(STDIN_FILENO, TCSANOW, &orig);
    }
    TerminalRawGuard(const TerminalRawGuard&) = delete;
    TerminalRawGuard& operator=(const TerminalRawGuard&) = delete;
};

void copy_winsize(int src_fd, int dst_fd) {
    struct winsize ws{};
    if (::ioctl(src_fd, TIOCGWINSZ, &ws) == 0) {
        ::ioctl(dst_fd, TIOCSWINSZ, &ws);
    }
}

void relay_pty_session(int master_fd, int child_pid_for_signals) {
    TerminalRawGuard raw_guard;
    copy_winsize(STDIN_FILENO, master_fd);

    struct sigaction sa_winch{}, old_winch{};
    sa_winch.sa_handler = handle_sigwinch;
    sigemptyset(&sa_winch.sa_mask);
    ::sigaction(SIGWINCH, &sa_winch, &old_winch);

    struct sigaction sa_fwd{}, old_int{}, old_term{};
    sa_fwd.sa_handler = handle_forward_signal;
    sigemptyset(&sa_fwd.sa_mask);
    ::sigaction(SIGINT, &sa_fwd, &old_int);
    ::sigaction(SIGTERM, &sa_fwd, &old_term);

    bool stdin_open = true;
    char buf[4096];
    while (true) {
        if (g_winch_received) {
            g_winch_received = 0;
            copy_winsize(STDIN_FILENO, master_fd);
        }
        if (g_forward_signal && child_pid_for_signals > 0) {
            int sig = static_cast<int>(g_forward_signal);
            g_forward_signal = 0;
            ::kill(child_pid_for_signals, sig);
        }

        struct pollfd fds[2];
        nfds_t nfds = 0;
        fds[nfds++] = {master_fd, POLLIN, 0};
        if (stdin_open) fds[nfds++] = {STDIN_FILENO, POLLIN, 0};

        int prc = ::poll(fds, nfds, 100);
        if (prc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (prc == 0) continue;

        if (fds[0].revents & POLLIN) {
            ssize_t n = ::read(master_fd, buf, sizeof(buf));
            if (n <= 0) break;
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = ::write(STDOUT_FILENO, buf + off, static_cast<size_t>(n - off));
                if (w <= 0) break;
                off += w;
            }
        } else if (fds[0].revents & (POLLHUP | POLLERR)) {
            break;
        }

        if (stdin_open && nfds > 1) {
            if (fds[1].revents & POLLIN) {
                ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
                if (n <= 0) {
                    stdin_open = false;
                } else {
                    ssize_t off = 0;
                    while (off < n) {
                        ssize_t w = ::write(master_fd, buf + off, static_cast<size_t>(n - off));
                        if (w <= 0) break;
                        off += w;
                    }
                }
            } else if (fds[1].revents & (POLLHUP | POLLERR)) {
                stdin_open = false;
            }
        }
    }

    ::sigaction(SIGWINCH, &old_winch, nullptr);
    ::sigaction(SIGINT, &old_int, nullptr);
    ::sigaction(SIGTERM, &old_term, nullptr);
}

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
    if (!val) return {};
    if (val->is_array()) {
        std::vector<std::string> out;
        for (const auto& item : val->as_array()) {
            if (item.is_string()) out.push_back(item.as_string());
        }
        return out;
    }
    if (val->is_string()) return split_shell_words(val->as_string());
    return {};
}

void write_container_meta(const std::string& container_dir, const JsonObject& meta) {
    fs::create_directories(container_dir);
    fs::path meta_path = fs::path(container_dir) / "meta.json";
    fs::path tmp = meta_path;
    tmp += ".tmp." + std::to_string(::getpid());
    {
        std::ofstream out(tmp);
        if (!out) return;
        out << JsonValue(meta).dump(2) << "\n";
    }
    std::error_code ec;
    fs::rename(tmp, meta_path, ec);
}

std::optional<JsonObject> read_meta_object(const fs::path& meta_path) {
    std::error_code ec;
    if (!fs::is_regular_file(meta_path, ec)) return std::nullopt;
    std::ifstream in(meta_path);
    if (!in) return std::nullopt;
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    try {
        JsonValue parsed = JsonValue::parse(content);
        if (parsed.is_object()) return parsed.as_object();
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

bool is_pid_alive(int pid) {
    if (pid <= 0) return false;
    if (::kill(pid, 0) == 0) return true;
    return errno == EPERM;
}

std::optional<std::string> find_container_dir(const std::string& identifier, const std::string& containers_dir) {
    std::error_code ec;
    if (!fs::is_directory(containers_dir, ec)) return std::nullopt;
    fs::path direct = fs::path(containers_dir) / identifier;
    if (fs::is_directory(direct, ec)) return direct.string();
    for (const auto& entry : fs::directory_iterator(containers_dir, ec)) {
        if (!entry.is_directory(ec)) continue;
        std::string dirname = entry.path().filename().string();
        if (dirname.rfind(identifier, 0) == 0) return entry.path().string();
        if (auto meta = read_meta_object(entry.path() / "meta.json"); meta.has_value()) {
            auto it = meta->find("name");
            if (it != meta->end() && it->second.is_string() && it->second.as_string() == identifier) {
                return entry.path().string();
            }
        }
    }
    return std::nullopt;
}

int waitstatus_to_exitcode(int status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
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

void reconcile_dead_container_resources(
    const fs::path& cdir,
    JsonObject& obj,
    const std::string& containers_dir) {
    std::string cid = cdir.filename().string();
    std::string method = "copy";
    if (auto m = obj.find("rootfs_method"); m != obj.end() && m->second.is_string()) {
        method = m->second.as_string();
    }

    ContainerNetwork orphan_plan;
    if (auto hv = obj.find("host_veth"); hv != obj.end() && hv->second.is_string()) {
        orphan_plan.host_veth = hv->second.as_string();
    }
    if (auto ip = obj.find("ip"); ip != obj.end() && ip->second.is_string()) {
        orphan_plan.container_ip = ip->second.as_string();
    }
    if (auto ps = obj.find("ports"); ps != obj.end() && ps->second.is_array()) {
        for (const auto& p : ps->second.as_array()) {
            if (!p.is_string()) continue;
            std::string s = p.as_string();
            auto arrow = s.find("->");
            if (arrow != std::string::npos) {
                try {
                    orphan_plan.ports.push_back(parse_port_mapping(s.substr(0, arrow) + ":" + s.substr(arrow + 2)));
                } catch (const std::exception&) {
                }
            }
        }
    }
    std::string net_name = "bridge";
    if (auto nn = obj.find("network"); nn != obj.end() && nn->second.is_string() && !nn->second.as_string().empty()) {
        net_name = nn->second.as_string();
    }
    orphan_plan.bridge_name = DEFAULT_BRIDGE;

    if (!orphan_plan.ports.empty() && !orphan_plan.container_ip.empty()) {
        cleanup_port_forwarding(orphan_plan);
    }
    if (!orphan_plan.host_veth.empty()) cleanup_container_network(orphan_plan.host_veth);
    release_container_ip(containers_dir, cid, net_name);
    CgroupManager cg(cid);
    cg.cleanup();
    cleanup_container_rootfs(cdir.string(), method);

    obj["status"] = "exited";
    obj["pid"] = static_cast<int64_t>(0);
    write_container_meta(cdir.string(), obj);
}

void drain_fd_to_rotating_log(int pipe_fd, RotatingLogWriter& writer) {
    char buf[4096];
    while (true) {
        ssize_t n = ::read(pipe_fd, buf, sizeof(buf));
        if (n > 0) writer.write(buf, static_cast<size_t>(n));
        else if (n == 0) break;
        else if (errno != EINTR) break;
    }
}

struct TimingEntry {
    std::string phase;
    double delta_ms{0.0};
    double total_ms{0.0};
};

class StartupProfiler {
public:
    explicit StartupProfiler(bool enabled)
        : enabled_(enabled),
          start_(std::chrono::steady_clock::now()),
          last_(start_) {}

    void mark(const std::string& phase) {
        if (!enabled_) return;
        auto now = std::chrono::steady_clock::now();
        double delta = std::chrono::duration<double, std::milli>(now - last_).count();
        double total = std::chrono::duration<double, std::milli>(now - start_).count();
        last_ = now;
        entries_.push_back({phase, delta, total});
    }

    void print_report(std::ostream& out = std::cerr) const {
        if (!enabled_ || entries_.empty()) return;
        out << "\nTIMING: Startup phase breakdown:\n";
        for (const auto& e : entries_) {
            out << "  " << std::left << std::setw(32) << e.phase
                << " +" << std::fixed << std::setprecision(2) << std::setw(8) << e.delta_ms << " ms"
                << " (total " << std::setw(8) << e.total_ms << " ms)\n";
        }
    }

private:
    bool enabled_;
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point last_;
    std::vector<TimingEntry> entries_;
};

int run_single_container_attempt(
    const ContainerRunConfig& config,
    const std::string& container_id,
    const std::string& hostname,
    const std::string& image_path,
    const std::string& container_dir,
    const RootfsSetup& rootfs,
    const std::vector<std::string>& command,
    const std::map<std::string, std::string>& env_map,
    const std::string& workdir,
    const std::vector<VolumeMount>& volumes,
    const std::vector<TmpfsMount>& tmpfs_mounts,
    const std::vector<PortMapping>& rootless_ports,
    const std::set<cap_value_t>& target_caps,
    const std::optional<SeccompProgram>& prebuilt_seccomp,
    const SecurityOptions& sec_opts,
    const std::optional<UserSpec>& user_spec,
    const std::optional<ContainerNetwork>& net_plan,
    CgroupManager& cgroup_mgr,
    bool use_userns,
    JsonObject& meta_record,
    int& notify_parent_fd,
    StartupProfiler& profiler) {
    uid_t host_uid = ::getuid();
    gid_t host_gid = ::getgid();

    int pty_master = -1;
    int pty_slave = -1;
    bool use_pty = !config.detach && config.allocate_tty && ::isatty(STDIN_FILENO);
    if (use_pty) {
        if (::openpty(&pty_master, &pty_slave, nullptr, nullptr, nullptr) != 0) {
            use_pty = false;
            pty_master = -1;
            pty_slave = -1;
        }
    }

    int log_pipe[2]{-1, -1};
    int null_fd = -1;
    if (config.detach) {
        if (::pipe(log_pipe) != 0) return 1;
        null_fd = ::open("/dev/null", O_RDONLY);
    }

    int ready_pipe[2]{-1, -1};
    int userns_done_pipe[2]{-1, -1};
    int go_pipe[2]{-1, -1};
    if (::pipe(ready_pipe) != 0 || ::pipe(go_pipe) != 0 ||
        (use_userns && ::pipe(userns_done_pipe) != 0)) {
        if (pty_master >= 0) { ::close(pty_master); ::close(pty_slave); }
        if (log_pipe[0] >= 0) { ::close(log_pipe[0]); ::close(log_pipe[1]); }
        if (null_fd >= 0) ::close(null_fd);
        if (ready_pipe[0] >= 0) { ::close(ready_pipe[0]); ::close(ready_pipe[1]); }
        if (go_pipe[0] >= 0) { ::close(go_pipe[0]); ::close(go_pipe[1]); }
        return 1;
    }

    std::vector<std::string> env_entries;
    env_entries.reserve(env_map.size());
    for (const auto& [k, v] : env_map) env_entries.push_back(k + "=" + v);

    pid_t pid1 = ::fork();
    if (pid1 < 0) {
        if (pty_master >= 0) { ::close(pty_master); ::close(pty_slave); }
        if (log_pipe[0] >= 0) { ::close(log_pipe[0]); ::close(log_pipe[1]); }
        if (null_fd >= 0) ::close(null_fd);
        ::close(ready_pipe[0]); ::close(ready_pipe[1]);
        if (use_userns) { ::close(userns_done_pipe[0]); ::close(userns_done_pipe[1]); }
        ::close(go_pipe[0]); ::close(go_pipe[1]);
        return 1;
    }

    if (pid1 == 0) {
        ::close(ready_pipe[0]);
        if (use_userns) ::close(userns_done_pipe[1]);
        ::close(go_pipe[1]);
        if (pty_master >= 0) ::close(pty_master);
        if (log_pipe[0] >= 0) ::close(log_pipe[0]);
        if (notify_parent_fd >= 0) ::close(notify_parent_fd);

        try {
            int ns_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC;
            if (config.network_mode != "host") ns_flags |= CLONE_NEWNET;
            if (use_userns) ns_flags |= CLONE_NEWUSER;
            unshare_namespaces(ns_flags);

            if (use_userns) {
                std::string p1_msg = std::to_string(::getpid()) + "\n";
                [[maybe_unused]] ssize_t pw = ::write(ready_pipe[1], p1_msg.data(), p1_msg.size());
                char ubuf = 0;
                [[maybe_unused]] ssize_t ur = ::read(userns_done_pipe[0], &ubuf, 1);
                ::close(userns_done_pipe[0]);
            }

            pid_t pid2 = ::fork();
            if (pid2 < 0) throw std::system_error(errno, std::generic_category(), "fork(pid2)");

            if (pid2 == 0) {
                ::close(ready_pipe[1]);
                try {
                    char buf = 0;
                    [[maybe_unused]] ssize_t n = ::read(go_pipe[0], &buf, 1);
                    ::close(go_pipe[0]);

                    if (pty_slave >= 0) {
                        ::setsid();
                        ::ioctl(pty_slave, TIOCSCTTY, 0);
                        ::dup2(pty_slave, STDIN_FILENO);
                        ::dup2(pty_slave, STDOUT_FILENO);
                        ::dup2(pty_slave, STDERR_FILENO);
                        ::close(pty_slave);
                    } else if (log_pipe[1] >= 0) {
                        ::dup2(log_pipe[1], STDOUT_FILENO);
                        ::dup2(log_pipe[1], STDERR_FILENO);
                        ::close(log_pipe[1]);
                        if (null_fd >= 0) {
                            ::dup2(null_fd, STDIN_FILENO);
                            ::close(null_fd);
                        }
                    }

                    checked_sethostname(hostname);
                    if (net_plan.has_value()) {
                        configure_container_netns_netlink(*net_plan);
                    }
                    std::optional<OverlayRootfsSpec> overlay_spec;
                    if (rootfs.method == "in-ns-overlay") {
                        overlay_spec = OverlayRootfsSpec{
                            image_path, rootfs.upper_dir, rootfs.work_dir, config.full_copy};
                    }
                    setup_container_mounts(
                        rootfs.rootfs_dir,
                        volumes,
                        use_userns,
                        !config.privileged,
                        config.readonly_rootfs,
                        {},
                        {},
                        overlay_spec,
                        tmpfs_mounts);

                    if (!workdir.empty() && workdir != "/") {
                        fs::create_directories(workdir);
                        if (::chdir(workdir.c_str()) != 0) {
                            throw std::system_error(errno, std::generic_category(), "chdir(" + workdir + ")");
                        }
                    }

                    if (sec_opts.apparmor_profile.has_value()) {
                        apply_apparmor_profile(*sec_opts.apparmor_profile);
                    }
                    if (sec_opts.selinux_label.has_value()) {
                        apply_selinux_label(*sec_opts.selinux_label);
                    }

                    if (!config.privileged) {
                        drop_capabilities_to_set(target_caps);
                        if (prebuilt_seccomp.has_value()) {
                            apply_seccomp_program(*prebuilt_seccomp);
                        }
                    }

                    if (user_spec.has_value()) {
                        apply_process_user(user_spec->uid, user_spec->gid, {}, config.run_as_non_root);
                    } else if (config.run_as_non_root) {
                        apply_process_user(::getuid(), ::getgid(), {}, true);
                    }

                    std::vector<char*> argv_ptrs;
                    argv_ptrs.reserve(command.size() + 1);
                    for (auto& arg : const_cast<std::vector<std::string>&>(command)) argv_ptrs.push_back(arg.data());
                    argv_ptrs.push_back(nullptr);

                    std::vector<char*> env_ptrs;
                    env_ptrs.reserve(env_entries.size() + 1);
                    for (auto& e : env_entries) env_ptrs.push_back(e.data());
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
                if (pty_slave >= 0) ::close(pty_slave);
                if (log_pipe[1] >= 0) ::close(log_pipe[1]);
                if (null_fd >= 0) ::close(null_fd);

                std::string p2_msg = std::to_string(pid2) + "\n";
                [[maybe_unused]] ssize_t written = ::write(ready_pipe[1], p2_msg.data(), p2_msg.size());
                ::close(ready_pipe[1]);

                int status2 = 0;
                ::waitpid(pid2, &status2, 0);
                ::_exit(waitstatus_to_exitcode(status2));
            }
        } catch (const std::exception& exc) {
            std::cerr << "CHILD ERROR: " << exc.what() << "\n";
            if (pty_slave >= 0) ::close(pty_slave);
            if (log_pipe[1] >= 0) ::close(log_pipe[1]);
            if (null_fd >= 0) ::close(null_fd);
            ::close(ready_pipe[1]);
            if (use_userns) ::close(userns_done_pipe[0]);
            ::close(go_pipe[0]);
            ::_exit(1);
        }
    }

    ::close(ready_pipe[1]);
    if (use_userns) ::close(userns_done_pipe[0]);
    ::close(go_pipe[0]);
    if (pty_slave >= 0) ::close(pty_slave);
    if (log_pipe[1] >= 0) ::close(log_pipe[1]);
    if (null_fd >= 0) ::close(null_fd);

    auto read_line_fd = [](int fd) -> std::string {
        std::string line;
        char c = 0;
        while (::read(fd, &c, 1) == 1) {
            if (c == '\n') break;
            if (c != '\r') line.push_back(c);
        }
        return line;
    };

    if (use_userns) {
        std::string p1_str = read_line_fd(ready_pipe[0]);
        if (!p1_str.empty() && std::all_of(p1_str.begin(), p1_str.end(), ::isdigit)) {
            try {
                setup_rootless_user_namespace(static_cast<pid_t>(std::stoi(p1_str)), host_uid, host_gid);
            } catch (const std::exception& exc) {
                std::cerr << "USERNS: Warning: " << exc.what() << "\n";
            }
            [[maybe_unused]] ssize_t uw = ::write(userns_done_pipe[1], "1", 1);
        }
        ::close(userns_done_pipe[1]);
        profiler.mark("unshare + userns map");
    }

    std::string p2_str = read_line_fd(ready_pipe[0]);
    ::close(ready_pipe[0]);

    int grandchild_pid = 0;
    int rootless_net_pid = -1;
    if (!p2_str.empty() && std::all_of(p2_str.begin(), p2_str.end(), ::isdigit)) {
        grandchild_pid = std::stoi(p2_str);
        if (!use_userns) {
            profiler.mark("unshare + fork pid2");
        }
        cgroup_mgr.setup(grandchild_pid);
        if (net_plan.has_value()) {
            if (!setup_container_network(grandchild_pid, *net_plan)) {
                meta_record["ip"] = "";
                meta_record["ports"] = JsonArray{};
            }
        } else if (use_userns && ::geteuid() != 0 && config.network_mode == "bridge") {
            rootless_net_pid = setup_rootless_userspace_network(grandchild_pid, rootless_ports);
        }
        if (!config.auto_remove || config.detach) {
            meta_record["pid"] = static_cast<int64_t>(grandchild_pid);
            write_container_meta(container_dir, meta_record);
        }
        profiler.mark("cgroup + veth + port fwd");
        [[maybe_unused]] ssize_t gw = ::write(go_pipe[1], "1", 1);
    } else {
        profiler.mark("child setup failed");
    }
    ::close(go_pipe[1]);

    if (notify_parent_fd >= 0) {
        std::string msg = (grandchild_pid > 0) ? ("OK:" + container_id + "\n") : "ERR\n";
        [[maybe_unused]] ssize_t nw = ::write(notify_parent_fd, msg.data(), msg.size());
        ::close(notify_parent_fd);
        notify_parent_fd = -1;
    }

    if (pty_master >= 0) {
        relay_pty_session(pty_master, grandchild_pid);
        ::close(pty_master);
    } else if (log_pipe[0] >= 0) {
        RotatingLogWriter logger(
            (fs::path(container_dir) / "container.log").string(),
            config.log_max_bytes,
            config.log_max_files);
        drain_fd_to_rotating_log(log_pipe[0], logger);
        ::close(log_pipe[0]);
    }

    int status1 = 0;
    int exit_code = 1;
    if (::waitpid(pid1, &status1, 0) >= 0) {
        exit_code = waitstatus_to_exitcode(status1);
    }
    profiler.mark("container waitpid exit");

    if (net_plan.has_value()) {
        cleanup_port_forwarding(*net_plan);
        cleanup_container_network(net_plan->host_veth);
    }
    if (rootless_net_pid > 0) cleanup_rootless_userspace_network(rootless_net_pid);
    cgroup_mgr.cleanup();
    return exit_code;
}

int execute_container_supervisor(
    const ContainerRunConfig& config,
    const std::string& container_id,
    const std::string& container_name,
    const std::string& hostname,
    const std::string& image_path,
    const std::string& container_dir,
    const RootfsSetup& rootfs,
    const std::vector<std::string>& command,
    const std::map<std::string, std::string>& env_map,
    const std::string& workdir,
    const std::vector<VolumeMount>& volumes,
    const std::vector<TmpfsMount>& tmpfs_mounts,
    const std::vector<PortMapping>& rootless_ports,
    const std::set<cap_value_t>& target_caps,
    const std::optional<SeccompProgram>& prebuilt_seccomp,
    const SecurityOptions& sec_opts,
    const std::optional<UserSpec>& user_spec,
    std::optional<ContainerNetwork>& net_plan,
    CgroupManager& cgroup_mgr,
    bool use_userns,
    JsonObject& meta_record,
    int notify_parent_fd,
    StartupProfiler& profiler) {
    int exit_code = 1;
    int backoff_ms = 100;

    while (true) {
        exit_code = run_single_container_attempt(
            config, container_id, hostname, image_path, container_dir, rootfs,
            command, env_map, workdir, volumes, tmpfs_mounts, rootless_ports, target_caps,
            prebuilt_seccomp, sec_opts, user_spec,
            net_plan, cgroup_mgr, use_userns, meta_record, notify_parent_fd, profiler);

        std::error_code ec;
        bool stop_requested = fs::exists(fs::path(container_dir) / ".stop_requested", ec);
        bool should_restart = false;
        switch (config.restart_policy) {
            case RestartPolicy::No: should_restart = false; break;
            case RestartPolicy::OnFailure: should_restart = !stop_requested && (exit_code != 0); break;
            case RestartPolicy::Always:
            case RestartPolicy::UnlessStopped: should_restart = !stop_requested; break;
        }
        if (!should_restart) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
        backoff_ms = std::min(5000, backoff_ms * 2);
    }

    if (net_plan.has_value()) {
        release_container_ip(config.containers_dir, container_id, net_plan->network_name);
    }
    cleanup_container_rootfs(container_dir, rootfs.method);

    if (config.auto_remove) {
        std::error_code ec;
        if (fs::exists(container_dir, ec)) {
            fs::remove_all(container_dir, ec);
        }
    } else {
        meta_record["status"] = "exited";
        meta_record["pid"] = static_cast<int64_t>(0);
        meta_record["exit_code"] = static_cast<int64_t>(exit_code);
        write_container_meta(container_dir, meta_record);
    }
    profiler.mark("cleanup");
    profiler.print_report();

    if (!config.detach) {
        std::cout << "RUN: Container '" << container_name << "' exited with code " << exit_code << ".\n";
    }
    return exit_code;
}

}  // namespace

RotatingLogWriter::RotatingLogWriter(std::string base_path, std::size_t max_bytes, int max_files)
    : base_path_(std::move(base_path)),
      max_bytes_(std::max<std::size_t>(1024, max_bytes)),
      max_files_(std::max(1, max_files)) {
    std::error_code ec;
    fs::create_directories(fs::path(base_path_).parent_path(), ec);
    fd_ = ::open(base_path_.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd_ >= 0 && fs::is_regular_file(base_path_, ec)) {
        current_bytes_ = static_cast<std::size_t>(fs::file_size(base_path_, ec));
    }
}

void RotatingLogWriter::rotate() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    std::error_code ec;
    for (int idx = max_files_ - 1; idx >= 1; --idx) {
        std::string src = (idx == 1) ? base_path_ : (base_path_ + "." + std::to_string(idx - 1));
        std::string dst = base_path_ + "." + std::to_string(idx);
        if (fs::exists(src, ec)) fs::rename(src, dst, ec);
    }
    fd_ = ::open(base_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    current_bytes_ = 0;
}

void RotatingLogWriter::write(const char* data, std::size_t len) {
    if (fd_ < 0 || len == 0) return;
    if (current_bytes_ + len > max_bytes_ && current_bytes_ > 0) rotate();
    std::size_t off = 0;
    while (off < len && fd_ >= 0) {
        ssize_t w = ::write(fd_, data + off, len - off);
        if (w <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += static_cast<std::size_t>(w);
        current_bytes_ += static_cast<std::size_t>(w);
    }
}

void RotatingLogWriter::flush() {
    if (fd_ >= 0) ::fsync(fd_);
}

RestartPolicy parse_restart_policy(const std::string& spec) {
    if (spec == "no") return RestartPolicy::No;
    if (spec == "on-failure") return RestartPolicy::OnFailure;
    if (spec == "always") return RestartPolicy::Always;
    if (spec == "unless-stopped") return RestartPolicy::UnlessStopped;
    throw std::invalid_argument(
        "Invalid restart policy '" + spec + "'; expected no, on-failure, always, or unless-stopped");
}

std::string restart_policy_to_string(RestartPolicy policy) {
    switch (policy) {
        case RestartPolicy::No: return "no";
        case RestartPolicy::OnFailure: return "on-failure";
        case RestartPolicy::Always: return "always";
        case RestartPolicy::UnlessStopped: return "unless-stopped";
    }
    return "no";
}

std::size_t parse_byte_size(const std::string& spec) {
    return static_cast<std::size_t>(parse_memory_limit(spec));
}

std::vector<std::string> load_env_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Cannot open --env-file: " + path);
    std::vector<std::string> specs;
    std::string line;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        size_t b = 0;
        while (b < line.size() && std::isspace(static_cast<unsigned char>(line[b]))) ++b;
        line = line.substr(b);
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq != std::string::npos) {
            std::string k = line.substr(0, eq);
            std::string v = line.substr(eq + 1);
            if (v.size() >= 2 &&
                ((v.front() == '"' && v.back() == '"') || (v.front() == '\'' && v.back() == '\''))) {
                v = v.substr(1, v.size() - 2);
            }
            specs.push_back(k + "=" + v);
        } else {
            specs.push_back(line);
        }
    }
    return specs;
}

JsonObject inspect_container_json(const std::string& identifier, const std::string& containers_dir) {
    auto target_opt = find_container_dir(identifier, containers_dir);
    if (!target_opt.has_value()) throw std::runtime_error("Container '" + identifier + "' not found");
    auto meta = read_meta_object(fs::path(*target_opt) / "meta.json");
    if (!meta.has_value()) throw std::runtime_error("Container metadata missing for '" + identifier + "'");
    JsonObject out = *meta;
    out["containerDir"] = fs::absolute(*target_opt).string();
    std::string cid = fs::path(*target_opt).filename().string();
    CgroupManager cg(cid);
    auto st = cg.stats();
    out["cgroup"] = JsonObject{
        {"memoryCurrentBytes", static_cast<int64_t>(st.memory_current_bytes)},
        {"memoryMaxBytes", static_cast<int64_t>(st.memory_max_bytes)},
        {"cpuUsageUsec", static_cast<int64_t>(st.cpu_usage_usec)},
        {"pidsCurrent", static_cast<int64_t>(st.pids_current)},
        {"pidsMax", static_cast<int64_t>(st.pids_max)},
    };
    return out;
}

JsonObject inspect_any_json(
    const std::string& identifier,
    const std::string& image_dir,
    const std::string& containers_dir) {
    if (find_container_dir(identifier, containers_dir).has_value()) {
        return inspect_container_json(identifier, containers_dir);
    }
    try {
        return inspect_image_json(identifier, image_dir);
    } catch (const std::exception&) {
    }
    throw std::runtime_error("No container or image found matching '" + identifier + "'");
}

void copy_between_host_and_container(
    const std::string& src_spec,
    const std::string& dst_spec,
    const std::string& image_dir,
    const std::string& containers_dir) {
    auto split_ref = [](const std::string& s) -> std::optional<std::pair<std::string, std::string>> {
        auto colon = s.find(':');
        if (colon == std::string::npos || colon == 0) return std::nullopt;
        return std::make_pair(s.substr(0, colon), s.substr(colon + 1));
    };

    auto src_c = split_ref(src_spec);
    auto dst_c = split_ref(dst_spec);
    if (src_c.has_value() == dst_c.has_value()) {
        throw std::invalid_argument("Exactly one side of `pieces cp` must be CONTAINER:PATH");
    }

    auto resolve_container_root = [&](const std::string& ident, bool for_write) -> fs::path {
        auto cdir_opt = find_container_dir(ident, containers_dir);
        if (!cdir_opt.has_value()) throw std::runtime_error("Container '" + ident + "' not found");
        auto meta = read_meta_object(fs::path(*cdir_opt) / "meta.json");
        if (meta.has_value()) {
            if (auto p = meta->find("pid"); p != meta->end() && p->second.is_int() && p->second.as_int() > 0) {
                int pid = static_cast<int>(p->second.as_int());
                if (is_pid_alive(pid)) {
                    fs::path proc_root = fs::path("/proc") / std::to_string(pid) / "root";
                    std::error_code ec;
                    if (fs::exists(proc_root, ec)) return proc_root;
                }
            }
            if (for_write) {
                fs::path up = fs::path(*cdir_opt) / "upper";
                if (fs::is_directory(up)) return up;
            }
            if (!for_write) {
                fs::path up = fs::path(*cdir_opt) / "upper";
                if (fs::is_directory(up)) return up;
            }
            if (auto img = meta->find("image"); img != meta->end() && img->second.is_string()) {
                return fs::path(resolve_image_path(img->second.as_string(), image_dir));
            }
        }
        return fs::path(*cdir_opt) / "rootfs";
    };

    auto copy_item = [](const fs::path& from, const fs::path& to) {
        if (!fs::exists(from)) throw std::runtime_error("Copy source does not exist: '" + from.string() + "'");
        if (fs::is_directory(from)) {
            fs::create_directories(to);
            fs::copy(from, to, fs::copy_options::recursive | fs::copy_options::copy_symlinks | fs::copy_options::overwrite_existing);
        } else {
            if (fs::is_directory(to)) {
                fs::copy_file(from, to / from.filename(), fs::copy_options::overwrite_existing);
            } else {
                fs::create_directories(to.parent_path());
                fs::copy_file(from, to, fs::copy_options::overwrite_existing);
            }
        }
    };

    auto join_safe = [](const fs::path& root, std::string rel) -> fs::path {
        while (!rel.empty() && rel.front() == '/') rel.erase(rel.begin());
        fs::path target = fs::weakly_canonical(root / rel);
        fs::path root_real = fs::weakly_canonical(root);
        auto check = target.lexically_relative(root_real);
        if (!check.empty() && *check.begin() == "..") {
            throw std::invalid_argument("Container copy path escapes rootfs");
        }
        return target;
    };

    if (src_c.has_value()) {
        fs::path croot = resolve_container_root(src_c->first, false);
        fs::path csrc = join_safe(croot, src_c->second);
        if (!fs::exists(csrc)) {
            // Fall back to base image rootfs when copying from stopped overlay upperdir
            auto cdir_opt = find_container_dir(src_c->first, containers_dir);
            auto meta = cdir_opt ? read_meta_object(fs::path(*cdir_opt) / "meta.json") : std::nullopt;
            if (meta && meta->contains("image")) {
                fs::path img_root(resolve_image_path(meta->at("image").as_string(), image_dir));
                csrc = join_safe(img_root, src_c->second);
            }
        }
        copy_item(csrc, fs::path(dst_spec));
    } else {
        fs::path croot = resolve_container_root(dst_c->first, true);
        fs::path cdst = join_safe(croot, dst_c->second);
        copy_item(fs::path(src_spec), cdst);
    }
}

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
    if (!entrypoint.empty()) return entrypoint;
    if (!default_cmd.empty()) return default_cmd;
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
            if (v.is_string()) env[k] = v.as_string();
        }
    }

    for (const auto& spec : env_specs) {
        auto eq = spec.find('=');
        if (eq != std::string::npos) {
            std::string key = spec.substr(0, eq);
            std::string val = spec.substr(eq + 1);
            if (key.empty()) throw std::invalid_argument("Invalid environment variable specification: '" + spec + "'");
            env[key] = val;
        } else {
            if (spec.empty()) throw std::invalid_argument("Environment variable name cannot be empty");
            if (const char* host_val = std::getenv(spec.c_str())) env[spec] = host_val;
        }
    }
    return env;
}

std::vector<JsonObject> list_containers(bool show_all, const std::string& containers_dir) {
    std::vector<JsonObject> records;
    std::error_code ec;
    if (!fs::is_directory(containers_dir, ec)) return records;

    for (const auto& entry : fs::directory_iterator(containers_dir, ec)) {
        if (!entry.is_directory(ec)) continue;
        fs::path meta_path = entry.path() / "meta.json";
        auto obj_opt = read_meta_object(meta_path);
        if (!obj_opt.has_value()) continue;
        JsonObject obj = std::move(*obj_opt);

        auto status_it = obj.find("status");
        bool is_running = (status_it != obj.end() && status_it->second.is_string() &&
                           status_it->second.as_string() == "running");
        if (is_running) {
            auto pid_it = obj.find("pid");
            if (pid_it != obj.end() && pid_it->second.is_int() && pid_it->second.as_int() > 0) {
                if (!is_pid_alive(static_cast<int>(pid_it->second.as_int()))) {
                    reconcile_dead_container_resources(entry.path(), obj, containers_dir);
                    is_running = false;
                }
            }
        }
        if (!show_all && !is_running) continue;
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
    if (!target_opt.has_value()) throw std::runtime_error("Container '" + identifier + "' not found");
    const std::string& target = *target_opt;

    if (auto meta = read_meta_object(fs::path(target) / "meta.json"); meta.has_value()) {
        auto status_it = meta->find("status");
        auto pid_it = meta->find("pid");
        bool marked_running = status_it != meta->end() && status_it->second.is_string() &&
                              status_it->second.as_string() == "running";
        int pid = (pid_it != meta->end() && pid_it->second.is_int()) ? static_cast<int>(pid_it->second.as_int()) : 0;
        bool alive = is_pid_alive(pid);
        if (marked_running && alive && !force) {
            throw std::runtime_error("Container '" + identifier + "' is running; stop it or pass --force.");
        }
        if (marked_running && alive && force) {
            {
                std::ofstream marker(fs::path(target) / ".stop_requested");
            }
            ::kill(pid, SIGKILL);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        reconcile_dead_container_resources(target, *meta, containers_dir);
    }

    fs::remove_all(target);
    return fs::path(target).filename().string();
}

int stop_container(const std::string& identifier, int timeout_sec, const std::string& containers_dir) {
    auto target_opt = find_container_dir(identifier, containers_dir);
    if (!target_opt.has_value()) throw std::runtime_error("Container '" + identifier + "' not found");
    auto meta = read_meta_object(fs::path(*target_opt) / "meta.json");
    if (!meta.has_value()) throw std::runtime_error("Container metadata missing for '" + identifier + "'");
    {
        std::ofstream marker(fs::path(*target_opt) / ".stop_requested");
    }
    auto pid_it = meta->find("pid");
    if (pid_it == meta->end() || !pid_it->second.is_int() || pid_it->second.as_int() <= 0) {
        std::cout << "Container '" << identifier << "' is not running.\n";
        return 0;
    }
    int pid = static_cast<int>(pid_it->second.as_int());
    if (!is_pid_alive(pid)) {
        reconcile_dead_container_resources(*target_opt, *meta, containers_dir);
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
    if (!target_opt.has_value()) throw std::runtime_error("Container '" + identifier + "' not found");
    fs::path log_path = fs::path(*target_opt) / "container.log";
    std::error_code ec;
    if (!fs::is_regular_file(log_path, ec) && !follow) return 0;

    std::streamoff offset = 0;
    if (fs::is_regular_file(log_path, ec)) {
        std::ifstream in(log_path, std::ios::binary);
        if (tail_lines >= 0) {
            std::vector<std::string> lines;
            std::string line;
            while (std::getline(in, line)) lines.push_back(line);
            size_t start = (lines.size() > static_cast<size_t>(tail_lines))
                               ? (lines.size() - static_cast<size_t>(tail_lines))
                               : 0;
            for (size_t i = start; i < lines.size(); ++i) std::cout << lines[i] << "\n";
            std::cout << std::flush;
        } else {
            std::cout << in.rdbuf() << std::flush;
        }
        offset = static_cast<std::streamoff>(fs::file_size(log_path, ec));
    }

    while (follow) {
        if (fs::is_regular_file(log_path, ec)) {
            auto cur_size = static_cast<std::streamoff>(fs::file_size(log_path, ec));
            if (cur_size < offset) offset = 0;
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
        if (!still_running) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return 0;
}

int exec_in_container(
    const std::string& identifier,
    const std::vector<std::string>& cmd_args,
    const std::vector<std::string>& env_specs,
    const std::optional<std::string>& workdir,
    bool allocate_tty,
    const std::string& containers_dir) {
    if (cmd_args.empty()) throw std::invalid_argument("exec requires a command to run inside the container");
    auto target_opt = find_container_dir(identifier, containers_dir);
    if (!target_opt.has_value()) throw std::runtime_error("Container '" + identifier + "' not found");
    auto meta = read_meta_object(fs::path(*target_opt) / "meta.json");
    if (!meta.has_value()) throw std::runtime_error("Container metadata missing for '" + identifier + "'");
    auto pid_it = meta->find("pid");
    if (pid_it == meta->end() || !pid_it->second.is_int() || pid_it->second.as_int() <= 0) {
        throw std::runtime_error("Container '" + identifier + "' is not running");
    }
    int target_pid = static_cast<int>(pid_it->second.as_int());
    if (!is_pid_alive(target_pid)) throw std::runtime_error("Container '" + identifier + "' process is not alive");

    std::string hostname = identifier;
    if (auto hn = meta->find("name"); hn != meta->end() && hn->second.is_string()) {
        hostname = hn->second.as_string();
    }
    auto env_map = build_container_env(*meta, env_specs, hostname);
    std::vector<std::string> env_entries;
    env_entries.reserve(env_map.size());
    for (const auto& [k, v] : env_map) env_entries.push_back(k + "=" + v);

    enter_container_namespaces(target_pid);

    int pty_master = -1;
    int pty_slave = -1;
    bool use_pty = allocate_tty && ::isatty(STDIN_FILENO);
    if (use_pty && ::openpty(&pty_master, &pty_slave, nullptr, nullptr, nullptr) != 0) {
        use_pty = false;
        pty_master = -1;
        pty_slave = -1;
    }

    pid_t child = ::fork();
    if (child < 0) {
        if (pty_master >= 0) { ::close(pty_master); ::close(pty_slave); }
        throw std::system_error(errno, std::generic_category(), "fork(exec)");
    }
    if (child == 0) {
        if (pty_master >= 0) ::close(pty_master);
        if (pty_slave >= 0) {
            ::setsid();
            ::ioctl(pty_slave, TIOCSCTTY, 0);
            ::dup2(pty_slave, STDIN_FILENO);
            ::dup2(pty_slave, STDOUT_FILENO);
            ::dup2(pty_slave, STDERR_FILENO);
            ::close(pty_slave);
        }
        if (workdir.has_value() && !workdir->empty()) {
            if (::chdir(workdir->c_str()) != 0) {
                std::cerr << "EXEC ERROR: chdir(" << *workdir << ") failed: " << std::strerror(errno) << "\n";
                ::_exit(1);
            }
        }
        std::vector<char*> argv_ptrs;
        argv_ptrs.reserve(cmd_args.size() + 1);
        for (auto& a : const_cast<std::vector<std::string>&>(cmd_args)) argv_ptrs.push_back(a.data());
        argv_ptrs.push_back(nullptr);

        std::vector<char*> env_ptrs;
        env_ptrs.reserve(env_entries.size() + 1);
        for (auto& e : env_entries) env_ptrs.push_back(e.data());
        env_ptrs.push_back(nullptr);

        ::execvpe(argv_ptrs[0], argv_ptrs.data(), env_ptrs.data());
        int err = errno;
        std::cerr << "EXEC ERROR: execvpe(" << cmd_args[0] << ") failed: " << std::strerror(err) << "\n";
        ::_exit(err == ENOENT ? 127 : 126);
    }

    if (pty_slave >= 0) ::close(pty_slave);
    if (pty_master >= 0) {
        relay_pty_session(pty_master, child);
        ::close(pty_master);
    }

    int status = 0;
    if (::waitpid(child, &status, 0) < 0) return 1;
    return waitstatus_to_exitcode(status);
}

int show_container_stats(
    const std::string& identifier,
    const std::string& containers_dir,
    const std::string& cgroup_root) {
    std::string cid = identifier;
    std::string cg_dir;
    if (auto target_opt = find_container_dir(identifier, containers_dir); target_opt.has_value()) {
        cid = fs::path(*target_opt).filename().string();
        cg_dir = (fs::path(cgroup_root) / "pieces" / cid).string();
    } else {
        auto state_obj = oci_get_state(identifier);
        if (auto it = state_obj.find("cgroupsPath"); it != state_obj.end() && it->second.is_string()) {
            cg_dir = it->second.as_string();
        }
    }

    CgroupStats st = read_cgroup_stats(cg_dir);
    JsonObject out;
    out["id"] = cid;
    out["memoryCurrentBytes"] = static_cast<int64_t>(st.memory_current_bytes);
    out["memoryMaxBytes"] = static_cast<int64_t>(st.memory_max_bytes);
    out["cpuUsageUsec"] = static_cast<int64_t>(st.cpu_usage_usec);
    out["pidsCurrent"] = static_cast<int64_t>(st.pids_current);
    out["pidsMax"] = static_cast<int64_t>(st.pids_max);
    std::cout << JsonValue(out).dump(2) << "\n";
    return 0;
}

int run_container(const ContainerRunConfig& config) {
    ::signal(SIGPIPE, SIG_IGN);
    StartupProfiler profiler(config.timing && !config.detach);

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
    if (config.entrypoint_override.has_value()) {
        if (config.entrypoint_override->empty()) {
            metadata.erase("entrypoint");
        } else {
            JsonArray arr;
            for (const auto& tok : parse_command_value(*config.entrypoint_override)) arr.emplace_back(tok);
            metadata["entrypoint"] = std::move(arr);
        }
    }
    std::vector<std::string> command = resolve_command(config.cmd_args, metadata);

    std::vector<std::string> merged_env_specs;
    for (const auto& ef : config.env_files) {
        auto loaded = load_env_file(ef);
        merged_env_specs.insert(merged_env_specs.end(), loaded.begin(), loaded.end());
    }
    merged_env_specs.insert(merged_env_specs.end(), config.env_specs.begin(), config.env_specs.end());
    std::map<std::string, std::string> env_map = build_container_env(metadata, merged_env_specs, hostname);

    std::string workdir = "/";
    if (config.workdir.has_value()) {
        workdir = *config.workdir;
    } else if (auto wd_it = metadata.find("workdir"); wd_it != metadata.end() && wd_it->second.is_string()) {
        workdir = wd_it->second.as_string();
    }

    std::vector<VolumeMount> volumes;
    volumes.reserve(config.volume_specs.size());
    for (const auto& vs : config.volume_specs) {
        volumes.push_back(parse_volume_spec(vs, config.volumes_dir));
    }

    std::vector<TmpfsMount> tmpfs_mounts;
    tmpfs_mounts.reserve(config.tmpfs_specs.size());
    for (const auto& ts : config.tmpfs_specs) tmpfs_mounts.push_back(parse_tmpfs_spec(ts));

    std::vector<PortMapping> ports;
    ports.reserve(config.port_specs.size());
    for (const auto& ps : config.port_specs) ports.push_back(parse_port_mapping(ps));

    std::optional<UserSpec> user_spec;
    if (config.user_spec.has_value()) {
        user_spec = parse_user_spec(*config.user_spec);
    } else if (auto u_it = metadata.find("user"); u_it != metadata.end() && u_it->second.is_string() &&
               !u_it->second.as_string().empty()) {
        user_spec = parse_user_spec(u_it->second.as_string());
    }
    if (config.run_as_non_root && (!user_spec.has_value() || user_spec->uid == 0)) {
        throw std::invalid_argument("--run-as-non-root requires a non-zero --user UID[:GID]");
    }

    SecurityOptions sec_opts = parse_security_opts(config.security_opts);

    std::optional<SeccompProgram> prebuilt_seccomp;
    if (!config.privileged) {
        if (config.seccomp_profile.has_value()) {
            prebuilt_seccomp = load_seccomp_profile_file(*config.seccomp_profile);
        } else {
            prebuilt_seccomp = build_allowlist_seccomp_filter(
                default_allowed_syscalls(),
                SECCOMP_RET_ERRNO | (EPERM & 0x0000FFFFU));
        }
    }

    std::set<cap_value_t> target_caps;
    if (!config.privileged) {
        target_caps = compute_target_capabilities(config.cap_add, config.cap_drop);
    }
    profiler.mark("config + seccomp + caps prep");

    bool use_userns = config.rootless || (::geteuid() != 0);
    bool host_is_root = (::geteuid() == 0);
    CgroupManager cgroup_mgr(container_id, config.memory_limit, config.cpu_limit, config.pids_limit);

    std::optional<ContainerNetwork> net_plan;
    if (config.network_mode != "none" && config.network_mode != "host") {
        if (!host_is_root) {
            if (!ports.empty()) {
                std::cerr << "NETWORK: Info: rootless -p forwarding uses pasta if installed.\n";
            }
        } else {
            NetworkConfig ncfg = load_network_config(config.network_mode, config.networks_dir);
            bool iso = ncfg.isolate && config.isolate_net;
            if (setup_host_network(ncfg.bridge_name, ncfg.gateway_ip + "/24", ncfg.subnet_cidr, true, iso)) {
                net_plan = build_network_plan(container_id, config.containers_dir, ports, ncfg.name, config.networks_dir);
            }
        }
    }

    // Generate custom /etc/hosts and /etc/resolv.conf bind mounts if --add-host, --dns, or peer discovery apply
    if (!config.add_hosts.empty() || (net_plan.has_value() && config.network_mode != "bridge")) {
        std::ostringstream hss;
        hss << "127.0.0.1\tlocalhost " << hostname << "\n::1\t\tlocalhost\n";
        if (net_plan.has_value()) {
            hss << net_plan->container_ip << "\t" << container_name << "\n";
            for (const auto& [pname, pip] : collect_network_peers(config.containers_dir, config.network_mode)) {
                hss << pip << "\t" << pname << " " << pname << ".pieces\n";
            }
        }
        for (const auto& ah : config.add_hosts) {
            auto colon = ah.find(':');
            if (colon == std::string::npos || colon == 0 || colon + 1 >= ah.size()) {
                throw std::invalid_argument("Invalid --add-host '" + ah + "'; expected HOST:IP");
            }
            hss << ah.substr(colon + 1) << "\t" << ah.substr(0, colon) << "\n";
        }
        fs::create_directories(container_dir);
        fs::path hosts_gen = fs::path(container_dir) / "hosts.gen";
        {
            std::ofstream hf(hosts_gen);
            hf << hss.str();
        }
        volumes.push_back({fs::absolute(hosts_gen).string(), "/etc/hosts", true});
    }
    if (!config.dns_servers.empty()) {
        fs::create_directories(container_dir);
        fs::path resolv_gen = fs::path(container_dir) / "resolv.gen";
        {
            std::ofstream rf(resolv_gen);
            for (const auto& ns : config.dns_servers) rf << "nameserver " << ns << "\n";
        }
        volumes.push_back({fs::absolute(resolv_gen).string(), "/etc/resolv.conf", true});
    }
    profiler.mark("host network + IPAM");

    if (!config.detach) {
        std::cout << "RUN: Starting container '" << container_name << "' (" << container_id
                  << ") from '" << config.image << "'" << (use_userns ? " [userns]" : "") << "...\n"
                  << std::flush;
    }

    RootfsSetup rootfs = prepare_container_rootfs(
        image_path,
        container_dir,
        hostname,
        config.readonly_rootfs,
        config.auto_remove && !config.detach);
    profiler.mark("rootfs (" + rootfs.method + ")");

    JsonArray port_arr;
    if (net_plan.has_value()) {
        for (const auto& pm : net_plan->ports) port_arr.emplace_back(format_port_mapping(pm));
    }

    JsonObject meta_record;
    meta_record["id"] = container_id;
    meta_record["name"] = container_name;
    meta_record["image"] = config.image;
    meta_record["command"] = join_args(command);
    meta_record["status"] = "running";
    meta_record["pid"] = static_cast<int64_t>(0);
    meta_record["network"] = config.network_mode;
    meta_record["ip"] = net_plan.has_value() ? net_plan->container_ip : "";
    meta_record["host_veth"] = net_plan.has_value() ? net_plan->host_veth : "";
    meta_record["ports"] = std::move(port_arr);
    meta_record["restart_policy"] = restart_policy_to_string(config.restart_policy);
    meta_record["rootless"] = use_userns;
    meta_record["readonly_rootfs"] = config.readonly_rootfs;
    meta_record["rootfs_method"] = rootfs.method;
    meta_record["created_at"] = utc_timestamp_iso();
    meta_record["exit_code"] = nullptr;
    if (!config.auto_remove || config.detach) {
        write_container_meta(container_dir, meta_record);
    }

    if (!config.detach) {
        int dummy_fd = -1;
        return execute_container_supervisor(
            config, container_id, container_name, hostname, image_path, container_dir, rootfs,
            command, env_map, workdir, volumes, tmpfs_mounts, ports, target_caps,
            prebuilt_seccomp, sec_opts, user_spec,
            net_plan, cgroup_mgr, use_userns, meta_record, dummy_fd, profiler);
    }

    int sup_pipe[2]{-1, -1};
    if (::pipe(sup_pipe) != 0) {
        if (net_plan.has_value()) release_container_ip(config.containers_dir, container_id, net_plan->network_name);
        cleanup_container_rootfs(container_dir, rootfs.method);
        throw std::system_error(errno, std::generic_category(), "pipe(detach)");
    }

    pid_t sup_pid = ::fork();
    if (sup_pid < 0) {
        ::close(sup_pipe[0]); ::close(sup_pipe[1]);
        if (net_plan.has_value()) release_container_ip(config.containers_dir, container_id, net_plan->network_name);
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
        int notify_fd = sup_pipe[1];
        int rc = execute_container_supervisor(
            config, container_id, container_name, hostname, image_path, container_dir, rootfs,
            command, env_map, workdir, volumes, tmpfs_mounts, ports, target_caps,
            prebuilt_seccomp, sec_opts, user_spec,
            net_plan, cgroup_mgr, use_userns, meta_record, notify_fd, profiler);
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

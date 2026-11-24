#include "pieces/namespaces.hpp"

#include <fcntl.h>
#include <pwd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace fs = std::filesystem;

namespace pieces {

namespace {

[[noreturn]] void throw_errno(const std::string& op) {
    int err = errno;
    throw std::system_error(err, std::generic_category(), op);
}

void write_exact_file(const fs::path& path, const std::string& content) {
    int fd = ::open(path.c_str(), O_WRONLY);
    if (fd < 0) {
        throw_errno("open(" + path.string() + ")");
    }
    ssize_t written = ::write(fd, content.data(), content.size());
    int saved_err = errno;
    ::close(fd);
    if (written != static_cast<ssize_t>(content.size())) {
        throw std::system_error(saved_err, std::generic_category(), "write(" + path.string() + ")");
    }
}

bool command_in_path(const std::string& cmd) {
    const char* path_env = std::getenv("PATH");
    if (!path_env) return false;
    std::string path_str(path_env);
    size_t start = 0;
    while (start <= path_str.size()) {
        size_t colon = path_str.find(':', start);
        std::string dir = (colon == std::string::npos) ? path_str.substr(start) : path_str.substr(start, colon - start);
        if (!dir.empty() && ::access((fs::path(dir) / cmd).c_str(), X_OK) == 0) {
            return true;
        }
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    return false;
}

int run_quiet_helper(const std::vector<std::string>& args) {
    pid_t p = ::fork();
    if (p < 0) return -1;
    if (p == 0) {
        int dn = ::open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            ::dup2(dn, STDOUT_FILENO);
            ::dup2(dn, STDERR_FILENO);
            ::close(dn);
        }
        std::vector<char*> argv;
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }
    int st = 0;
    if (::waitpid(p, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

void ensure_dev_node(
    const char* dev_name,
    unsigned int maj,
    unsigned int min,
    bool rootless) {
    std::string target = std::string("/dev/") + dev_name;
    std::error_code ec;
    if (fs::exists(target, ec)) {
        return;
    }

    if (!rootless) {
        if (::mknod(target.c_str(), S_IFCHR | 0666, makedev(maj, min)) == 0) {
            return;
        }
        if (errno != EPERM && errno != EACCES) {
            throw_errno("mknod(" + target + ")");
        }
    }

    std::string host_dev = std::string("/old_root/dev/") + dev_name;
    if (fs::exists(host_dev, ec)) {
        int fd = ::open(target.c_str(), O_WRONLY | O_CREAT, 0666);
        if (fd >= 0) {
            ::close(fd);
            if (::mount(host_dev.c_str(), target.c_str(), nullptr, MS_BIND, nullptr) == 0) {
                return;
            }
        }
    }
}

void apply_bind_mounts(const fs::path& rootfs_real, const std::vector<VolumeMount>& volumes) {
    for (const auto& vol : volumes) {
        std::string rel = vol.container_path;
        while (!rel.empty() && rel.front() == '/') {
            rel.erase(rel.begin());
        }
        fs::path target = fs::weakly_canonical(rootfs_real / rel);
        auto relative_check = target.lexically_relative(rootfs_real);
        if (relative_check.empty() || (*relative_check.begin() == "..")) {
            throw std::invalid_argument("Volume destination escapes container rootfs: '" + vol.container_path + "'");
        }

        if (fs::is_directory(vol.host_path)) {
            fs::create_directories(target);
        } else {
            fs::create_directories(target.parent_path());
            if (!fs::exists(target)) {
                std::ofstream touch(target, std::ios::app);
            }
        }

        checked_mount(vol.host_path.c_str(), target.c_str(), nullptr, MS_BIND | MS_REC, nullptr);
        if (vol.read_only) {
            checked_mount(nullptr, target.c_str(), nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
        }
    }
}

void mask_sensitive_proc_and_sys_paths() {
    std::error_code ec;
    // Remount /proc/sys read-only
    if (fs::exists("/proc/sys", ec)) {
        if (::mount("/proc/sys", "/proc/sys", nullptr, MS_BIND | MS_REC, nullptr) == 0) {
            ::mount(nullptr, "/proc/sys", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
        }
    }
    // Remount /sys read-only
    if (fs::exists("/sys", ec)) {
        ::mount(nullptr, "/sys", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
    }

    const char* masked_files[] = {
        "/proc/kcore",
        "/proc/keys",
        "/proc/timer_list",
        "/proc/sched_debug",
        "/proc/latency_stats",
    };
    for (const char* p : masked_files) {
        if (fs::exists(p, ec)) {
            ::mount("/dev/null", p, nullptr, MS_BIND, nullptr);
        }
    }

    const char* masked_dirs[] = {
        "/proc/acpi",
        "/proc/scsi",
        "/sys/firmware",
    };
    for (const char* d : masked_dirs) {
        if (fs::is_directory(d, ec)) {
            ::mount("tmpfs", d, "tmpfs", MS_RDONLY, "mode=000");
        }
    }
}

}  // namespace

void unshare_namespaces(int flags) {
    if (::unshare(flags) != 0) {
        throw_errno("unshare");
    }
}

void checked_mount(
    const char* source,
    const char* target,
    const char* fstype,
    unsigned long flags,
    const void* data) {
    if (::mount(source, target, fstype, flags, data) != 0) {
        throw_errno(std::string("mount(") + (source ? source : "none") + " -> " + target + ")");
    }
}

void checked_umount2(const char* target, int flags) {
    if (::umount2(target, flags) != 0) {
        throw_errno(std::string("umount2(") + target + ")");
    }
}

void checked_sethostname(const std::string& hostname) {
    std::string truncated = hostname.substr(0, 64);
    if (::sethostname(truncated.c_str(), truncated.size()) != 0) {
        throw_errno("sethostname(" + truncated + ")");
    }
}

void pivot_root_dir(const std::string& new_root, const std::string& put_old) {
    if (::syscall(SYS_pivot_root, new_root.c_str(), put_old.c_str()) != 0) {
        throw_errno("pivot_root(" + new_root + ", " + put_old + ")");
    }
}

std::optional<SubIdRange> parse_subid_range(
    const std::string& subid_file_path,
    const std::string& username) {
    std::ifstream in(subid_file_path);
    if (!in) {
        return std::nullopt;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string user, start_s, count_s;
        if (!std::getline(iss, user, ':') ||
            !std::getline(iss, start_s, ':') ||
            !std::getline(iss, count_s, ':')) {
            continue;
        }
        if (user == username) {
            try {
                uint32_t start = static_cast<uint32_t>(std::stoul(start_s));
                uint32_t count = static_cast<uint32_t>(std::stoul(count_s));
                if (count > 0) {
                    return SubIdRange{start, count};
                }
            } catch (const std::exception&) {
                continue;
            }
        }
    }
    return std::nullopt;
}

void write_user_namespace_maps(
    const std::string& proc_dir_for_pid,
    uid_t host_uid,
    gid_t host_gid) {
    fs::path proc_dir(proc_dir_for_pid);
    std::error_code ec;
    fs::path setgroups_path = proc_dir / "setgroups";
    if (fs::exists(setgroups_path, ec)) {
        write_exact_file(setgroups_path, "deny");
    }
    write_exact_file(proc_dir / "uid_map", "0 " + std::to_string(host_uid) + " 1\n");
    write_exact_file(proc_dir / "gid_map", "0 " + std::to_string(host_gid) + " 1\n");
}

void setup_rootless_user_namespace(
    pid_t target_pid,
    uid_t host_uid,
    gid_t host_gid) {
    if (target_pid != ::getpid() && command_in_path("newuidmap") && command_in_path("newgidmap")) {
        struct passwd pwd{};
        struct passwd* res = nullptr;
        char buf[1024];
        if (::getpwuid_r(host_uid, &pwd, buf, sizeof(buf), &res) == 0 && res && res->pw_name) {
            auto subuid = parse_subid_range("/etc/subuid", res->pw_name);
            auto subgid = parse_subid_range("/etc/subgid", res->pw_name);
            if (subuid.has_value() && subgid.has_value()) {
                std::string pid_s = std::to_string(target_pid);
                int r1 = run_quiet_helper({
                    "newuidmap", pid_s,
                    "0", std::to_string(host_uid), "1",
                    "1", std::to_string(subuid->start), std::to_string(subuid->count)
                });
                int r2 = run_quiet_helper({
                    "newgidmap", pid_s,
                    "0", std::to_string(host_gid), "1",
                    "1", std::to_string(subgid->start), std::to_string(subgid->count)
                });
                if (r1 == 0 && r2 == 0) {
                    return;
                }
            }
        }
    }

    std::string proc_path = (target_pid == ::getpid())
                                ? "/proc/self"
                                : ("/proc/" + std::to_string(target_pid));
    write_user_namespace_maps(proc_path, host_uid, host_gid);
}

void enter_container_namespaces(int target_pid) {
    std::string pid_str = std::to_string(target_pid);
    const char* ns_names[] = {"user", "ipc", "uts", "net", "pid", "mnt"};
    for (const char* ns : ns_names) {
        std::string ns_path = "/proc/" + pid_str + "/ns/" + ns;
        std::string self_path = std::string("/proc/self/ns/") + ns;
        struct stat st_target{}, st_self{};
        if (::stat(ns_path.c_str(), &st_target) == 0 && ::stat(self_path.c_str(), &st_self) == 0) {
            if (st_target.st_ino == st_self.st_ino && st_target.st_dev == st_self.st_dev) {
                continue;
            }
        }
        int fd = ::open(ns_path.c_str(), O_RDONLY);
        if (fd < 0) {
            if (std::strcmp(ns, "user") == 0 && errno == ENOENT) {
                continue;
            }
            throw_errno("open(" + ns_path + ")");
        }
        int rc = ::setns(fd, 0);
        int saved_err = errno;
        ::close(fd);
        if (rc != 0) {
            throw std::system_error(saved_err, std::generic_category(), "setns(" + ns_path + ")");
        }
    }
}

VolumeMount parse_volume_spec(const std::string& spec) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t colon = spec.find(':', start);
        if (colon == std::string::npos) {
            parts.push_back(spec.substr(start));
            break;
        }
        parts.push_back(spec.substr(start, colon - start));
        start = colon + 1;
    }

    if (parts.size() != 2 && parts.size() != 3) {
        throw std::invalid_argument("Invalid volume specification '" + spec + "'; expected HOST:CONTAINER[:ro]");
    }

    fs::path host_abs = fs::absolute(parts[0]);
    const std::string& container_path = parts[1];
    bool read_only = false;
    if (parts.size() == 3) {
        if (parts[2] == "ro") {
            read_only = true;
        } else if (parts[2] != "rw") {
            throw std::invalid_argument("Invalid volume mode '" + parts[2] + "'; expected 'ro' or 'rw'");
        }
    }

    if (container_path.empty() || container_path.front() != '/') {
        throw std::invalid_argument("Container volume path must be absolute: '" + container_path + "'");
    }
    if (!fs::exists(host_abs)) {
        throw std::runtime_error("Host volume path does not exist: '" + host_abs.string() + "'");
    }

    return {host_abs.string(), container_path, read_only};
}

void setup_container_mounts(
    const std::string& rootfs_dir,
    const std::vector<VolumeMount>& volumes,
    bool rootless,
    bool harden_proc_sys) {
    checked_mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);

    fs::path rootfs_real = fs::weakly_canonical(fs::absolute(rootfs_dir));
    apply_bind_mounts(rootfs_real, volumes);

    checked_mount(rootfs_real.c_str(), rootfs_real.c_str(), "bind", MS_BIND | MS_REC, nullptr);
    fs::path old_root = rootfs_real / "old_root";
    fs::create_directories(old_root);
    pivot_root_dir(rootfs_real.string(), old_root.string());
    if (::chdir("/") != 0) {
        throw_errno("chdir(/)");
    }

    fs::create_directories("/proc");
    checked_mount("proc", "/proc", "proc", 0, nullptr);

    fs::create_directories("/sys");
    if (::mount("sysfs", "/sys", "sysfs", 0, nullptr) != 0) {
        if (!rootless || (errno != EPERM && errno != EACCES)) {
            throw_errno("mount(sysfs -> /sys)");
        }
        ::mount("/old_root/sys", "/sys", nullptr, MS_BIND | MS_REC | MS_RDONLY, nullptr);
    }

    fs::create_directories("/dev");
    checked_mount("tmpfs", "/dev", "tmpfs", 0, "mode=755");

    fs::create_directories("/dev/pts");
    if (::mount("devpts", "/dev/pts", "devpts", 0, nullptr) != 0 && !rootless) {
        throw_errno("mount(devpts -> /dev/pts)");
    }

    fs::create_directories("/dev/shm");
    checked_mount("tmpfs", "/dev/shm", "tmpfs", 0, nullptr);

    ensure_dev_node("null", 1, 3, rootless);
    ensure_dev_node("zero", 1, 5, rootless);
    ensure_dev_node("random", 1, 8, rootless);
    ensure_dev_node("urandom", 1, 9, rootless);
    ensure_dev_node("tty", 5, 0, rootless);

    const std::pair<const char*, const char*> symlinks[] = {
        {"/dev/stdin", "/proc/self/fd/0"},
        {"/dev/stdout", "/proc/self/fd/1"},
        {"/dev/stderr", "/proc/self/fd/2"},
    };
    std::error_code ec;
    for (const auto& [link_path, target] : symlinks) {
        if (!fs::exists(fs::symlink_status(link_path, ec))) {
            fs::create_symlink(target, link_path);
        }
    }

    checked_umount2("/old_root", MNT_DETACH);
    if (::rmdir("/old_root") != 0) {
        throw_errno("rmdir(/old_root)");
    }

    if (harden_proc_sys) {
        mask_sensitive_proc_and_sys_paths();
    }
}

}  // namespace pieces

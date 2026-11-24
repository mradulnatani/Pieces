#include "pieces/namespaces.hpp"

#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <system_error>

namespace fs = std::filesystem;

namespace pieces {

namespace {

[[noreturn]] void throw_errno(const std::string& op) {
    int err = errno;
    throw std::system_error(err, std::generic_category(), op);
}

void ensure_char_device(const char* path, unsigned int maj, unsigned int min, mode_t mode = 0666) {
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        if (::mknod(path, S_IFCHR | mode, makedev(maj, min)) != 0) {
            throw_errno(std::string("mknod(") + path + ")");
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

void setup_container_mounts(const std::string& rootfs_dir, const std::vector<VolumeMount>& volumes) {
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
    checked_umount2("/old_root", MNT_DETACH);
    if (::rmdir("/old_root") != 0) {
        throw_errno("rmdir(/old_root)");
    }

    fs::create_directories("/proc");
    checked_mount("proc", "/proc", "proc", 0, nullptr);

    fs::create_directories("/sys");
    checked_mount("sysfs", "/sys", "sysfs", 0, nullptr);

    fs::create_directories("/dev");
    checked_mount("tmpfs", "/dev", "tmpfs", 0, "mode=755");

    fs::create_directories("/dev/pts");
    checked_mount("devpts", "/dev/pts", "devpts", 0, nullptr);

    fs::create_directories("/dev/shm");
    checked_mount("tmpfs", "/dev/shm", "tmpfs", 0, nullptr);

    ensure_char_device("/dev/null", 1, 3);
    ensure_char_device("/dev/zero", 1, 5);
    ensure_char_device("/dev/random", 1, 8);
    ensure_char_device("/dev/urandom", 1, 9);
    ensure_char_device("/dev/tty", 5, 0);

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
}

}  // namespace pieces

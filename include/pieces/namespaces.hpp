#pragma once

#include <sys/types.h>

#include <string>
#include <vector>

namespace pieces {

struct VolumeMount {
    std::string host_path;
    std::string container_path;
    bool read_only{false};
};

void unshare_namespaces(int flags);
void checked_mount(
    const char* source,
    const char* target,
    const char* fstype,
    unsigned long flags,
    const void* data = nullptr);
void checked_umount2(const char* target, int flags);
void checked_sethostname(const std::string& hostname);
void pivot_root_dir(const std::string& new_root, const std::string& put_old);

void write_user_namespace_maps(
    const std::string& proc_dir_for_pid,
    uid_t host_uid,
    gid_t host_gid);

void enter_container_namespaces(int target_pid);

[[nodiscard]] VolumeMount parse_volume_spec(const std::string& spec);
void setup_container_mounts(
    const std::string& rootfs_dir,
    const std::vector<VolumeMount>& volumes = {},
    bool rootless = false);

}  // namespace pieces

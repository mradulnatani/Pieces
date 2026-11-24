#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

namespace pieces {

struct VolumeMount {
    std::string host_path;
    std::string container_path;
    bool read_only{false};
};

struct TmpfsMount {
    std::string container_path;
    std::string options;
};

struct SubIdRange {
    uint32_t start{0};
    uint32_t count{0};
};

struct IdMapping {
    uint32_t container_id{0};
    uint32_t host_id{0};
    uint32_t size{1};
};

struct OverlayRootfsSpec {
    std::string lower_dir;
    std::string upper_dir;
    std::string work_dir;
    bool full_copy{false};
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

[[nodiscard]] std::optional<SubIdRange> parse_subid_range(
    const std::string& subid_file_path,
    const std::string& username);

void write_user_namespace_maps(
    const std::string& proc_dir_for_pid,
    const std::vector<IdMapping>& uid_maps,
    const std::vector<IdMapping>& gid_maps);

void write_user_namespace_maps(
    const std::string& proc_dir_for_pid,
    uid_t host_uid,
    gid_t host_gid);

void setup_rootless_user_namespace(
    pid_t target_pid,
    uid_t host_uid,
    gid_t host_gid,
    const std::vector<IdMapping>& custom_uid_maps = {},
    const std::vector<IdMapping>& custom_gid_maps = {});

void join_namespace_path(const std::string& ns_path);
void enter_container_namespaces(int target_pid);

[[nodiscard]] VolumeMount parse_volume_spec(
    const std::string& spec,
    const std::string& volumes_dir = ".pieces/volumes");
[[nodiscard]] TmpfsMount parse_tmpfs_spec(const std::string& spec);
void setup_container_mounts(
    const std::string& rootfs_dir,
    const std::vector<VolumeMount>& volumes = {},
    bool rootless = false,
    bool harden_proc_sys = true,
    bool readonly_rootfs = false,
    const std::vector<std::string>& extra_masked_paths = {},
    const std::vector<std::string>& extra_readonly_paths = {},
    const std::optional<OverlayRootfsSpec>& overlay_spec = std::nullopt,
    const std::vector<TmpfsMount>& tmpfs_mounts = {});

}  // namespace pieces

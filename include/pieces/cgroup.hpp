#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace pieces {

inline constexpr const char* CGROUP_ROOT = "/sys/fs/cgroup";

struct CgroupStats {
    uint64_t memory_current_bytes{0};
    uint64_t memory_max_bytes{0};  // 0 means unlimited ("max")
    uint64_t cpu_usage_usec{0};
    uint64_t pids_current{0};
    uint64_t pids_max{0};  // 0 means unlimited ("max")
};

[[nodiscard]] uint64_t parse_memory_limit(const std::string& value);
[[nodiscard]] std::string format_cpu_max(double cpus, int period_us = 100000);
[[nodiscard]] CgroupStats read_cgroup_stats(const std::string& group_dir);

class CgroupManager {
public:
    CgroupManager(
        std::string container_id,
        std::optional<std::string> memory_limit = std::nullopt,
        std::optional<double> cpu_limit = std::nullopt,
        std::optional<int> pids_limit = std::nullopt,
        std::string cgroup_root = CGROUP_ROOT,
        std::string custom_cgroups_path = "");

    [[nodiscard]] bool has_limits() const;
    [[nodiscard]] const std::string& group_dir() const { return group_dir_; }
    bool setup(int pid);
    [[nodiscard]] CgroupStats stats() const;
    void cleanup();

private:
    void enable_subtree_controllers() const;
    void write_file(const std::string& filename, const std::string& content) const;

    std::string container_id_;
    std::optional<uint64_t> memory_bytes_;
    std::optional<std::string> cpu_max_;
    std::optional<int> pids_max_;
    std::string cgroup_root_;
    std::string base_dir_;
    std::string group_dir_;
    bool active_{false};
};

}  // namespace pieces

#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace pieces {

inline constexpr const char* CGROUP_ROOT = "/sys/fs/cgroup";

[[nodiscard]] uint64_t parse_memory_limit(const std::string& value);
[[nodiscard]] std::string format_cpu_max(double cpus, int period_us = 100000);

class CgroupManager {
public:
    CgroupManager(
        std::string container_id,
        std::optional<std::string> memory_limit = std::nullopt,
        std::optional<double> cpu_limit = std::nullopt,
        std::optional<int> pids_limit = std::nullopt,
        std::string cgroup_root = CGROUP_ROOT);

    [[nodiscard]] bool has_limits() const;
    bool setup(int pid);
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

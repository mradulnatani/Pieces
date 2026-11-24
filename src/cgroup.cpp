#include "pieces/cgroup.hpp"

#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <system_error>

namespace fs = std::filesystem;

namespace pieces {

namespace {

std::string to_lower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

}  // namespace

uint64_t parse_memory_limit(const std::string& value) {
    static const std::regex kMemRe(R"(^\s*(\d+(?:\.\d+)?)\s*([kmgt]?b?)?\s*$)", std::regex::icase);
    std::smatch match;
    if (!std::regex_match(value, match, kMemRe)) {
        throw std::invalid_argument("Invalid memory limit '" + value + "'; expected e.g. 256m or 1g");
    }

    double num = std::stod(match[1].str());
    std::string suffix = to_lower(match[2].str());
    uint64_t mult = 1;
    if (suffix.empty() || suffix == "b") {
        mult = 1;
    } else if (suffix == "k" || suffix == "kb") {
        mult = 1024ULL;
    } else if (suffix == "m" || suffix == "mb") {
        mult = 1024ULL * 1024ULL;
    } else if (suffix == "g" || suffix == "gb") {
        mult = 1024ULL * 1024ULL * 1024ULL;
    } else if (suffix == "t" || suffix == "tb") {
        mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    } else {
        throw std::invalid_argument("Unsupported memory unit '" + suffix + "' in '" + value + "'");
    }

    double total = num * static_cast<double>(mult);
    if (total <= 0.0) {
        throw std::invalid_argument("Memory limit must be greater than zero");
    }
    return static_cast<uint64_t>(total);
}

std::string format_cpu_max(double cpus, int period_us) {
    if (cpus <= 0.0) {
        throw std::invalid_argument("CPU limit must be greater than zero");
    }
    long quota = std::max(1000L, std::lround(cpus * static_cast<double>(period_us)));
    return std::to_string(quota) + " " + std::to_string(period_us);
}

CgroupManager::CgroupManager(
    std::string container_id,
    std::optional<std::string> memory_limit,
    std::optional<double> cpu_limit,
    std::optional<int> pids_limit,
    std::string cgroup_root)
    : container_id_(std::move(container_id)),
      cgroup_root_(std::move(cgroup_root)) {
    if (memory_limit.has_value()) {
        memory_bytes_ = parse_memory_limit(*memory_limit);
    }
    if (cpu_limit.has_value()) {
        cpu_max_ = format_cpu_max(*cpu_limit);
    }
    if (pids_limit.has_value()) {
        if (*pids_limit <= 0) {
            throw std::invalid_argument("PIDs limit must be greater than zero");
        }
        pids_max_ = *pids_limit;
    }
    base_dir_ = (fs::path(cgroup_root_) / "pieces").string();
    group_dir_ = (fs::path(base_dir_) / container_id_).string();
}

bool CgroupManager::has_limits() const {
    return memory_bytes_.has_value() || cpu_max_.has_value() || pids_max_.has_value();
}

bool CgroupManager::setup(int pid) {
    if (!has_limits()) {
        return false;
    }
    std::error_code ec;
    fs::path controllers = fs::path(cgroup_root_) / "cgroup.controllers";
    if (!fs::is_regular_file(controllers, ec)) {
        std::cerr << "CGROUP: Warning: cgroup v2 not detected; skipping resource limits.\n";
        return false;
    }

    try {
        fs::create_directories(base_dir_);
        enable_subtree_controllers();
        fs::create_directories(group_dir_);

        if (memory_bytes_.has_value()) {
            write_file("memory.max", std::to_string(*memory_bytes_));
        }
        if (cpu_max_.has_value()) {
            write_file("cpu.max", *cpu_max_);
        }
        if (pids_max_.has_value()) {
            write_file("pids.max", std::to_string(*pids_max_));
        }
        write_file("cgroup.procs", std::to_string(pid));
        active_ = true;
        return true;
    } catch (const std::exception& exc) {
        std::cerr << "CGROUP: Warning: could not apply cgroup limits (" << exc.what()
                  << "); continuing without limits.\n";
        cleanup();
        return false;
    }
}

void CgroupManager::enable_subtree_controllers() const {
    fs::path subtree_ctl = fs::path(base_dir_) / "cgroup.subtree_control";
    std::error_code ec;
    if (!fs::exists(subtree_ctl, ec)) {
        return;
    }
    std::string needed;
    if (memory_bytes_.has_value()) needed += "+memory ";
    if (cpu_max_.has_value()) needed += "+cpu ";
    if (pids_max_.has_value()) needed += "+pids ";
    if (!needed.empty()) {
        needed.pop_back();
        std::ofstream out(subtree_ctl);
        if (out) {
            out << needed;
        }
    }
}

void CgroupManager::write_file(const std::string& filename, const std::string& content) const {
    fs::path target = fs::path(group_dir_) / filename;
    std::ofstream out(target);
    if (!out) {
        throw std::runtime_error("Failed to open " + target.string());
    }
    out << content;
    out.flush();
    if (!out) {
        throw std::runtime_error("Failed to write " + target.string());
    }
}

void CgroupManager::cleanup() {
    std::error_code ec;
    if (fs::is_directory(group_dir_, ec)) {
        ::rmdir(group_dir_.c_str());
    }
    active_ = false;
}

}  // namespace pieces

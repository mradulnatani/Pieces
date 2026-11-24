#include "pieces/cgroup.hpp"

#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
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

uint64_t read_u64_or_zero(const fs::path& p) {
    std::ifstream in(p);
    if (!in) return 0;
    std::string tok;
    if (!(in >> tok) || tok == "max") return 0;
    try {
        return std::stoull(tok);
    } catch (const std::exception&) {
        return 0;
    }
}

}  // namespace

uint64_t parse_memory_limit(const std::string& value) {
    size_t i = 0;
    while (i < value.size() && std::isspace(static_cast<unsigned char>(value[i]))) ++i;
    size_t num_start = i;
    bool saw_digit = false;
    bool saw_dot = false;
    while (i < value.size()) {
        unsigned char c = static_cast<unsigned char>(value[i]);
        if (std::isdigit(c)) {
            saw_digit = true;
            ++i;
        } else if (c == '.' && !saw_dot && saw_digit) {
            saw_dot = true;
            ++i;
        } else {
            break;
        }
    }
    if (!saw_digit) {
        throw std::invalid_argument("Invalid memory limit '" + value + "'; expected e.g. 256m or 1g");
    }
    double num = std::stod(value.substr(num_start, i - num_start));
    while (i < value.size() && std::isspace(static_cast<unsigned char>(value[i]))) ++i;
    size_t unit_start = i;
    while (i < value.size() && !std::isspace(static_cast<unsigned char>(value[i]))) ++i;
    std::string suffix = to_lower(value.substr(unit_start, i - unit_start));
    while (i < value.size() && std::isspace(static_cast<unsigned char>(value[i]))) ++i;
    if (i != value.size()) {
        throw std::invalid_argument("Invalid memory limit '" + value + "'; expected e.g. 256m or 1g");
    }

    uint64_t mult = 1;
    if (suffix.empty() || suffix == "b") mult = 1;
    else if (suffix == "k" || suffix == "kb") mult = 1024ULL;
    else if (suffix == "m" || suffix == "mb") mult = 1024ULL * 1024ULL;
    else if (suffix == "g" || suffix == "gb") mult = 1024ULL * 1024ULL * 1024ULL;
    else if (suffix == "t" || suffix == "tb") mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    else throw std::invalid_argument("Unsupported memory unit '" + suffix + "' in '" + value + "'");

    double total = num * static_cast<double>(mult);
    if (total <= 0.0) throw std::invalid_argument("Memory limit must be greater than zero");
    return static_cast<uint64_t>(total);
}

std::string format_cpu_max(double cpus, int period_us) {
    if (cpus <= 0.0) throw std::invalid_argument("CPU limit must be greater than zero");
    long quota = std::max(1000L, std::lround(cpus * static_cast<double>(period_us)));
    return std::to_string(quota) + " " + std::to_string(period_us);
}

CgroupStats read_cgroup_stats(const std::string& group_dir) {
    CgroupStats st;
    fs::path dir(group_dir);
    st.memory_current_bytes = read_u64_or_zero(dir / "memory.current");
    st.memory_max_bytes = read_u64_or_zero(dir / "memory.max");
    st.pids_current = read_u64_or_zero(dir / "pids.current");
    st.pids_max = read_u64_or_zero(dir / "pids.max");

    std::ifstream cpu_in(dir / "cpu.stat");
    std::string line;
    while (std::getline(cpu_in, line)) {
        std::istringstream iss(line);
        std::string key;
        uint64_t val = 0;
        if (iss >> key >> val && key == "usage_usec") {
            st.cpu_usage_usec = val;
            break;
        }
    }
    return st;
}

CgroupManager::CgroupManager(
    std::string container_id,
    std::optional<std::string> memory_limit,
    std::optional<double> cpu_limit,
    std::optional<int> pids_limit,
    std::string cgroup_root,
    std::string custom_cgroups_path)
    : container_id_(std::move(container_id)),
      cgroup_root_(std::move(cgroup_root)) {
    if (memory_limit.has_value()) memory_bytes_ = parse_memory_limit(*memory_limit);
    if (cpu_limit.has_value()) cpu_max_ = format_cpu_max(*cpu_limit);
    if (pids_limit.has_value()) {
        if (*pids_limit <= 0) throw std::invalid_argument("PIDs limit must be greater than zero");
        pids_max_ = *pids_limit;
    }

    if (!custom_cgroups_path.empty()) {
        std::string rel = custom_cgroups_path;
        while (!rel.empty() && rel.front() == '/') rel.erase(rel.begin());
        fs::path full = fs::path(cgroup_root_) / rel;
        base_dir_ = full.parent_path().string();
        group_dir_ = full.string();
    } else {
        base_dir_ = (fs::path(cgroup_root_) / "pieces").string();
        group_dir_ = (fs::path(base_dir_) / container_id_).string();
    }
}

bool CgroupManager::has_limits() const {
    return memory_bytes_.has_value() || cpu_max_.has_value() || pids_max_.has_value();
}

bool CgroupManager::setup(int pid) {
    std::error_code ec;
    fs::path controllers = fs::path(cgroup_root_) / "cgroup.controllers";
    if (!fs::is_regular_file(controllers, ec)) {
        if (has_limits()) {
            std::cerr << "CGROUP: Warning: cgroup v2 not detected; skipping resource limits.\n";
        }
        return false;
    }

    try {
        fs::create_directories(base_dir_);
        if (has_limits()) enable_subtree_controllers();
        fs::create_directories(group_dir_);

        if (memory_bytes_.has_value()) write_file("memory.max", std::to_string(*memory_bytes_));
        if (cpu_max_.has_value()) write_file("cpu.max", *cpu_max_);
        if (pids_max_.has_value()) write_file("pids.max", std::to_string(*pids_max_));

        write_file("cgroup.procs", std::to_string(pid));
        active_ = true;
        return true;
    } catch (const std::exception& exc) {
        if (has_limits()) {
            std::cerr << "CGROUP: Warning: could not apply cgroup limits (" << exc.what()
                      << "); continuing without limits.\n";
        }
        cleanup();
        return false;
    }
}

CgroupStats CgroupManager::stats() const {
    return read_cgroup_stats(group_dir_);
}

void CgroupManager::enable_subtree_controllers() const {
    fs::path subtree_ctl = fs::path(base_dir_) / "cgroup.subtree_control";
    std::error_code ec;
    if (!fs::exists(subtree_ctl, ec)) return;
    std::string needed;
    if (memory_bytes_.has_value()) needed += "+memory ";
    if (cpu_max_.has_value()) needed += "+cpu ";
    if (pids_max_.has_value()) needed += "+pids ";
    if (!needed.empty()) {
        needed.pop_back();
        std::ofstream out(subtree_ctl);
        if (out) out << needed;
    }
}

void CgroupManager::write_file(const std::string& filename, const std::string& content) const {
    fs::path target = fs::path(group_dir_) / filename;
    std::ofstream out(target);
    if (!out) throw std::runtime_error("Failed to open " + target.string());
    out << content;
    out.flush();
    if (!out) throw std::runtime_error("Failed to write " + target.string());
}

void CgroupManager::cleanup() {
    std::error_code ec;
    if (fs::is_directory(group_dir_, ec)) ::rmdir(group_dir_.c_str());
    active_ = false;
}

}  // namespace pieces

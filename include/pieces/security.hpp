#pragma once

#include <linux/filter.h>
#include <sys/capability.h>

#include <set>
#include <string>
#include <vector>

namespace pieces {

struct SeccompProgram {
    std::vector<sock_filter> instructions;
};

[[nodiscard]] cap_value_t parse_capability_name(const std::string& name);
[[nodiscard]] std::set<cap_value_t> default_container_capabilities();
[[nodiscard]] std::set<cap_value_t> compute_target_capabilities(
    const std::vector<std::string>& cap_add,
    const std::vector<std::string>& cap_drop);

void drop_capabilities_to_set(const std::set<cap_value_t>& allowed_caps);

[[nodiscard]] std::vector<int> default_blocked_syscalls();
[[nodiscard]] SeccompProgram build_seccomp_filter(const std::vector<int>& blocked_syscalls);
void apply_default_seccomp_filter();

}  // namespace pieces

#pragma once

#include <linux/filter.h>
#include <sys/capability.h>
#include <sys/types.h>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "pieces/json.hpp"

namespace pieces {

struct SeccompRule {
    int syscall_nr{0};
    uint32_t action{0};
};

struct SeccompProgram {
    std::vector<sock_filter> instructions;
};

struct UserSpec {
    uid_t uid{0};
    gid_t gid{0};
    bool has_gid{false};
};

struct SecurityOptions {
    std::optional<std::string> apparmor_profile;
    std::optional<std::string> selinux_label;
};

[[nodiscard]] cap_value_t parse_capability_name(const std::string& name);
[[nodiscard]] std::set<cap_value_t> default_container_capabilities();
[[nodiscard]] std::set<cap_value_t> compute_target_capabilities(
    const std::vector<std::string>& cap_add,
    const std::vector<std::string>& cap_drop);
void drop_capabilities_to_set(const std::set<cap_value_t>& allowed_caps);

[[nodiscard]] std::optional<int> resolve_syscall_number(const std::string& name);
[[nodiscard]] std::vector<int> default_allowed_syscalls();
[[nodiscard]] SeccompProgram build_allowlist_seccomp_filter(
    const std::vector<int>& allowed_syscalls,
    uint32_t default_action);
[[nodiscard]] SeccompProgram build_seccomp_from_oci_json(const JsonValue& seccomp_obj);
[[nodiscard]] SeccompProgram load_seccomp_profile_file(const std::string& path);
void apply_seccomp_program(const SeccompProgram& prog);
void apply_default_seccomp_filter();

[[nodiscard]] UserSpec parse_user_spec(const std::string& spec);
void apply_process_user(
    uid_t uid,
    gid_t gid,
    const std::vector<gid_t>& additional_gids = {},
    bool run_as_non_root = false);

[[nodiscard]] SecurityOptions parse_security_opts(const std::vector<std::string>& opts);
void apply_apparmor_profile(const std::string& profile);
void apply_selinux_label(const std::string& label);

}  // namespace pieces

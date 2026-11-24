#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <sys/capability.h>
#include <sys/types.h>
#include <vector>

#include "pieces/json.hpp"
#include "pieces/namespaces.hpp"

namespace pieces {

struct OciHook {
    std::string path;
    std::vector<std::string> args;
    std::vector<std::string> env;
    int timeout_sec{0};
};

struct OciHooks {
    std::vector<OciHook> prestart;
    std::vector<OciHook> create_runtime;
    std::vector<OciHook> create_container;
    std::vector<OciHook> start_container;
    std::vector<OciHook> poststart;
    std::vector<OciHook> poststop;
};

struct OciNamespace {
    std::string type;  // pid, network, mount, ipc, uts, user, cgroup
    std::string path;
};

struct OciMount {
    std::string destination;
    std::string type;
    std::string source;
    std::vector<std::string> options;
};

struct OciSpec {
    std::string oci_version{"1.0.2"};
    std::string root_path{"rootfs"};
    bool root_readonly{false};
    std::string hostname{"pieces"};

    std::vector<std::string> args;
    std::vector<std::string> env;
    std::string cwd{"/"};
    uid_t uid{0};
    gid_t gid{0};
    std::vector<gid_t> additional_gids;
    bool no_new_privileges{true};
    std::optional<std::set<cap_value_t>> capabilities;
    std::optional<std::string> apparmor_profile;
    std::optional<std::string> selinux_label;

    std::vector<OciNamespace> namespaces;
    std::vector<IdMapping> uid_mappings;
    std::vector<IdMapping> gid_mappings;
    std::string cgroups_path;
    std::optional<uint64_t> memory_limit_bytes;
    std::optional<int64_t> cpu_quota;
    int64_t cpu_period{100000};
    std::optional<int> pids_limit;

    std::optional<JsonValue> seccomp;
    std::vector<std::string> masked_paths;
    std::vector<std::string> readonly_paths;
    std::vector<OciMount> mounts;
    std::map<std::string, std::string> annotations;
    OciHooks hooks;
};

[[nodiscard]] std::string default_oci_state_root();
[[nodiscard]] OciSpec parse_oci_spec_json(const JsonValue& doc);
[[nodiscard]] OciSpec parse_oci_spec_file(const std::string& config_path);
[[nodiscard]] JsonObject generate_default_oci_spec_json(bool rootless = false);
[[nodiscard]] int parse_signal_name(const std::string& sig);

int oci_create(
    const std::string& container_id,
    const std::string& bundle_dir,
    const std::string& pid_file = "",
    const std::string& state_root = "");
int oci_start(const std::string& container_id, const std::string& state_root = "");
[[nodiscard]] JsonObject oci_get_state(const std::string& container_id, const std::string& state_root = "");
int oci_print_state(const std::string& container_id, const std::string& state_root = "");
int oci_kill(
    const std::string& container_id,
    const std::string& signal_str = "SIGTERM",
    const std::string& state_root = "");
int oci_delete(
    const std::string& container_id,
    bool force = false,
    const std::string& state_root = "");

}  // namespace pieces

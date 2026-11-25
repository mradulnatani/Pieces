#include <archive.h>
#include <archive_entry.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "pieces/cgroup.hpp"
#include "pieces/cli.hpp"
#include "pieces/compose.hpp"
#include "pieces/container.hpp"
#include "pieces/daemon.hpp"
#include "pieces/filesystem.hpp"
#include "pieces/json.hpp"
#include "pieces/namespaces.hpp"
#include "pieces/network.hpp"
#include "pieces/oci_runtime.hpp"
#include "pieces/parser.hpp"
#include "pieces/registry.hpp"
#include "pieces/security.hpp"

namespace fs = std::filesystem;

namespace {

#define CHECK(cond)                                                                             \
    do {                                                                                        \
        if (!(cond)) {                                                                          \
            std::ostringstream oss;                                                             \
            oss << "Assertion failed at " << __FILE__ << ":" << __LINE__ << ": " << #cond;      \
            throw std::runtime_error(oss.str());                                                \
        }                                                                                       \
    } while (false)

struct TempDir {
    fs::path path;
    explicit TempDir(const std::string& prefix) {
        std::string tmpl = (fs::temp_directory_path() / (prefix + "-XXXXXX")).string();
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');
        char* created = ::mkdtemp(buf.data());
        CHECK(created != nullptr);
        path = created;
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void write_text_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p);
    CHECK(out.good());
    out << content;
}

std::string read_text_file(const fs::path& p) {
    std::ifstream in(p);
    CHECK(in.good());
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void create_tar_gz(const fs::path& out_tar, const std::vector<std::pair<std::string, std::string>>& entries) {
    archive* a = archive_write_new();
    CHECK(a != nullptr);
    CHECK(archive_write_add_filter_gzip(a) == ARCHIVE_OK);
    CHECK(archive_write_set_format_pax_restricted(a) == ARCHIVE_OK);
    CHECK(archive_write_open_filename(a, out_tar.c_str()) == ARCHIVE_OK);

    for (const auto& [name, content] : entries) {
        archive_entry* entry = archive_entry_new();
        archive_entry_set_pathname(entry, name.c_str());
        archive_entry_set_size(entry, static_cast<la_int64_t>(content.size()));
        archive_entry_set_filetype(entry, AE_IFREG);
        archive_entry_set_perm(entry, 0644);
        CHECK(archive_write_header(a, entry) == ARCHIVE_OK);
        CHECK(archive_write_data(a, content.data(), content.size()) == static_cast<la_ssize_t>(content.size()));
        archive_entry_free(entry);
    }
    CHECK(archive_write_close(a) == ARCHIVE_OK);
    archive_write_free(a);
}

void test_json_and_parser() {
    pieces::JsonObject obj;
    obj["name"] = "pieces";
    obj["count"] = 42;
    obj["arr"] = pieces::JsonArray{"a", "b\"c"};
    auto parsed = pieces::JsonValue::parse(pieces::JsonValue(obj).dump(2));
    CHECK(parsed.find("name")->as_string() == "pieces");
    CHECK(parsed.find("count")->as_int() == 42);

    TempDir tmp("pieces-parser");
    fs::path pf = tmp.path / "Piecefile";
    write_text_file(pf, R"(
FROM ubuntu:22.04
SHA256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ENV FOO=bar BAZ="hello world"
WORKDIR /app
COPY ./src /app/src
RUN echo "a" && \
    echo "b"
ENTRYPOINT ["/bin/sh", "-c"]
CMD echo "hi"
)");
    auto spec = pieces::parse_piecefile(pf.string());
    CHECK(spec.has_value());
    CHECK(spec->sha256 == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(spec->runs[0] == "echo \"a\" && echo \"b\"");
}

void test_cli_native_and_oci() {
    auto run_args = pieces::parse_command_args({
        "run", "--rm", "-d", "-it", "--read-only", "--run-as-non-root", "--timing",
        "--user", "1000:1000", "--seccomp-profile", "/tmp/sc.json",
        "--security-opt", "apparmor=pieces-default", "--security-opt", "label=system_u:system_r:container_t:s0",
        "--no-isolate-net", "--restart", "unless-stopped",
        "-p", "8080:80", "ubuntu-22.04", "sh"
    });
    CHECK(run_args.command == pieces::CliCommand::Run);
    CHECK(run_args.timing);
    CHECK(run_args.readonly_rootfs);
    CHECK(run_args.run_as_non_root);
    CHECK(!run_args.isolate_net);
    CHECK(run_args.user_spec == "1000:1000");
    CHECK(run_args.seccomp_profile == "/tmp/sc.json");
    CHECK(run_args.security_opts.size() == 2);

    auto oci_create = pieces::parse_command_args({"--root", "/run/k8s-pieces", "create", "--bundle", "/b", "--pid-file", "/p", "pod-c1"});
    CHECK(oci_create.command == pieces::CliCommand::OciCreate);
    CHECK(oci_create.oci_state_root == "/run/k8s-pieces");
    CHECK(oci_create.oci_bundle == "/b");
    CHECK(oci_create.oci_pid_file == "/p");
    CHECK(oci_create.target_container == "pod-c1");

    auto oci_kill = pieces::parse_command_args({"kill", "pod-c1", "SIGKILL"});
    CHECK(oci_kill.command == pieces::CliCommand::OciKill);
    CHECK(oci_kill.oci_signal == "SIGKILL");

    auto oci_del = pieces::parse_command_args({"delete", "-f", "pod-c1"});
    CHECK(oci_del.command == pieces::CliCommand::OciDelete);
    CHECK(oci_del.force);
    CHECK(oci_del.target_container == "pod-c1");

    auto stats_args = pieces::parse_command_args({"stats", "pod-c1"});
    CHECK(stats_args.command == pieces::CliCommand::Stats);
}

void test_allowlist_seccomp_oci_json_user_and_mac() {
    // Verify default allowlist blocks unshare, setns, chroot, bpf, ptrace, mount
    auto allowed = pieces::default_allowed_syscalls();
    auto is_allowed = [&](const char* name) {
        auto nr = pieces::resolve_syscall_number(name);
        if (!nr.has_value()) return false;
        return std::find(allowed.begin(), allowed.end(), *nr) != allowed.end();
    };
    CHECK(is_allowed("read"));
    CHECK(is_allowed("write"));
    CHECK(is_allowed("execve"));
    CHECK(!is_allowed("unshare"));
    CHECK(!is_allowed("setns"));
    CHECK(!is_allowed("chroot"));
    CHECK(!is_allowed("bpf"));
    CHECK(!is_allowed("ptrace"));
    CHECK(!is_allowed("mount"));

    auto prog = pieces::build_allowlist_seccomp_filter(allowed, SECCOMP_RET_ERRNO | 1);
    CHECK(prog.instructions.size() > 100);
    // Final instruction must be default-deny (not SECCOMP_RET_ALLOW)
    CHECK(prog.instructions.back().k != SECCOMP_RET_ALLOW);

    // OCI seccomp JSON profile compilation
    pieces::JsonValue oci_sc = pieces::JsonValue::parse(R"({
      "defaultAction": "SCMP_ACT_ERRNO",
      "defaultErrnoRet": 1,
      "syscalls": [
        {"names": ["read", "write", "exit_group"], "action": "SCMP_ACT_ALLOW"}
      ]
    })");
    auto custom_prog = pieces::build_seccomp_from_oci_json(oci_sc);
    CHECK(custom_prog.instructions.size() == 4 + 3 * 2 + 1);
    CHECK(custom_prog.instructions.back().k == (SECCOMP_RET_ERRNO | 1U));

    // User & security-opt parsing
    auto u1 = pieces::parse_user_spec("1000:2000");
    CHECK(u1.uid == 1000 && u1.gid == 2000 && u1.has_gid);
    auto u2 = pieces::parse_user_spec("65534");
    CHECK(u2.uid == 65534 && u2.gid == 65534);

    bool non_root_threw = false;
    try {
        pieces::apply_process_user(0, 0, {}, true);
    } catch (const std::runtime_error&) {
        non_root_threw = true;
    }
    CHECK(non_root_threw);

    auto sopts = pieces::parse_security_opts({"apparmor=pieces-default", "label=system_u:system_r:svirt_lxc_net_t:s0"});
    CHECK(sopts.apparmor_profile == "pieces-default");
    CHECK(sopts.selinux_label == "system_u:system_r:svirt_lxc_net_t:s0");
}

void test_oci_runtime_spec_and_cgroup_stats() {
    auto def_spec = pieces::generate_default_oci_spec_json(true);
    auto parsed_def = pieces::parse_oci_spec_json(pieces::JsonValue(def_spec));
    CHECK(parsed_def.oci_version == "1.0.2");
    CHECK(parsed_def.no_new_privileges);
    CHECK(parsed_def.masked_paths.size() == 4);

    // Parse full Kubernetes/containerd-style config.json
    pieces::JsonValue k8s_cfg = pieces::JsonValue::parse(R"({
      "ociVersion": "1.0.2",
      "hostname": "web-pod",
      "root": {"path": "rootfs", "readonly": true},
      "process": {
        "user": {"uid": 1001, "gid": 1001, "additionalGids": [2000, 3000]},
        "args": ["/usr/bin/server", "--port", "8080"],
        "env": ["PATH=/usr/bin:/bin", "POD=web"],
        "cwd": "/srv",
        "noNewPrivileges": true,
        "apparmorProfile": "k8s-apparmor",
        "selinuxLabel": "system_u:system_r:container_t:s0:c1,c2",
        "capabilities": {
          "bounding": ["CAP_NET_BIND_SERVICE"],
          "effective": ["CAP_NET_BIND_SERVICE"],
          "permitted": ["CAP_NET_BIND_SERVICE"]
        }
      },
      "mounts": [
        {"destination": "/data", "type": "bind", "source": "/var/lib/data", "options": ["rbind", "ro"]}
      ],
      "linux": {
        "cgroupsPath": "/kubepods.slice/pod123/c1",
        "namespaces": [
          {"type": "pid"},
          {"type": "network", "path": "/var/run/netns/cni-pod123"},
          {"type": "ipc", "path": "/proc/1234/ns/ipc"}
        ],
        "uidMappings": [{"containerID": 0, "hostID": 100000, "size": 65536}],
        "gidMappings": [{"containerID": 0, "hostID": 100000, "size": 65536}],
        "resources": {
          "memory": {"limit": 268435456},
          "cpu": {"quota": 50000, "period": 100000},
          "pids": {"limit": 128}
        },
        "seccomp": {
          "defaultAction": "SCMP_ACT_ERRNO",
          "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}]
        }
      },
      "annotations": {"io.kubernetes.pod.name": "web-pod"},
      "hooks": {
        "poststart": [{"path": "/usr/local/bin/cni-hook", "args": ["cni-hook", "add"]}]
      }
    })");

    auto spec = pieces::parse_oci_spec_json(k8s_cfg);
    CHECK(spec.root_readonly);
    CHECK(spec.uid == 1001 && spec.gid == 1001);
    CHECK((spec.additional_gids == std::vector<gid_t>{2000, 3000}));
    CHECK(spec.apparmor_profile == "k8s-apparmor");
    CHECK(spec.selinux_label == "system_u:system_r:container_t:s0:c1,c2");
    CHECK(spec.capabilities.has_value() && spec.capabilities->contains(CAP_NET_BIND_SERVICE));
    CHECK(spec.cgroups_path == "/kubepods.slice/pod123/c1");
    CHECK(spec.namespaces[1].path == "/var/run/netns/cni-pod123");
    CHECK(spec.uid_mappings.size() == 1 && spec.uid_mappings[0].size == 65536);
    CHECK(spec.memory_limit_bytes == 268435456ULL);
    CHECK(spec.cpu_quota == 50000);
    CHECK(spec.pids_limit == 128);
    CHECK(spec.seccomp.has_value());
    CHECK(spec.annotations.at("io.kubernetes.pod.name") == "web-pod");
    CHECK(spec.hooks.poststart.size() == 1);

    CHECK(pieces::parse_signal_name("SIGTERM") == SIGTERM);
    CHECK(pieces::parse_signal_name("KILL") == SIGKILL);
    CHECK(pieces::parse_signal_name("9") == 9);

    // Mock cgroup v2 stats reading
    TempDir cg_tmp("pieces-cgstats");
    write_text_file(cg_tmp.path / "memory.current", "1048576\n");
    write_text_file(cg_tmp.path / "memory.max", "268435456\n");
    write_text_file(cg_tmp.path / "pids.current", "4\n");
    write_text_file(cg_tmp.path / "pids.max", "128\n");
    write_text_file(cg_tmp.path / "cpu.stat", "usage_usec 987654\nuser_usec 500000\n");

    auto st = pieces::read_cgroup_stats(cg_tmp.path.string());
    CHECK(st.memory_current_bytes == 1048576ULL);
    CHECK(st.memory_max_bytes == 268435456ULL);
    CHECK(st.pids_current == 4ULL);
    CHECK(st.pids_max == 128ULL);
    CHECK(st.cpu_usage_usec == 987654ULL);
}

void test_oci_pull_no_docker_hub_and_ipam_logs() {
    for (const char* rejected : {"ubuntu:22.04", "docker.io/library/alpine:3.18", "registry-1.docker.io/library/ubuntu:22.04"}) {
        bool threw = false;
        try {
            (void)pieces::parse_image_reference(rejected);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        CHECK(threw);
    }

    TempDir tmp("pieces-ipam");
    write_text_file(
        tmp.path / "c1" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{{"id", "c1"}, {"status", "running"}, {"pid", static_cast<int64_t>(::getpid())}}).dump());
    std::string ip1 = pieces::allocate_container_ip(tmp.path.string(), "c1");
    CHECK(ip1 == "10.0.0.2");
    pieces::release_container_ip(tmp.path.string(), "c1");
    CHECK(pieces::allocate_container_ip(tmp.path.string(), "c2") == "10.0.0.2");

    fs::path log_file = tmp.path / "logs" / "container.log";
    {
        pieces::RotatingLogWriter writer(log_file.string(), 1024, 3);
        std::string chunk(700, 'A');
        writer.write(chunk.data(), chunk.size());
        writer.write(chunk.data(), chunk.size());
    }
    CHECK(fs::exists(log_file));
    CHECK(fs::exists(log_file.string() + ".1"));
    CHECK(read_text_file(log_file).find('A') != std::string::npos);

    // Safe tarball extraction + whiteout + SHA-256 verification
    fs::path bad_tar = tmp.path / "bad.tar.gz";
    create_tar_gz(bad_tar, {{"../escape.txt", "bad"}});
    bool tar_threw = false;
    try {
        pieces::safe_extract_tar_file(bad_tar.string(), (tmp.path / "out").string());
    } catch (const std::exception&) {
        tar_threw = true;
    }
    CHECK(tar_threw);

    fs::path good_tar = tmp.path / "good.tar.gz";
    create_tar_gz(good_tar, {{"etc/hello.txt", "hello"}});
    fs::path extracted = tmp.path / "extracted";
    pieces::safe_extract_tar_file(good_tar.string(), extracted.string());
    CHECK(read_text_file(extracted / "etc/hello.txt") == "hello");
    CHECK(pieces::sha256_file(good_tar.string()).size() == 64);

    // Zero-copy read-only rootfs fast path
    fs::path ro_cdir = tmp.path / "ro-container";
    auto ro_setup = pieces::prepare_container_rootfs(extracted.string(), ro_cdir.string(), "robox", true, true);
    CHECK(ro_setup.method == "readonly-bind");
    CHECK(ro_setup.rootfs_dir == fs::absolute(extracted).string());
    CHECK(!fs::exists(ro_cdir));
    pieces::cleanup_container_rootfs(ro_cdir.string(), ro_setup.method);
    CHECK(read_text_file(extracted / "etc/hello.txt") == "hello");

    // In-namespace OverlayFS / hybrid writable rootfs fast path (no parent-side 500ms copy)
    fs::path rw_cdir = tmp.path / "rw-container";
    auto rw_setup = pieces::prepare_container_rootfs(extracted.string(), rw_cdir.string(), "rwbox", false, false);
    CHECK(rw_setup.method == "in-ns-overlay");
    CHECK(fs::is_directory(rw_setup.upper_dir));
    CHECK(fs::is_directory(rw_setup.work_dir));
    CHECK(fs::is_directory(rw_setup.rootfs_dir));
    CHECK(!fs::exists(fs::path(rw_setup.rootfs_dir) / "etc/hello.txt"));
    pieces::cleanup_container_rootfs(rw_cdir.string(), rw_setup.method);
}

void test_docker_parity_build_cli_volumes_auth_net_compose_api() {
    TempDir tmp("pieces-parity");

    // 1. Dockerfile fallback + multi-stage + ARG + USER + LABEL + EXPOSE + VOLUME + .piecesignore
    fs::path ctx = tmp.path / "ctx";
    fs::path base_tar = tmp.path / "base.tar.gz";
    create_tar_gz(base_tar, {{"bin/sh", "#!/bin/sh\n"}, {"etc/os-release", "ID=test\n"}});
    write_text_file(ctx / ".dockerignore", "*.tmp\nsecret/\n");
    write_text_file(ctx / "src" / "hello.txt", "compiled-artifact\n");
    write_text_file(ctx / "src" / "ignored.tmp", "skip-me\n");
    write_text_file(ctx / "secret" / "key.txt", "do-not-copy\n");
    write_text_file(ctx / "bundle.tar.gz", "");
    create_tar_gz(ctx / "bundle.tar.gz", {{"extracted/data.txt", "from-add\n"}});
    write_text_file(ctx / "Dockerfile", R"(
ARG APP_NAME=demo
FROM_URL https://example.com/base.tar.gz AS stage1
COPY ./src /build
FROM_URL https://example.com/base.tar.gz AS final
ARG VER=1.2.3
LABEL org.example.version=1.2.3 app="my demo"
EXPOSE 8080/tcp 9090
VOLUME ["/data"]
USER 1000:1000
ENV SERVICE_VER=${VER}
WORKDIR /app
COPY --from=stage1 /build/hello.txt /app/hello.txt
ADD bundle.tar.gz /app/
CMD ["/bin/sh"]
)");

    std::string resolved_pf = pieces::resolve_piecefile_path(ctx.string());
    CHECK(fs::path(resolved_pf).filename() == "Dockerfile");
    auto spec = pieces::parse_piecefile(resolved_pf);
    CHECK(spec.has_value());
    CHECK(spec->stages.size() == 2);
    CHECK(spec->user == "1000:1000");
    CHECK(spec->labels.at("org.example.version") == "1.2.3");
    CHECK(spec->exposed_ports.size() == 2);
    CHECK(spec->volumes.size() == 1 && spec->volumes[0] == "/data");

    fs::path img_dir = tmp.path / "images";
    fs::path cache_dir = tmp.path / "cache";
    fs::path out_img = img_dir / "parity-app";
    auto mock_dl = [&](const std::string& /*url*/, const std::string& dst) {
        fs::copy_file(base_tar, dst, fs::copy_options::overwrite_existing);
    };
    bool built = pieces::build_image(
        *spec, out_img.string(), ctx.string(), mock_dl, nullptr, nullptr, false,
        cache_dir.string(), {{"VER", "9.9.9"}}, img_dir.string());
    CHECK(built);
    CHECK(read_text_file(out_img / "app/hello.txt") == "compiled-artifact\n");
    CHECK(read_text_file(out_img / "app/extracted/data.txt") == "from-add\n");
    CHECK(!fs::exists(out_img / "app/ignored.tmp"));

    // Local image tagging + inspect + local FROM build
    pieces::tag_image("parity-app", "parity-app:v2", img_dir.string());
    auto inspected_img = pieces::inspect_image_json("parity-app:v2", img_dir.string());
    CHECK(inspected_img.at("name").as_string() == "parity-app-v2");

    fs::path derived_ctx = tmp.path / "derived_ctx";
    write_text_file(derived_ctx / "Piecefile", "FROM parity-app:v2\nWORKDIR /app\n");
    auto derived_spec = pieces::parse_piecefile((derived_ctx / "Piecefile").string());
    CHECK(derived_spec.has_value());
    CHECK(pieces::build_image(
        *derived_spec, (img_dir / "derived").string(), derived_ctx.string(),
        nullptr, nullptr, nullptr, false, cache_dir.string(), {}, img_dir.string()));
    CHECK(read_text_file(img_dir / "derived/app/hello.txt") == "compiled-artifact\n");

    // 2. CLI parity flags & new subcommands
    auto cli_run = pieces::parse_command_args({
        "run", "--name=web", "--net=host", "--entrypoint=/usr/bin/env",
        "--env-file", "/tmp/e", "--tmpfs=/run:rw,size=8m",
        "--add-host=db.local:10.0.0.5", "--dns=1.1.1.1", "-di", "parity-app", "arg1"
    });
    CHECK(cli_run.command == pieces::CliCommand::Run);
    CHECK(cli_run.name == "web");
    CHECK(cli_run.network_mode == "host");
    CHECK(cli_run.entrypoint_override == "/usr/bin/env");
    CHECK(cli_run.env_files.size() == 1);
    CHECK(cli_run.tmpfs_specs.size() == 1);
    CHECK(cli_run.add_hosts.size() == 1);
    CHECK(cli_run.dns_servers.size() == 1);
    CHECK(cli_run.detach && cli_run.interactive);
    CHECK(cli_run.cmd_args == std::vector<std::string>{"arg1"});

    auto cli_dit = pieces::parse_command_args({"run", "-dit", "--name", "sh1", "ubuntu-22.04", "/bin/sh"});
    CHECK(cli_dit.detach && cli_dit.interactive && cli_dit.allocate_tty && cli_dit.name == "sh1");

    auto cli_tag = pieces::parse_command_args({"tag", "a", "b"});
    CHECK(cli_tag.command == pieces::CliCommand::Tag);
    auto cli_cp = pieces::parse_command_args({"cp", "c1:/a", "/tmp/a"});
    CHECK(cli_cp.command == pieces::CliCommand::Cp);
    auto cli_vol = pieces::parse_command_args({"volume", "create", "mydata"});
    CHECK(cli_vol.command == pieces::CliCommand::Volume && cli_vol.sub_action == "create");
    auto cli_net = pieces::parse_command_args({"network", "create", "--subnet=10.9.0.0/24", "appnet"});
    CHECK(cli_net.command == pieces::CliCommand::Network && cli_net.subnet_cidr == "10.9.0.0/24");
    auto cli_login = pieces::parse_command_args({"login", "-u", "alice", "-p", "sec", "ghcr.io"});
    CHECK(cli_login.command == pieces::CliCommand::Login && cli_login.login_registry == "ghcr.io");

    // 3. Named volumes & tmpfs parser + cp + container inspect + env-file
    fs::path vol_dir = tmp.path / "volumes";
    pieces::create_volume("pgdata", vol_dir.string());
    CHECK(pieces::list_volumes(vol_dir.string()).size() == 1);
    auto vm = pieces::parse_volume_spec("pgdata:/var/lib/pg:ro", vol_dir.string());
    CHECK(vm.container_path == "/var/lib/pg" && vm.read_only);
    auto tm = pieces::parse_tmpfs_spec("/cache:size=16m");
    CHECK(tm.container_path == "/cache" && tm.options == "size=16m");
    pieces::remove_volume("pgdata", vol_dir.string());
    CHECK(pieces::list_volumes(vol_dir.string()).empty());

    fs::path envf = tmp.path / "app.env";
    write_text_file(envf, "# comment\nFOO=bar\nQUOTED=\"hello world\"\n");
    auto loaded_env = pieces::load_env_file(envf.string());
    CHECK((loaded_env == std::vector<std::string>{"FOO=bar", "QUOTED=hello world"}));

    fs::path cdir = tmp.path / "containers";
    write_text_file(
        cdir / "c100" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{
            {"id", "c100"}, {"name", "web1"}, {"image", "parity-app"}, {"status", "exited"},
            {"ip", "10.0.0.2"}, {"network", "appnet"}, {"pid", static_cast<int64_t>(0)}
        }).dump());
    write_text_file(cdir / "c100" / "upper" / "out.txt", "container-output\n");
    fs::path host_copied = tmp.path / "copied_out.txt";
    pieces::copy_between_host_and_container("c100:/out.txt", host_copied.string(), img_dir.string(), cdir.string());
    CHECK(read_text_file(host_copied) == "container-output\n");
    CHECK(pieces::inspect_any_json("web1", img_dir.string(), cdir.string()).at("id").as_string() == "c100");

    // 4. Registry authentication persistence & ~/.docker/config.json fallback
    fs::path auth_json = tmp.path / "auth.json";
    pieces::save_registry_credentials("ghcr.io", "bob", "tok123", auth_json.string());
    CHECK(pieces::load_registry_basic_auth("ghcr.io", auth_json.string()).value() ==
          pieces::base64_encode("bob:tok123"));

    // 5. Custom networks & Embedded DNS responder
    fs::path nets_dir = tmp.path / "networks";
    auto netcfg = pieces::create_network("appnet", "10.7.0.0/24", false, nets_dir.string());
    CHECK(netcfg.gateway_ip == "10.7.0.1");
    CHECK(pieces::list_networks(nets_dir.string()).size() == 2);
    // Construct DNS A query for "db" (qtype=1, qclass=1)
    std::vector<uint8_t> dns_q = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        2, 'd', 'b', 0,
        0x00, 0x01, 0x00, 0x01
    };
    auto dns_resp = pieces::build_dns_response(dns_q, {{"db", "10.7.0.4"}});
    CHECK(dns_resp.size() > dns_q.size());
    CHECK((dns_resp[3] & 0x0F) == 0);  // NOERROR
    CHECK(dns_resp[dns_resp.size() - 4] == 10 && dns_resp[dns_resp.size() - 1] == 4);
    pieces::EmbeddedDnsServer dns_srv("127.0.0.1", 0, cdir.string(), "appnet");
    CHECK(dns_srv.start());
    CHECK(dns_srv.bound_port() > 0);
    dns_srv.stop();
    pieces::remove_network("appnet", nets_dir.string());

    // 6. Compose YAML parsing + depends_on topological sort + REST API shim
    auto proj = pieces::parse_compose_yaml(R"(
services:
  web:
    image: parity-app
    ports:
      - "8080:80"
    depends_on:
      - db
  db:
    image: alpine:3.18
    environment:
      POSTGRES_DB: app
networks:
  backend:
volumes:
  dbdata:
)", "myapp");
    CHECK(proj.services.size() == 2);
    auto order = pieces::topo_sort_services(proj.services);
    CHECK((order == std::vector<std::string>{"db", "web"}));

    auto ping = pieces::handle_docker_api_request("GET", "/v1.43/_ping");
    CHECK(ping.status_code == 200 && ping.body == "OK");
    auto info = pieces::handle_docker_api_request("GET", "/info", "", img_dir.string(), cdir.string(), vol_dir.string(), nets_dir.string());
    CHECK(info.status_code == 200 && info.body.find("in-ns-overlay") != std::string::npos);
    auto cjson = pieces::handle_docker_api_request("GET", "/containers/web1/json", "", img_dir.string(), cdir.string(), vol_dir.string(), nets_dir.string());
    CHECK(cjson.status_code == 200 && cjson.body.find("c100") != std::string::npos);
}

}  // namespace

int main() {
    test_json_and_parser();
    test_cli_native_and_oci();
    test_allowlist_seccomp_oci_json_user_and_mac();
    test_oci_runtime_spec_and_cgroup_stats();
    test_oci_pull_no_docker_hub_and_ipam_logs();
    test_docker_parity_build_cli_volumes_auth_net_compose_api();
    std::cout << "All 6 hardened, OCI runtime & Docker parity C++ test suites passed.\n";
    return 0;
}

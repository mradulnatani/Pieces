#include <archive.h>
#include <archive_entry.h>
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
#include "pieces/container.hpp"
#include "pieces/filesystem.hpp"
#include "pieces/json.hpp"
#include "pieces/namespaces.hpp"
#include "pieces/network.hpp"
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

void test_json_roundtrip() {
    pieces::JsonObject obj;
    obj["name"] = "pieces";
    obj["count"] = 42;
    obj["ok"] = true;
    obj["arr"] = pieces::JsonArray{"a", "b\"c"};

    std::string dumped = pieces::JsonValue(obj).dump(2);
    pieces::JsonValue parsed = pieces::JsonValue::parse(dumped);
    CHECK(parsed.is_object());
    CHECK(parsed.find("name")->as_string() == "pieces");
    CHECK(parsed.find("count")->as_int() == 42);
    CHECK(parsed.find("arr")->as_array()[1].as_string() == "b\"c");
}

void test_parser() {
    TempDir tmp("pieces-parser");
    fs::path pf = tmp.path / "Piecefile";
    write_text_file(pf, R"(
# comment
FROM ubuntu:22.04
SHA256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ENV FOO=bar BAZ="hello world"
ENV LEGACY legacy value
WORKDIR /app
COPY ./src /app/src
RUN echo "step 1" && \
    echo "step 2"
ENTRYPOINT ["/bin/sh", "-c"]
CMD echo "hi there"
)");

    auto spec = pieces::parse_piecefile(pf.string());
    CHECK(spec.has_value());
    CHECK(spec->from_image == "ubuntu:22.04");
    CHECK(spec->sha256 == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(spec->env.at("FOO") == "bar");
    CHECK(spec->env.at("BAZ") == "hello world");
    CHECK(spec->env.at("LEGACY") == "legacy value");
    CHECK(spec->workdir == "/app");
    CHECK(spec->copies.size() == 1);
    CHECK(spec->runs.size() == 1);
    CHECK(spec->runs[0] == "echo \"step 1\" && echo \"step 2\"");
    CHECK((spec->entrypoint == std::vector<std::string>{"/bin/sh", "-c"}));
    CHECK((spec->cmd == std::vector<std::string>{"echo", "hi there"}));

    fs::path bad_sha = tmp.path / "BadSha";
    write_text_file(bad_sha, "FROM ubuntu:22.04\nSHA256 not-hex\n");
    CHECK(!pieces::parse_piecefile(bad_sha.string()).has_value());

    fs::path missing_from = tmp.path / "NoFrom";
    write_text_file(missing_from, "CMD /bin/sh\n");
    CHECK(!pieces::parse_piecefile(missing_from.string()).has_value());
}

void test_cli() {
    auto run_args = pieces::parse_command_args({
        "run", "--rm", "-d", "-it", "--rootless", "--name", "c1",
        "--restart", "unless-stopped", "--log-max-size", "5m", "--log-max-files", "4",
        "--cap-drop", "NET_RAW", "--cap-add", "SYS_TIME",
        "-p", "8080:80", "-p", "127.0.0.1:5353:53/udp",
        "--memory", "128m", "-e", "A=1", "ubuntu-22.04", "ls", "-la", "/"
    });
    CHECK(run_args.command == pieces::CliCommand::Run);
    CHECK(run_args.auto_remove);
    CHECK(run_args.detach);
    CHECK(run_args.interactive);
    CHECK(run_args.allocate_tty);
    CHECK(run_args.rootless);
    CHECK(run_args.restart_policy == "unless-stopped");
    CHECK(run_args.log_max_size == "5m");
    CHECK(run_args.log_max_files == 4);
    CHECK((run_args.cap_drop == std::vector<std::string>{"NET_RAW"}));
    CHECK((run_args.cap_add == std::vector<std::string>{"SYS_TIME"}));
    CHECK((run_args.port_specs == std::vector<std::string>{"8080:80", "127.0.0.1:5353:53/udp"}));
    CHECK(run_args.image == "ubuntu-22.04");
    CHECK((run_args.cmd_args == std::vector<std::string>{"ls", "-la", "/"}));

    auto build_args = pieces::parse_command_args({"build", ".", "--no-cache", "-t", "custom:v1"});
    CHECK(build_args.command == pieces::CliCommand::Build);
    CHECK(build_args.no_cache);
    CHECK(build_args.tag == "custom:v1");

    auto pull_args = pieces::parse_command_args({"pull", "ghcr.io/org/app:v1", "-t", "app1"});
    CHECK(pull_args.command == pieces::CliCommand::Pull);
    CHECK(pull_args.pull_ref == "ghcr.io/org/app:v1");
    CHECK(pull_args.tag == "app1");

    auto exec_args = pieces::parse_command_args({"exec", "-it", "-w", "/app", "web", "sh"});
    CHECK(exec_args.command == pieces::CliCommand::Exec);
    CHECK(exec_args.interactive);
    CHECK(exec_args.allocate_tty);

    auto prune_args = pieces::parse_command_args({"prune"});
    CHECK(prune_args.command == pieces::CliCommand::Prune);
}

void test_filesystem_security_cache_and_build_run_order() {
    for (const char* bad : {"", ".", "..", "../etc", "a/b", "a\\b", "-bad"}) {
        bool threw = false;
        try {
            (void)pieces::validate_name(bad);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        CHECK(threw);
    }

    TempDir tmp("pieces-fs");
    for (const char* unsafe_entry : {"../escape.txt", "/etc/passwd"}) {
        fs::path bad_tar = tmp.path / "bad.tar.gz";
        create_tar_gz(bad_tar, {{unsafe_entry, "bad"}});
        bool threw = false;
        try {
            pieces::safe_extract_tar_file(bad_tar.string(), (tmp.path / "out").string());
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
    }

    fs::path base_tar = tmp.path / "base.tar.gz";
    create_tar_gz(base_tar, {{"etc/os-release", "ID=alpine\n"}});
    std::string good_sha = pieces::sha256_file(base_tar.string());

    fs::path ctx = tmp.path / "ctx";
    write_text_file(ctx / "app.txt", "hello-app\n");
    fs::path pf = ctx / "Piecefile";
    write_text_file(
        pf,
        "FROM_URL https://example.com/base.tar.gz\n"
        "SHA256 " + good_sha + "\n"
        "ENV STAGE=1\n"
        "WORKDIR /app\n"
        "COPY app.txt /app/app.txt\n"
        "RUN cat /app/app.txt > /app/built.txt\n"
        "CMD [\"/bin/sh\"]\n");

    auto spec = pieces::parse_piecefile(pf.string());
    CHECK(spec.has_value());

    fs::path img_path = tmp.path / "images" / "my-app";
    fs::path cache_dir = tmp.path / "cache";
    int downloads = 0;
    bool built = pieces::build_image(
        *spec,
        img_path.string(),
        ctx.string(),
        [&](const std::string&, const std::string& dest) {
            ++downloads;
            fs::copy_file(base_tar, dest, fs::copy_options::overwrite_existing);
        },
        [&](const std::string& rootfs_dir,
            const std::string&,
            const std::map<std::string, std::string>& env,
            const std::string& workdir) -> int {
            CHECK(env.at("STAGE") == "1");
            CHECK(workdir == "/app");
            CHECK(read_text_file(fs::path(rootfs_dir) / "app/app.txt") == "hello-app\n");
            write_text_file(fs::path(rootfs_dir) / "app/built.txt", "built-ok\n");
            return 0;
        },
        nullptr,
        false,
        cache_dir.string());
    CHECK(built);
    CHECK(downloads == 1);
    CHECK(read_text_file(img_path / "app/built.txt") == "built-ok\n");

    // Second build hits cache without invoking downloader
    bool built_cached = pieces::build_image(
        *spec,
        img_path.string(),
        ctx.string(),
        [&](const std::string&, const std::string&) {
            ++downloads;
            throw std::runtime_error("should not re-download on cache hit");
        },
        [&](const std::string& rootfs_dir, const std::string&, const std::map<std::string, std::string>&, const std::string&) {
            write_text_file(fs::path(rootfs_dir) / "app/built.txt", "built-cached\n");
            return 0;
        },
        nullptr,
        false,
        cache_dir.string());
    CHECK(built_cached);
    CHECK(downloads == 1);
    CHECK(read_text_file(img_path / "app/built.txt") == "built-cached\n");

    // SHA-256 mismatch rejects build and preserves existing image
    spec->sha256 = std::string(64, '0');
    bool bad_sha_ok = pieces::build_image(
        *spec,
        img_path.string(),
        ctx.string(),
        [&](const std::string&, const std::string& dest) {
            fs::copy_file(base_tar, dest, fs::copy_options::overwrite_existing);
        },
        nullptr,
        nullptr,
        true,
        cache_dir.string());
    CHECK(!bad_sha_ok);
    CHECK(read_text_file(img_path / "app/built.txt") == "built-cached\n");
}

void test_non_docker_hub_oci_and_sha256_verification() {
    // Reject Docker Hub and bare registry-less OCI refs
    for (const char* rejected : {"ubuntu:22.04", "alpine", "docker.io/library/alpine:3.18", "registry-1.docker.io/library/ubuntu:22.04"}) {
        bool threw = false;
        try {
            (void)pieces::parse_image_reference(rejected);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        CHECK(threw);
    }

    auto r1 = pieces::parse_image_reference("ghcr.io/org/service:v1.2");
    CHECK(r1.registry == "ghcr.io");
    CHECK(r1.repository == "org/service");
    CHECK(r1.tag == "v1.2");

    auto r2 = pieces::parse_image_reference("localhost:5000/team/api:dev");
    CHECK(r2.registry == "localhost:5000");
    CHECK(r2.repository == "team/api");
    CHECK(r2.tag == "dev");

    TempDir tmp("pieces-oci");
    fs::path layer1 = tmp.path / "layer1.tar.gz";
    fs::path layer2 = tmp.path / "layer2.tar.gz";
    create_tar_gz(layer1, {
        {"etc/keep.txt", "keep\n"},
        {"etc/remove_me.txt", "gone\n"},
        {"opt/opaque/old.txt", "old\n"},
    });
    create_tar_gz(layer2, {
        {"etc/.wh.remove_me.txt", ""},
        {"opt/opaque/.wh..wh..opq", ""},
        {"opt/opaque/new.txt", "new\n"},
    });

    std::string l1_digest = "sha256:" + pieces::sha256_file(layer1.string());
    std::string l2_digest = "sha256:" + pieces::sha256_file(layer2.string());
    std::string config_json = R"({
      "config": {
        "Env": ["PATH=/usr/bin:/bin", "APP=oci"],
        "WorkingDir": "/srv",
        "Cmd": ["/bin/sh", "-c", "echo ok"]
      }
    })";
    std::string cfg_digest = "sha256:" + pieces::sha256_string(config_json);
    std::string manifest_json = R"({
      "config": {"digest": ")" + cfg_digest + R"("},
      "layers": [
        {"digest": ")" + l1_digest + R"("},
        {"digest": ")" + l2_digest + R"("}
      ]
    })";
    std::string man_digest = "sha256:" + pieces::sha256_string(manifest_json);
    std::string index_json = R"({
      "manifests": [
        {"digest": ")" + man_digest + R"(", "platform": {"os": "linux", "architecture": ")" + pieces::host_oci_architecture() + R"("}}
      ]
    })";

    auto make_mock_http = [&](bool corrupt_layer) {
        return [&, corrupt_layer](const std::string& url,
                                  const std::vector<std::string>& headers,
                                  const std::string& save_to_path) -> pieces::HttpResponse {
            bool has_auth = false;
            for (const auto& h : headers) {
                if (h == "Authorization: Bearer tok123") has_auth = true;
            }
            if (url.find("auth.example.com/token") != std::string::npos) {
                return {200, {}, R"({"token":"tok123"})"};
            }
            if (!has_auth) {
                return {401, {{"www-authenticate", "Bearer realm=\"https://auth.example.com/token\",service=\"reg\",scope=\"repo:pull\""}}, ""};
            }
            if (url.find("/manifests/v1") != std::string::npos) {
                return {200, {}, index_json};
            }
            if (url.find("/manifests/" + man_digest) != std::string::npos) {
                return {200, {}, manifest_json};
            }
            if (url.find("/blobs/" + cfg_digest) != std::string::npos) {
                return {200, {}, config_json};
            }
            if (url.find("/blobs/" + l1_digest) != std::string::npos) {
                fs::copy_file(layer1, save_to_path, fs::copy_options::overwrite_existing);
                return {200, {}, ""};
            }
            if (url.find("/blobs/" + l2_digest) != std::string::npos) {
                if (corrupt_layer) {
                    write_text_file(save_to_path, "tampered bytes");
                } else {
                    fs::copy_file(layer2, save_to_path, fs::copy_options::overwrite_existing);
                }
                return {200, {}, ""};
            }
            return {404, {}, ""};
        };
    };

    fs::path pulled_img = tmp.path / "images" / "demo-v1";
    CHECK(pieces::pull_oci_image("ghcr.io/org/demo:v1", pulled_img.string(), make_mock_http(false)));
    CHECK(read_text_file(pulled_img / "etc/keep.txt") == "keep\n");
    CHECK(!fs::exists(pulled_img / "etc/remove_me.txt"));
    CHECK(!fs::exists(pulled_img / "opt/opaque/old.txt"));
    CHECK(read_text_file(pulled_img / "opt/opaque/new.txt") == "new\n");

    // Tampered layer digest fails SHA-256 verification
    fs::path bad_img = tmp.path / "images" / "demo-bad";
    CHECK(!pieces::pull_oci_image("ghcr.io/org/demo:v1", bad_img.string(), make_mock_http(true)));
    CHECK(!fs::exists(bad_img));
}

void test_security_subid_and_cgroup() {
    auto caps = pieces::compute_target_capabilities({"SYS_TIME"}, {"NET_RAW"});
    CHECK(!caps.contains(CAP_NET_RAW));
    CHECK(!caps.contains(CAP_SYS_ADMIN));
    CHECK(caps.contains(CAP_SYS_TIME));
    CHECK(caps.contains(CAP_CHOWN));

    auto seccomp_prog = pieces::build_seccomp_filter(pieces::default_blocked_syscalls());
    CHECK(seccomp_prog.instructions.size() > 10);

    TempDir tmp("pieces-subid");
    fs::path subuid = tmp.path / "subuid";
    write_text_file(subuid, "alice:100000:65536\nbob:165536:65536\n");
    auto r = pieces::parse_subid_range(subuid.string(), "bob");
    CHECK(r.has_value());
    CHECK(r->start == 165536U);
    CHECK(r->count == 65536U);
    CHECK(!pieces::parse_subid_range(subuid.string(), "charlie").has_value());

    CHECK(pieces::parse_memory_limit("256m") == 256ULL * 1024ULL * 1024ULL);
    CHECK(pieces::format_cpu_max(0.5) == "50000 100000");
}

void test_ipam_log_rotation_and_restart_policies() {
    TempDir tmp("pieces-prod");

    // Flock-backed IPAM lease allocation + release
    write_text_file(
        tmp.path / "c1" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{{"id", "c1"}, {"status", "running"}, {"pid", static_cast<int64_t>(::getpid())}}).dump());
    write_text_file(
        tmp.path / "c2" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{{"id", "c2"}, {"status", "running"}, {"pid", static_cast<int64_t>(::getpid())}}).dump());

    std::string ip1 = pieces::allocate_container_ip(tmp.path.string(), "c1");
    std::string ip2 = pieces::allocate_container_ip(tmp.path.string(), "c2");
    CHECK(ip1 == "10.0.0.2");
    CHECK(ip2 == "10.0.0.3");
    pieces::release_container_ip(tmp.path.string(), "c1");
    CHECK(pieces::allocate_container_ip(tmp.path.string(), "c3") == "10.0.0.2");

    // RotatingLogWriter rotates when crossing max_bytes (min 1024 bytes)
    fs::path log_file = tmp.path / "logs" / "container.log";
    {
        pieces::RotatingLogWriter writer(log_file.string(), 1024, 3);
        std::string chunk(600, 'A');
        writer.write(chunk.data(), chunk.size());
        writer.write(chunk.data(), chunk.size());  // triggers rotation
        std::string chunk2(300, 'B');
        writer.write(chunk2.data(), chunk2.size());
    }
    CHECK(fs::exists(log_file));
    CHECK(fs::exists(log_file.string() + ".1"));
    CHECK(read_text_file(log_file).find('B') != std::string::npos);

    CHECK(pieces::parse_restart_policy("unless-stopped") == pieces::RestartPolicy::UnlessStopped);
    CHECK(pieces::restart_policy_to_string(pieces::RestartPolicy::OnFailure) == "on-failure");

    auto p1 = pieces::parse_port_mapping("8080:80");
    CHECK(pieces::format_port_mapping(p1) == "8080->80/tcp");
}

}  // namespace

int main() {
    test_json_roundtrip();
    test_parser();
    test_cli();
    test_filesystem_security_cache_and_build_run_order();
    test_non_docker_hub_oci_and_sha256_verification();
    test_security_subid_and_cgroup();
    test_ipam_log_rotation_and_restart_policies();
    std::cout << "All 7 production C++ test suites passed.\n";
    return 0;
}

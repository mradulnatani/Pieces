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
    CHECK(spec->env.at("FOO") == "bar");
    CHECK(spec->env.at("BAZ") == "hello world");
    CHECK(spec->env.at("LEGACY") == "legacy value");
    CHECK(spec->workdir == "/app");
    CHECK(spec->copies.size() == 1);
    CHECK(spec->copies[0].first == "./src");
    CHECK(spec->copies[0].second == "/app/src");
    CHECK(spec->runs.size() == 1);
    CHECK(spec->runs[0] == "echo \"step 1\" && echo \"step 2\"");
    CHECK((spec->entrypoint == std::vector<std::string>{"/bin/sh", "-c"}));
    CHECK((spec->cmd == std::vector<std::string>{"echo", "hi there"}));

    fs::path missing_from = tmp.path / "NoFrom";
    write_text_file(missing_from, "CMD /bin/sh\n");
    CHECK(!pieces::parse_piecefile(missing_from.string()).has_value());

    fs::path bad_kw = tmp.path / "BadKw";
    write_text_file(bad_kw, "FROM ubuntu:22.04\nBOGUS foo\n");
    CHECK(!pieces::parse_piecefile(bad_kw.string()).has_value());
}

void test_cli() {
    auto run_args = pieces::parse_command_args({
        "run", "--rm", "-d", "--rootless", "--name", "c1",
        "-p", "8080:80", "-p", "127.0.0.1:5353:53/udp",
        "--memory", "128m", "-e", "A=1", "ubuntu-22.04", "ls", "-la", "/"
    });
    CHECK(run_args.command == pieces::CliCommand::Run);
    CHECK(run_args.auto_remove);
    CHECK(run_args.detach);
    CHECK(run_args.rootless);
    CHECK(run_args.name == "c1");
    CHECK((run_args.port_specs == std::vector<std::string>{"8080:80", "127.0.0.1:5353:53/udp"}));
    CHECK(run_args.memory_limit == "128m");
    CHECK((run_args.env_specs == std::vector<std::string>{"A=1"}));
    CHECK(run_args.image == "ubuntu-22.04");
    CHECK((run_args.cmd_args == std::vector<std::string>{"ls", "-la", "/"}));

    auto pull_args = pieces::parse_command_args({"pull", "python:3.12-alpine", "-t", "py312"});
    CHECK(pull_args.command == pieces::CliCommand::Pull);
    CHECK(pull_args.pull_ref == "python:3.12-alpine");
    CHECK(pull_args.tag == "py312");

    auto stop_args = pieces::parse_command_args({"stop", "-t", "5", "web", "db"});
    CHECK(stop_args.command == pieces::CliCommand::Stop);
    CHECK(stop_args.timeout_sec == 5);
    CHECK((stop_args.containers == std::vector<std::string>{"web", "db"}));

    auto logs_args = pieces::parse_command_args({"logs", "-f", "-n", "25", "web"});
    CHECK(logs_args.command == pieces::CliCommand::Logs);
    CHECK(logs_args.follow);
    CHECK(logs_args.tail_lines == 25);
    CHECK(logs_args.target_container == "web");

    auto exec_args = pieces::parse_command_args({"exec", "-w", "/app", "-e", "DEBUG=1", "web", "sh", "-c", "id"});
    CHECK(exec_args.command == pieces::CliCommand::Exec);
    CHECK(exec_args.workdir == "/app");
    CHECK((exec_args.env_specs == std::vector<std::string>{"DEBUG=1"}));
    CHECK(exec_args.target_container == "web");
    CHECK((exec_args.cmd_args == std::vector<std::string>{"sh", "-c", "id"}));
}

void test_filesystem_security_and_build_run_order() {
    for (const char* bad : {"", ".", "..", "../etc", "a/b", "a\\b", "-bad"}) {
        bool threw = false;
        try {
            (void)pieces::validate_name(bad);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        CHECK(threw);
    }
    CHECK(pieces::validate_name("ubuntu-22.04") == "ubuntu-22.04");

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

    // Create base rootfs tar
    fs::path base_tar = tmp.path / "base.tar.gz";
    create_tar_gz(base_tar, {{"etc/os-release", "ID=alpine\n"}});

    fs::path ctx = tmp.path / "ctx";
    write_text_file(ctx / "app.txt", "hello-app\n");
    fs::path pf = ctx / "Piecefile";
    write_text_file(pf, R"(
FROM_URL https://example.com/base.tar.gz
ENV STAGE=1
WORKDIR /app
COPY app.txt /app/app.txt
RUN cat /app/app.txt > /app/built.txt
CMD ["/bin/sh"]
)");

    auto spec = pieces::parse_piecefile(pf.string());
    CHECK(spec.has_value());

    fs::path img_path = tmp.path / "images" / "my-app";
    std::vector<std::string> seen_runs;
    bool built = pieces::build_image(
        *spec,
        img_path.string(),
        ctx.string(),
        [&](const std::string&, const std::string& dest) {
            fs::copy_file(base_tar, dest, fs::copy_options::overwrite_existing);
        },
        [&](const std::string& rootfs_dir,
            const std::string& cmd,
            const std::map<std::string, std::string>& env,
            const std::string& workdir) -> int {
            seen_runs.push_back(cmd);
            CHECK(env.at("STAGE") == "1");
            CHECK(workdir == "/app");
            // Verify COPY already ran before RUN
            CHECK(read_text_file(fs::path(rootfs_dir) / "app/app.txt") == "hello-app\n");
            write_text_file(fs::path(rootfs_dir) / "app/built.txt", "built-ok\n");
            return 0;
        });
    CHECK(built);
    CHECK(seen_runs.size() == 1);
    CHECK(read_text_file(img_path / "app/built.txt") == "built-ok\n");

    // Failed RUN preserves existing image atomically
    write_text_file(pf, R"(
FROM_URL https://example.com/base.tar.gz
RUN exit 42
)");
    auto bad_spec = pieces::parse_piecefile(pf.string());
    CHECK(bad_spec.has_value());
    bool bad_ok = pieces::build_image(
        *bad_spec,
        img_path.string(),
        ctx.string(),
        [&](const std::string&, const std::string& dest) {
            fs::copy_file(base_tar, dest, fs::copy_options::overwrite_existing);
        },
        [](const std::string&, const std::string&, const std::map<std::string, std::string>&, const std::string&) {
            return 42;
        });
    CHECK(!bad_ok);
    CHECK(read_text_file(img_path / "app/built.txt") == "built-ok\n");
}

void test_oci_registry_and_whiteouts() {
    auto r1 = pieces::parse_image_reference("ubuntu:22.04");
    CHECK(r1.registry == "registry-1.docker.io");
    CHECK(r1.repository == "library/ubuntu");
    CHECK(r1.tag == "22.04");
    CHECK(r1.default_local_name() == "ubuntu-22.04");

    auto r2 = pieces::parse_image_reference("alpine");
    CHECK(r2.registry == "registry-1.docker.io");
    CHECK(r2.repository == "library/alpine");
    CHECK(r2.tag == "latest");

    auto r3 = pieces::parse_image_reference("ghcr.io/org/service:v1.2");
    CHECK(r3.registry == "ghcr.io");
    CHECK(r3.repository == "org/service");
    CHECK(r3.tag == "v1.2");

    auto r4 = pieces::parse_image_reference("localhost:5000/team/api:dev");
    CHECK(r4.registry == "localhost:5000");
    CHECK(r4.repository == "team/api");
    CHECK(r4.tag == "dev");

    auto auth = pieces::parse_www_authenticate(
        "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/alpine:pull\"");
    CHECK(auth.at("realm") == "https://auth.docker.io/token");
    CHECK(auth.at("service") == "registry.docker.io");
    CHECK(auth.at("scope") == "repository:library/alpine:pull");

    // Multi-layer OCI pull simulation with 401 auth, index selection, config, and whiteouts
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

    std::string index_json = R"({
      "manifests": [
        {"digest": "sha256:other", "platform": {"os": "linux", "architecture": "otherarch"}},
        {"digest": "sha256:host", "platform": {"os": "linux", "architecture": ")" + pieces::host_oci_architecture() + R"("}}
      ]
    })";
    std::string manifest_json = R"({
      "config": {"digest": "sha256:cfg"},
      "layers": [
        {"digest": "sha256:l1"},
        {"digest": "sha256:l2"}
      ]
    })";
    std::string config_json = R"({
      "config": {
        "Env": ["PATH=/usr/bin:/bin", "APP=oci"],
        "WorkingDir": "/srv",
        "Cmd": ["/bin/sh", "-c", "echo ok"]
      }
    })";

    auto mock_http = [&](const std::string& url,
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
        if (url.find("/manifests/latest") != std::string::npos) {
            return {200, {}, index_json};
        }
        if (url.find("/manifests/sha256:host") != std::string::npos) {
            return {200, {}, manifest_json};
        }
        if (url.find("/blobs/sha256:cfg") != std::string::npos) {
            return {200, {}, config_json};
        }
        if (url.find("/blobs/sha256:l1") != std::string::npos) {
            fs::copy_file(layer1, save_to_path, fs::copy_options::overwrite_existing);
            return {200, {}, ""};
        }
        if (url.find("/blobs/sha256:l2") != std::string::npos) {
            fs::copy_file(layer2, save_to_path, fs::copy_options::overwrite_existing);
            return {200, {}, ""};
        }
        return {404, {}, ""};
    };

    fs::path pulled_img = tmp.path / "images" / "demo-latest";
    CHECK(pieces::pull_oci_image("demo:latest", pulled_img.string(), mock_http));
    CHECK(read_text_file(pulled_img / "etc/keep.txt") == "keep\n");
    CHECK(!fs::exists(pulled_img / "etc/remove_me.txt"));
    CHECK(!fs::exists(pulled_img / "opt/opaque/old.txt"));
    CHECK(read_text_file(pulled_img / "opt/opaque/new.txt") == "new\n");

    auto meta = pieces::load_image_metadata(pulled_img.string());
    CHECK(meta.at("workdir").as_string() == "/srv");
    CHECK(meta.at("env").as_object().at("APP").as_string() == "oci");
    CHECK(meta.at("cmd").as_array().size() == 3);
}

void test_cgroup_userns_and_ports() {
    CHECK(pieces::parse_memory_limit("256m") == 256ULL * 1024ULL * 1024ULL);
    CHECK(pieces::parse_memory_limit("1G") == 1024ULL * 1024ULL * 1024ULL);
    CHECK(pieces::format_cpu_max(0.5) == "50000 100000");

    TempDir tmp("pieces-cg");
    pieces::CgroupManager mgr("abc123", "64m", std::nullopt, std::nullopt, tmp.path.string());
    CHECK(!mgr.setup(::getpid()));
    mgr.cleanup();

    // User namespace map writer test
    TempDir fake_proc("pieces-userns");
    write_text_file(fake_proc.path / "setgroups", "");
    write_text_file(fake_proc.path / "uid_map", "");
    write_text_file(fake_proc.path / "gid_map", "");
    pieces::write_user_namespace_maps(fake_proc.path.string(), 1000, 1000);
    CHECK(read_text_file(fake_proc.path / "setgroups") == "deny");
    CHECK(read_text_file(fake_proc.path / "uid_map") == "0 1000 1\n");
    CHECK(read_text_file(fake_proc.path / "gid_map") == "0 1000 1\n");

    // Port mapping parser
    auto p1 = pieces::parse_port_mapping("8080:80");
    CHECK(p1.host_ip.empty());
    CHECK(p1.host_port == 8080);
    CHECK(p1.container_port == 80);
    CHECK(p1.protocol == "tcp");
    CHECK(pieces::format_port_mapping(p1) == "8080->80/tcp");

    auto p2 = pieces::parse_port_mapping("127.0.0.1:5353:53/udp");
    CHECK(p2.host_ip == "127.0.0.1");
    CHECK(p2.host_port == 5353);
    CHECK(p2.container_port == 53);
    CHECK(p2.protocol == "udp");
    CHECK(pieces::format_port_mapping(p2) == "127.0.0.1:5353->53/udp");

    bool bad_port = false;
    try {
        (void)pieces::parse_port_mapping("99999:80");
    } catch (const std::invalid_argument&) {
        bad_port = true;
    }
    CHECK(bad_port);
}

void test_network_logs_and_container_helpers() {
    TempDir tmp("pieces-net");
    write_text_file(
        tmp.path / "c1" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{
            {"id", "c1"}, {"status", "running"}, {"pid", static_cast<int64_t>(::getpid())}, {"ip", "10.0.0.2"}
        }).dump());
    write_text_file(
        tmp.path / "c2" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{
            {"id", "c2"}, {"status", "exited"}, {"pid", static_cast<int64_t>(0)}, {"ip", "10.0.0.3"}
        }).dump());
    write_text_file(
        tmp.path / "c3" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{
            {"id", "c3"}, {"status", "running"}, {"pid", static_cast<int64_t>(99999999)}, {"ip", "10.0.0.4"}
        }).dump());

    CHECK(pieces::allocate_container_ip(tmp.path.string()) == "10.0.0.3");
    auto running_only = pieces::list_containers(false, tmp.path.string());
    // c3 has dead PID so list_containers reconciles it to exited
    CHECK(running_only.size() == 1);
    CHECK(running_only[0].at("id").as_string() == "c1");

    // Logs --tail verification
    write_text_file(tmp.path / "c1" / "container.log", "line1\nline2\nline3\n");
    std::ostringstream captured;
    auto* old_buf = std::cout.rdbuf(captured.rdbuf());
    int log_rc = pieces::show_container_logs("c1", false, 2, tmp.path.string());
    std::cout.rdbuf(old_buf);
    CHECK(log_rc == 0);
    CHECK(captured.str() == "line2\nline3\n");

    pieces::JsonObject meta;
    meta["entrypoint"] = pieces::JsonArray{"/bin/sh", "-c"};
    meta["cmd"] = "echo default";
    meta["env"] = pieces::JsonObject{{"APP", "pieces"}};
    CHECK((pieces::resolve_command({}, meta) == std::vector<std::string>{"/bin/sh", "-c", "echo", "default"}));
    CHECK((pieces::resolve_command({"id"}, meta) == std::vector<std::string>{"/bin/sh", "-c", "id"}));

    auto env = pieces::build_container_env(meta, {"EXTRA=42"}, "box1");
    CHECK(env.at("APP") == "pieces");
    CHECK(env.at("EXTRA") == "42");
    CHECK(env.at("HOSTNAME") == "box1");
}

}  // namespace

int main() {
    test_json_roundtrip();
    test_parser();
    test_cli();
    test_filesystem_security_and_build_run_order();
    test_oci_registry_and_whiteouts();
    test_cgroup_userns_and_ports();
    test_network_logs_and_container_helpers();
    std::cout << "All 7 C++ test suites passed.\n";
    return 0;
}

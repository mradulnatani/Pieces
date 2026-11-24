#include <archive.h>
#include <archive_entry.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
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
    auto run_args = pieces::parse_command_args(
        {"run", "--rm", "--name", "c1", "--memory", "128m", "-e", "A=1", "ubuntu-22.04", "ls", "-la", "/"});
    CHECK(run_args.command == pieces::CliCommand::Run);
    CHECK(run_args.auto_remove);
    CHECK(run_args.name == "c1");
    CHECK(run_args.memory_limit == "128m");
    CHECK((run_args.env_specs == std::vector<std::string>{"A=1"}));
    CHECK(run_args.image == "ubuntu-22.04");
    CHECK((run_args.cmd_args == std::vector<std::string>{"ls", "-la", "/"}));

    auto dd_args = pieces::parse_command_args({"run", "ubuntu-22.04", "--", "/bin/sh", "-c", "id"});
    CHECK((dd_args.cmd_args == std::vector<std::string>{"/bin/sh", "-c", "id"}));

    auto build_args = pieces::parse_command_args({"build", ".", "-t", "custom:v1"});
    CHECK(build_args.command == pieces::CliCommand::Build);
    CHECK(build_args.context == ".");
    CHECK(build_args.tag == "custom:v1");
}

void test_filesystem_security_and_build() {
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

    fs::path good_tar = tmp.path / "good.tar.gz";
    create_tar_gz(good_tar, {{"etc/hello.txt", "hello"}});
    fs::path rootfs_out = tmp.path / "rootfs";
    pieces::safe_extract_tar_file(good_tar.string(), rootfs_out.string());
    CHECK(read_text_file(rootfs_out / "etc/hello.txt") == "hello");

    fs::path img_path = tmp.path / "images" / "ubuntu-22.04";
    write_text_file(img_path / "keep.txt", "intact");
    pieces::PiecefileSpec spec;
    spec.from_image = "ubuntu:22.04";
    bool ok = pieces::build_image(
        spec,
        img_path.string(),
        tmp.path.string(),
        [](const std::string&, const std::string&) { throw std::runtime_error("network down"); });
    CHECK(!ok);
    CHECK(read_text_file(img_path / "keep.txt") == "intact");

    fs::path ctx = tmp.path / "ctx";
    write_text_file(ctx / "app.txt", "ok\n");
    pieces::apply_copies({{"app.txt", "/opt/app.txt"}}, ctx.string(), rootfs_out.string());
    CHECK(read_text_file(rootfs_out / "opt/app.txt") == "ok\n");

    bool copy_threw = false;
    try {
        pieces::apply_copies({{"../secret", "/opt/secret"}}, ctx.string(), rootfs_out.string());
    } catch (const std::invalid_argument&) {
        copy_threw = true;
    }
    CHECK(copy_threw);
}

void test_cgroup_and_volumes() {
    CHECK(pieces::parse_memory_limit("256m") == 256ULL * 1024ULL * 1024ULL);
    CHECK(pieces::parse_memory_limit("1G") == 1024ULL * 1024ULL * 1024ULL);
    CHECK(pieces::parse_memory_limit("4096") == 4096ULL);
    CHECK(pieces::format_cpu_max(0.5) == "50000 100000");
    CHECK(pieces::format_cpu_max(2.0) == "200000 100000");

    TempDir tmp("pieces-cg");
    pieces::CgroupManager mgr("abc123", "64m", std::nullopt, std::nullopt, tmp.path.string());
    CHECK(!mgr.setup(::getpid()));
    mgr.cleanup();

    TempDir host_vol("pieces-vol");
    auto vol = pieces::parse_volume_spec(host_vol.path.string() + ":/data:ro");
    CHECK(vol.container_path == "/data");
    CHECK(vol.read_only);
}

void test_network_and_container_helpers() {
    TempDir tmp("pieces-net");
    write_text_file(
        tmp.path / "c1" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{{"status", "running"}, {"ip", "10.0.0.2"}}).dump());
    write_text_file(
        tmp.path / "c2" / "meta.json",
        pieces::JsonValue(pieces::JsonObject{{"status", "exited"}, {"ip", "10.0.0.3"}}).dump());
    CHECK(pieces::allocate_container_ip(tmp.path.string()) == "10.0.0.3");

    pieces::JsonObject meta;
    meta["entrypoint"] = pieces::JsonArray{"/bin/sh", "-c"};
    meta["cmd"] = "echo default";
    meta["env"] = pieces::JsonObject{{"APP", "pieces"}};

    CHECK((pieces::resolve_command({}, meta) == std::vector<std::string>{"/bin/sh", "-c", "echo", "default"}));
    CHECK((pieces::resolve_command({"id"}, meta) == std::vector<std::string>{"/bin/sh", "-c", "id"}));

    pieces::JsonObject legacy_meta;
    legacy_meta["cmd"] = "/bin/sh -c \"hi world\"";
    CHECK((pieces::resolve_command({}, legacy_meta) == std::vector<std::string>{"/bin/sh", "-c", "hi world"}));

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
    test_filesystem_security_and_build();
    test_cgroup_and_volumes();
    test_network_and_container_helpers();
    std::cout << "All 6 C++ test suites passed.\n";
    return 0;
}

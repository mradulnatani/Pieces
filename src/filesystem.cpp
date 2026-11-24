#include "pieces/filesystem.hpp"

#include <archive.h>
#include <archive_entry.h>
#include <curl/curl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include "pieces/namespaces.hpp"
#include "pieces/network.hpp"
#include "pieces/security.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

constexpr const char* DEFAULT_BUILD_PATH =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

bool is_valid_name_char(unsigned char c) {
    return std::isalnum(c) != 0 || c == '.' || c == '_' || c == ':' || c == '-';
}

std::string strip_archive_suffix(const std::string& filename) {
    static const char* kSuffixes[] = {".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar"};
    for (const char* suffix : kSuffixes) {
        std::string sfx(suffix);
        if (filename.size() > sfx.size() &&
            filename.compare(filename.size() - sfx.size(), sfx.size(), sfx) == 0) {
            return filename.substr(0, filename.size() - sfx.size());
        }
    }
    return filename;
}

bool ends_with_archive_suffix(const std::string& filename) {
    static const char* kSuffixes[] = {".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar"};
    for (const char* suffix : kSuffixes) {
        std::string sfx(suffix);
        if (filename.size() >= sfx.size() &&
            filename.compare(filename.size() - sfx.size(), sfx.size(), sfx) == 0) {
            return true;
        }
    }
    return false;
}

bool is_within_dir(const fs::path& base, const fs::path& target) {
    auto rel = target.lexically_relative(base);
    if (rel.empty()) return false;
    auto it = rel.begin();
    return it != rel.end() && *it != "..";
}

std::string normalize_relative_tar_path(const std::string& raw_path) {
    if (raw_path.empty()) throw std::invalid_argument("Tarball contains empty member path");
    if (raw_path[0] == '/') throw std::invalid_argument("Tarball member uses unsafe absolute path: '" + raw_path + "'");
    fs::path norm = fs::path(raw_path).lexically_normal();
    for (const auto& part : norm) {
        if (part == "..") throw std::invalid_argument("Tarball member escapes destination: '" + raw_path + "'");
    }
    std::string result = norm.string();
    while (result.size() > 1 && result.back() == '/') result.pop_back();
    return result.empty() ? "." : result;
}

size_t curl_write_cb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* file = static_cast<FILE*>(userdata);
    return std::fwrite(ptr, size, nmemb, file);
}

int curl_progress_cb(void* /*clientp*/, curl_off_t dltotal, curl_off_t dlnow, curl_off_t, curl_off_t) {
    if (dltotal > 0) {
        double pct = std::min(100.0, (static_cast<double>(dlnow) / static_cast<double>(dltotal)) * 100.0);
        std::cout << "\rBUILD: Downloading... " << std::fixed << std::setprecision(1) << pct << "%" << std::flush;
    } else if (dlnow > 0) {
        double mib = static_cast<double>(dlnow) / (1024.0 * 1024.0);
        std::cout << "\rBUILD: Downloading... " << std::fixed << std::setprecision(2) << mib << " MiB" << std::flush;
    }
    return 0;
}

void default_curl_download(const std::string& url, const std::string& dest_path) {
    static const bool curl_inited = []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        return true;
    }();
    (void)curl_inited;

    FILE* fp = std::fopen(dest_path.c_str(), "wb");
    if (!fp) throw std::runtime_error("Cannot open temporary file for download: " + dest_path);

    CURL* curl = curl_easy_init();
    if (!curl) {
        std::fclose(fp);
        throw std::runtime_error("Failed to initialize libcurl");
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, curl_progress_cb);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    std::fclose(fp);
    std::cout << "\n";

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("Download failed: ") + curl_easy_strerror(res));
    }
}

void configure_container_dns_and_hosts(const fs::path& rootfs_dir, const std::string& hostname) {
    std::error_code ec;
    fs::path etc_dir = rootfs_dir / "etc";
    fs::create_directories(etc_dir, ec);

    fs::path resolv_dst = etc_dir / "resolv.conf";
    fs::path host_resolv("/etc/resolv.conf");
    if (fs::is_regular_file(host_resolv, ec)) {
        if (fs::is_symlink(resolv_dst, ec)) fs::remove(resolv_dst, ec);
        if (!fs::exists(resolv_dst, ec) || fs::file_size(resolv_dst, ec) == 0) {
            fs::copy_file(host_resolv, resolv_dst, fs::copy_options::overwrite_existing, ec);
        }
    }

    fs::path hosts_dst = etc_dir / "hosts";
    if (!fs::exists(hosts_dst, ec)) {
        std::ofstream out(hosts_dst);
        if (out) out << "127.0.0.1\tlocalhost " << hostname << "\n::1\t\tlocalhost\n";
    }
}

int default_run_build_step(
    const std::string& rootfs_dir,
    const std::string& command,
    const std::map<std::string, std::string>& env,
    const std::string& workdir) {
    std::cout << "BUILD: RUN " << command << "\n" << std::flush;
    configure_container_dns_and_hosts(rootfs_dir, "pieces-build");

    bool rootless = (::geteuid() != 0);
    uid_t host_uid = ::getuid();
    gid_t host_gid = ::getgid();

    std::vector<std::string> env_entries;
    std::map<std::string, std::string> merged = {
        {"PATH", DEFAULT_BUILD_PATH},
        {"HOME", "/root"},
        {"TERM", "xterm"},
    };
    for (const auto& [k, v] : env) merged[k] = v;
    env_entries.reserve(merged.size());
    for (const auto& [k, v] : merged) env_entries.push_back(k + "=" + v);

    pid_t pid1 = ::fork();
    if (pid1 < 0) return 1;
    if (pid1 == 0) {
        try {
            int ns_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC;
            if (rootless) ns_flags |= CLONE_NEWUSER;
            unshare_namespaces(ns_flags);
            if (rootless) setup_rootless_user_namespace(::getpid(), host_uid, host_gid);

            pid_t pid2 = ::fork();
            if (pid2 < 0) ::_exit(1);
            if (pid2 == 0) {
                try {
                    setup_container_mounts(rootfs_dir, {}, rootless, false);
                    if (!workdir.empty() && workdir != "/") {
                        fs::create_directories(workdir);
                        if (::chdir(workdir.c_str()) != 0) ::_exit(1);
                    }
                    std::string sh_bin = "/bin/sh";
                    std::string c_flag = "-c";
                    std::string cmd_copy = command;
                    char* argv[] = {sh_bin.data(), c_flag.data(), cmd_copy.data(), nullptr};
                    std::vector<char*> env_ptrs;
                    env_ptrs.reserve(env_entries.size() + 1);
                    for (auto& e : env_entries) env_ptrs.push_back(e.data());
                    env_ptrs.push_back(nullptr);
                    ::execvpe(argv[0], argv, env_ptrs.data());
                    ::_exit(127);
                } catch (const std::exception& exc) {
                    std::cerr << "BUILD RUN ERROR: " << exc.what() << "\n";
                    ::_exit(1);
                }
            } else {
                int st2 = 0;
                ::waitpid(pid2, &st2, 0);
                ::_exit(WIFEXITED(st2) ? WEXITSTATUS(st2) : 1);
            }
        } catch (const std::exception& exc) {
            std::cerr << "BUILD RUN ERROR: " << exc.what() << "\n";
            ::_exit(1);
        }
    }

    int status1 = 0;
    if (::waitpid(pid1, &status1, 0) < 0) return 1;
    return WIFEXITED(status1) ? WEXITSTATUS(status1) : 1;
}

bool handle_oci_whiteout_entry(const fs::path& dest_real, const std::string& rel) {
    fs::path rel_path(rel);
    std::string fname = rel_path.filename().string();
    fs::path parent_rel = rel_path.parent_path();
    fs::path target_dir = parent_rel.empty() ? dest_real : (dest_real / parent_rel);

    if (fname == ".wh..wh..opq") {
        std::error_code ec;
        if (fs::is_directory(target_dir, ec)) {
            for (const auto& item : fs::directory_iterator(target_dir, ec)) fs::remove_all(item.path(), ec);
        }
        return true;
    }
    if (fname.rfind(".wh.", 0) == 0) {
        std::string victim_name = fname.substr(4);
        if (!victim_name.empty() && victim_name != "." && victim_name != "..") {
            std::error_code ec;
            fs::remove_all(target_dir / victim_name, ec);
        }
        return true;
    }
    return false;
}

void fetch_tarball_with_cache(
    const std::string& url,
    const std::string& dest_tar,
    const std::optional<std::string>& expected_sha256,
    const DownloadFn& dl,
    bool no_cache,
    const std::string& cache_dir) {
    std::error_code ec;
    fs::create_directories(cache_dir, ec);
    std::string cache_key = sha256_string(url);
    fs::path cached_file = fs::path(cache_dir) / (cache_key + ".tar");

    if (!no_cache && fs::is_regular_file(cached_file, ec)) {
        bool valid = true;
        if (expected_sha256.has_value()) {
            valid = (sha256_file(cached_file.string()) == *expected_sha256);
        }
        if (valid) {
            std::cout << "BUILD: Using cached tarball (" << cache_key.substr(0, 12) << ")\n";
            fs::copy_file(cached_file, dest_tar, fs::copy_options::overwrite_existing);
            return;
        }
        fs::remove(cached_file, ec);
    }

    std::cout << "BUILD: Downloading from " << url << "...\n";
    dl(url, dest_tar);

    if (expected_sha256.has_value()) {
        std::string actual = sha256_file(dest_tar);
        if (actual != *expected_sha256) {
            throw std::runtime_error(
                "SHA-256 verification failed for '" + url + "': expected " + *expected_sha256 + ", got " + actual);
        }
        std::cout << "BUILD: Verified SHA-256 checksum (" << actual.substr(0, 12) << "...)\n";
    }

    fs::path tmp_cache = fs::path(cache_dir) / (".tmp-" + cache_key + "-" + std::to_string(::getpid()));
    if (fs::copy_file(dest_tar, tmp_cache, fs::copy_options::overwrite_existing, ec)) {
        fs::rename(tmp_cache, cached_file, ec);
        if (ec) fs::remove(tmp_cache, ec);
    }
}

bool wildcard_match(const std::string& pattern, const std::string& text) {
    size_t p = 0, t = 0, star = std::string::npos, match_t = 0;
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == text[t] || pattern[p] == '?')) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            match_t = t;
        } else if (star != std::string::npos) {
            p = star + 1;
            t = ++match_t;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

void copy_tree_respecting_ignore(
    const fs::path& src_root,
    const fs::path& src_cur,
    const fs::path& dst_cur,
    const std::vector<std::string>& ignore_patterns) {
    fs::create_directories(dst_cur);
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(src_cur, ec)) {
        std::string rel = entry.path().lexically_relative(src_root).generic_string();
        if (is_path_ignored(rel, ignore_patterns)) continue;
        fs::path dst = dst_cur / entry.path().filename();
        if (entry.is_symlink(ec)) {
            fs::remove_all(dst, ec);
            fs::create_symlink(fs::read_symlink(entry.path(), ec), dst, ec);
        } else if (entry.is_directory(ec)) {
            copy_tree_respecting_ignore(src_root, entry.path(), dst, ignore_patterns);
        } else if (entry.is_regular_file(ec)) {
            fs::copy_file(entry.path(), dst, fs::copy_options::overwrite_existing, ec);
        }
    }
}

void apply_chown_recursive(const fs::path& target, const std::string& chown_spec) {
    if (chown_spec.empty() || ::geteuid() != 0) return;
    UserSpec us = parse_user_spec(chown_spec);
    std::error_code ec;
    auto chown_one = [&](const fs::path& p) {
        if (::lchown(p.c_str(), us.uid, us.gid) != 0) {
            // Non-fatal fallback if kernel/filesystem denies lchown
        }
    };
    chown_one(target);
    if (fs::is_directory(target, ec)) {
        for (const auto& e : fs::recursive_directory_iterator(target, ec)) {
            chown_one(e.path());
        }
    }
}

std::string fingerprint_source_tree(const fs::path& p, const std::vector<std::string>& ignore_patterns) {
    std::ostringstream oss;
    std::error_code ec;
    if (!fs::exists(p, ec)) return "missing";
    if (fs::is_regular_file(p, ec)) {
        return sha256_file(p.string());
    }
    if (fs::is_directory(p, ec)) {
        std::vector<fs::path> items;
        for (const auto& e : fs::recursive_directory_iterator(p, ec)) {
            std::string rel = e.path().lexically_relative(p).generic_string();
            if (!is_path_ignored(rel, ignore_patterns)) items.push_back(e.path());
        }
        std::sort(items.begin(), items.end());
        for (const auto& item : items) {
            oss << item.lexically_relative(p).generic_string() << ":";
            if (fs::is_regular_file(item, ec)) oss << sha256_file(item.string());
            oss << "\n";
        }
        return sha256_string(oss.str());
    }
    return "other";
}

std::string normalize_local_image_ref(const std::string& ref) {
    std::string raw = ref;
    std::replace(raw.begin(), raw.end(), ':', '-');
    std::replace(raw.begin(), raw.end(), '/', '-');
    return raw;
}

void copy_directory_contents(const fs::path& src, const fs::path& dst) {
    std::error_code ec;
    fs::create_directories(dst);
    fs::copy(src, dst, fs::copy_options::recursive | fs::copy_options::copy_symlinks | fs::copy_options::overwrite_existing, ec);
    if (ec) {
        throw std::runtime_error("Failed copying directory tree from '" + src.string() + "': " + ec.message());
    }
}

void snapshot_stage_layer(const fs::path& staging_dir, const fs::path& layer_dir) {
    std::error_code ec;
    fs::path parent = layer_dir.parent_path();
    fs::create_directories(parent, ec);
    fs::path tmp = parent / (layer_dir.filename().string() + ".tmp." + std::to_string(::getpid()));
    fs::remove_all(tmp, ec);
    copy_directory_contents(staging_dir, tmp);
    std::ofstream done(tmp / ".layer_ready");
    done << "1\n";
    done.close();
    fs::remove_all(layer_dir, ec);
    fs::rename(tmp, layer_dir, ec);
}

bool restore_stage_layer(const fs::path& layer_dir, const fs::path& staging_dir) {
    std::error_code ec;
    if (!fs::is_regular_file(layer_dir / ".layer_ready", ec)) return false;
    fs::remove_all(staging_dir, ec);
    copy_directory_contents(layer_dir, staging_dir);
    fs::remove(staging_dir / ".layer_ready", ec);
    return true;
}

}  // namespace

const std::map<std::string, std::string>& known_images() {
    static const std::map<std::string, std::string> kImages = {
        {"alpine:3.18", "https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.3-x86_64.tar.gz"},
        {"fedora:38", "https://archives.fedoraproject.org/pub/fedora/linux/releases/38/Container/x86_64/images/Fedora-Container-Base-38-1.6.x86_64.tar.gz"},
        {"ubuntu:22.04", "https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.4-base-amd64.tar.gz"},
    };
    return kImages;
}

std::string validate_name(const std::string& name, const std::string& kind) {
    if (name.empty() || name == "." || name == "..") {
        throw std::invalid_argument("Invalid " + kind + " name: '" + name + "'");
    }
    if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos ||
        name.find('\0') != std::string::npos) {
        throw std::invalid_argument("Invalid " + kind + " name '" + name + "': path separators are not allowed");
    }
    if (name.size() > 128 || !std::isalnum(static_cast<unsigned char>(name[0])) ||
        !std::all_of(name.begin(), name.end(), [](unsigned char c) { return is_valid_name_char(c); })) {
        throw std::invalid_argument(
            "Invalid " + kind + " name '" + name +
            "': must start with an alphanumeric character and contain only [A-Za-z0-9._:-]");
    }
    return name;
}

std::string derive_image_name(const PiecefileSpec& spec, const std::string& tag) {
    std::string raw;
    if (!tag.empty()) {
        raw = tag;
    } else if (spec.from_image.has_value()) {
        if (known_images().contains(*spec.from_image)) {
            raw = *spec.from_image;
        } else {
            try {
                raw = parse_image_reference(*spec.from_image).default_local_name();
            } catch (const std::exception&) {
                raw = *spec.from_image;
            }
        }
    } else if (spec.from_url.has_value()) {
        std::string url = *spec.from_url;
        auto qpos = url.find_first_of("?#");
        if (qpos != std::string::npos) url = url.substr(0, qpos);
        auto slash = url.find_last_of('/');
        std::string base = (slash == std::string::npos) ? url : url.substr(slash + 1);
        raw = strip_archive_suffix(base);
    } else {
        throw std::invalid_argument("Piecefile must define FROM or FROM_URL.");
    }

    std::replace(raw.begin(), raw.end(), ':', '-');
    std::replace(raw.begin(), raw.end(), '/', '-');
    return validate_name(raw, "image");
}

std::string resolve_image_path(const std::string& image_name, const std::string& image_dir) {
    std::string safe = validate_name(image_name, "image");
    std::error_code ec;
    fs::path base_real = fs::weakly_canonical(fs::absolute(image_dir), ec);
    fs::path target = fs::weakly_canonical(base_real / safe, ec);
    if (!is_within_dir(base_real, target)) {
        throw std::invalid_argument("Unsafe image path resolved for '" + image_name + "'");
    }
    return target.string();
}

std::vector<std::string> load_ignore_patterns(const std::string& context_dir) {
    std::vector<std::string> patterns;
    for (const char* fname : {".piecesignore", ".dockerignore"}) {
        fs::path p = fs::path(context_dir) / fname;
        std::error_code ec;
        if (!fs::is_regular_file(p, ec)) continue;
        std::ifstream in(p);
        std::string line;
        while (std::getline(in, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) line.pop_back();
            size_t b = 0;
            while (b < line.size() && std::isspace(static_cast<unsigned char>(line[b]))) ++b;
            line = line.substr(b);
            if (line.empty() || line[0] == '#') continue;
            if (line.rfind("./", 0) == 0) line = line.substr(2);
            while (line.size() > 1 && line.back() == '/') line.pop_back();
            patterns.push_back(line);
        }
        break;
    }
    return patterns;
}

bool is_path_ignored(const std::string& rel_path, const std::vector<std::string>& patterns) {
    if (patterns.empty() || rel_path.empty()) return false;
    std::string clean = rel_path;
    if (clean.rfind("./", 0) == 0) clean = clean.substr(2);
    fs::path p(clean);
    std::string fname = p.filename().string();
    for (const auto& pat : patterns) {
        if (wildcard_match(pat, clean) || wildcard_match(pat, fname)) return true;
        if (clean.rfind(pat + "/", 0) == 0) return true;
    }
    return false;
}

void safe_extract_tar_file(
    const std::string& tar_path,
    const std::string& dest_dir,
    bool handle_oci_whiteouts) {
    fs::create_directories(dest_dir);
    fs::path dest_real = fs::weakly_canonical(fs::absolute(dest_dir));

    struct ArchiveGuard {
        archive* a{nullptr};
        ~ArchiveGuard() {
            if (a) {
                archive_read_close(a);
                archive_read_free(a);
            }
        }
    } reader{archive_read_new()};

    struct DiskGuard {
        archive* ext{nullptr};
        ~DiskGuard() {
            if (ext) {
                archive_write_close(ext);
                archive_write_free(ext);
            }
        }
    } writer{archive_write_disk_new()};

    if (!reader.a || !writer.ext) throw std::runtime_error("Failed to allocate libarchive handles");

    archive_read_support_format_all(reader.a);
    archive_read_support_filter_all(reader.a);

    int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL |
                ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_SECURE_NODOTDOT;
    if (::geteuid() == 0) flags |= ARCHIVE_EXTRACT_OWNER;
    archive_write_disk_set_options(writer.ext, flags);
    archive_write_disk_set_standard_lookup(writer.ext);

    if (archive_read_open_filename(reader.a, tar_path.c_str(), 10240) != ARCHIVE_OK) {
        throw std::runtime_error(std::string("Failed to open archive: ") + archive_error_string(reader.a));
    }

    archive_entry* entry = nullptr;
    while (true) {
        int r = archive_read_next_header(reader.a, &entry);
        if (r == ARCHIVE_EOF) break;
        if (r < ARCHIVE_OK) {
            const char* err = archive_error_string(reader.a);
            throw std::runtime_error(std::string("Tarball read error: ") + (err ? err : "unknown"));
        }

        const char* raw_name = archive_entry_pathname(entry);
        std::string rel = normalize_relative_tar_path(raw_name ? raw_name : "");

        if (handle_oci_whiteouts && handle_oci_whiteout_entry(dest_real, rel)) {
            archive_read_data_skip(reader.a);
            continue;
        }

        fs::path full_dest = (rel == ".") ? dest_real : (dest_real / rel);
        archive_entry_set_pathname(entry, full_dest.c_str());

        if (const char* hardlink = archive_entry_hardlink(entry)) {
            std::string link_rel = normalize_relative_tar_path(hardlink);
            fs::path link_dest = (link_rel == ".") ? dest_real : (dest_real / link_rel);
            archive_entry_set_hardlink(entry, link_dest.c_str());
        }

        r = archive_write_header(writer.ext, entry);
        if (r < ARCHIVE_OK) {
            const char* err = archive_error_string(writer.ext);
            throw std::runtime_error(std::string("Tarball header write error: ") + (err ? err : "unknown"));
        }

        if (archive_entry_size(entry) > 0) {
            const void* buff = nullptr;
            size_t size = 0;
            la_int64_t offset = 0;
            while (true) {
                int dr = archive_read_data_block(reader.a, &buff, &size, &offset);
                if (dr == ARCHIVE_EOF) break;
                if (dr < ARCHIVE_OK) {
                    const char* err = archive_error_string(reader.a);
                    throw std::runtime_error(std::string("Tarball data read error: ") + (err ? err : "unknown"));
                }
                if (archive_write_data_block(writer.ext, buff, size, offset) < ARCHIVE_OK) {
                    const char* err = archive_error_string(writer.ext);
                    throw std::runtime_error(std::string("Tarball data write error: ") + (err ? err : "unknown"));
                }
            }
        }

        if (archive_write_finish_entry(writer.ext) < ARCHIVE_OK) {
            const char* err = archive_error_string(writer.ext);
            throw std::runtime_error(std::string("Tarball finish entry error: ") + (err ? err : "unknown"));
        }
    }
}

void apply_copies(
    const std::vector<std::pair<std::string, std::string>>& copies,
    const std::string& context_dir,
    const std::string& rootfs_dir,
    const std::vector<std::string>& ignore_patterns) {
    fs::path context_real = fs::weakly_canonical(fs::absolute(context_dir));
    fs::path rootfs_real = fs::weakly_canonical(fs::absolute(rootfs_dir));

    for (const auto& [src_rel, dst_rel] : copies) {
        fs::path src_path = fs::weakly_canonical(context_real / src_rel);
        if (!is_within_dir(context_real, src_path) && src_path != context_real) {
            throw std::invalid_argument("COPY source escapes build context: '" + src_rel + "'");
        }
        if (!fs::exists(src_path)) {
            throw std::runtime_error("COPY source not found: '" + src_path.string() + "'");
        }

        std::string clean_dst = dst_rel;
        while (!clean_dst.empty() && clean_dst.front() == '/') clean_dst.erase(clean_dst.begin());
        fs::path dst_path = fs::weakly_canonical(rootfs_real / clean_dst);
        if (!is_within_dir(rootfs_real, dst_path) && dst_path != rootfs_real) {
            throw std::invalid_argument("COPY destination escapes rootfs: '" + dst_rel + "'");
        }

        if (fs::is_directory(src_path)) {
            copy_tree_respecting_ignore(src_path, src_path, dst_path, ignore_patterns);
        } else {
            std::string rel = src_path.lexically_relative(context_real).generic_string();
            if (is_path_ignored(rel, ignore_patterns)) continue;
            if ((!dst_rel.empty() && dst_rel.back() == '/') || fs::is_directory(dst_path)) {
                fs::create_directories(dst_path);
                fs::copy_file(src_path, dst_path / src_path.filename(), fs::copy_options::overwrite_existing);
            } else {
                fs::create_directories(dst_path.parent_path());
                fs::copy_file(src_path, dst_path, fs::copy_options::overwrite_existing);
            }
        }
    }
}

bool build_image(
    const PiecefileSpec& spec,
    const std::string& image_path,
    const std::string& context_dir,
    const DownloadFn& downloader,
    const RunStepFn& run_step_fn,
    const HttpGetFn& registry_http_get,
    bool no_cache,
    const std::string& cache_dir,
    const std::map<std::string, std::string>& build_args,
    const std::string& image_dir) {
    fs::path abs_image = fs::absolute(image_path);
    fs::path parent_dir = abs_image.parent_path();
    fs::create_directories(parent_dir);
    fs::path effective_img_dir = image_dir.empty() ? parent_dir : fs::absolute(image_dir);
    fs::path layer_cache_root = fs::path(cache_dir) / "layers";

    std::string pid_str = std::to_string(::getpid());
    fs::path tmp_tar = parent_dir / (".download-" + pid_str + ".tar");
    std::vector<fs::path> created_stage_dirs;

    auto cleanup_temp = [&]() {
        std::error_code ec;
        fs::remove(tmp_tar, ec);
        for (const auto& d : created_stage_dirs) fs::remove_all(d, ec);
    };

    try {
        DownloadFn dl = downloader ? downloader : DownloadFn(default_curl_download);
        RunStepFn exec_run = run_step_fn ? run_step_fn : RunStepFn(default_run_build_step);
        auto ignore_patterns = load_ignore_patterns(context_dir);

        std::vector<PiecefileStage> stages = spec.stages;
        if (stages.empty()) {
            PiecefileStage single;
            single.from_image = spec.from_image;
            single.from_url = spec.from_url;
            single.sha256 = spec.sha256;
            single.instructions = spec.instructions;
            stages.push_back(std::move(single));
        }

        std::map<std::string, fs::path> stage_roots;
        std::map<std::string, std::string> global_vars = spec.args;
        for (const auto& [k, v] : build_args) global_vars[k] = v;

        fs::path final_staging_dir;
        JsonObject final_meta;

        for (size_t s_idx = 0; s_idx < stages.size(); ++s_idx) {
            const auto& st = stages[s_idx];
            fs::path staging_dir = parent_dir / (".staging-" + abs_image.filename().string() + ".s" +
                                                 std::to_string(s_idx) + "." + pid_str);
            std::error_code ec;
            fs::remove_all(staging_dir, ec);
            created_stage_dirs.push_back(staging_dir);

            std::string base_id;
            if (st.from_url.has_value()) {
                std::string url = expand_variables(*st.from_url, global_vars);
                if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) {
                    throw std::invalid_argument("Unsupported URL scheme in '" + url + "'. Use http or https.");
                }
                fs::create_directories(staging_dir);
                fetch_tarball_with_cache(url, tmp_tar.string(), st.sha256, dl, no_cache, cache_dir);
                std::cout << "BUILD: Unpacking base rootfs...\n";
                safe_extract_tar_file(tmp_tar.string(), staging_dir.string());
                fs::remove(tmp_tar, ec);
                base_id = url + ":" + st.sha256.value_or("");
            } else if (st.from_image.has_value()) {
                std::string from_ref = expand_variables(*st.from_image, global_vars);
                base_id = from_ref;
                auto it = known_images().find(from_ref);
                if (it != known_images().end() && !registry_http_get) {
                    fs::create_directories(staging_dir);
                    fetch_tarball_with_cache(it->second, tmp_tar.string(), st.sha256, dl, no_cache, cache_dir);
                    std::cout << "BUILD: Unpacking base rootfs...\n";
                    safe_extract_tar_file(tmp_tar.string(), staging_dir.string());
                    fs::remove(tmp_tar, ec);
                } else {
                    std::string local_cand = normalize_local_image_ref(from_ref);
                    fs::path local_path = effective_img_dir / local_cand;
                    if (!registry_http_get && fs::is_regular_file(local_path / ".pieces_meta.json", ec)) {
                        std::cout << "BUILD: Using local base image '" << local_cand << "'...\n";
                        copy_directory_contents(local_path, staging_dir);
                    } else if (!pull_oci_image(from_ref, staging_dir.string(), registry_http_get)) {
                        throw std::runtime_error("Failed to pull base image '" + from_ref + "'");
                    }
                }
            } else {
                throw std::invalid_argument("Stage has neither FROM nor FROM_URL.");
            }

            JsonObject runtime_meta;
            std::map<std::string, std::string> build_env;
            std::map<std::string, std::string> stage_vars = global_vars;
            std::string build_workdir = "/";
            std::optional<std::string> build_user;

            fs::path base_meta_path = staging_dir / ".pieces_meta.json";
            if (fs::is_regular_file(base_meta_path, ec)) {
                std::ifstream in(base_meta_path);
                if (in) {
                    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                    try {
                        JsonValue parsed = JsonValue::parse(content);
                        if (parsed.is_object()) {
                            runtime_meta = parsed.as_object();
                            if (auto env_v = parsed.find("env"); env_v && env_v->is_object()) {
                                for (const auto& [k, v] : env_v->as_object()) {
                                    if (v.is_string()) {
                                        build_env[k] = v.as_string();
                                        stage_vars[k] = v.as_string();
                                    }
                                }
                            }
                            if (auto wd_v = parsed.find("workdir"); wd_v && wd_v->is_string()) {
                                build_workdir = wd_v->as_string();
                            }
                            if (auto usr_v = parsed.find("user"); usr_v && usr_v->is_string()) {
                                build_user = usr_v->as_string();
                            }
                        }
                    } catch (const std::exception&) {
                    }
                }
            }

            std::string chain_hash = sha256_string("stage_base:" + base_id);
            bool cache_broken = no_cache;

            if (!st.instructions.empty()) {
                for (const auto& inst : st.instructions) {
                    std::string expanded = expand_variables(inst.value, stage_vars);
                    if (inst.keyword == "ARG") {
                        auto eq = expanded.find('=');
                        std::string k = (eq == std::string::npos) ? expanded : expanded.substr(0, eq);
                        std::string def_v = (eq == std::string::npos) ? "" : expanded.substr(eq + 1);
                        if (auto bi = build_args.find(k); bi != build_args.end()) stage_vars[k] = bi->second;
                        else if (!def_v.empty() || !stage_vars.contains(k)) stage_vars[k] = def_v;
                        chain_hash = sha256_string(chain_hash + "|ARG|" + k + "=" + stage_vars[k]);
                    } else if (inst.keyword == "ENV") {
                        auto tokens = split_shell_words(expanded);
                        if (!tokens.empty() && tokens[0].find('=') != std::string::npos) {
                            for (const auto& tok : tokens) {
                                auto eq = tok.find('=');
                                if (eq != std::string::npos && eq > 0) {
                                    std::string k = tok.substr(0, eq);
                                    std::string v = tok.substr(eq + 1);
                                    build_env[k] = v;
                                    stage_vars[k] = v;
                                }
                            }
                        } else if (tokens.size() >= 2) {
                            auto ws = expanded.find_first_of(" \t");
                            if (ws != std::string::npos) {
                                build_env[tokens[0]] = expanded.substr(ws + 1);
                                stage_vars[tokens[0]] = build_env[tokens[0]];
                            }
                        }
                        chain_hash = sha256_string(chain_hash + "|ENV|" + expanded);
                    } else if (inst.keyword == "WORKDIR") {
                        build_workdir = expanded;
                        std::string clean = build_workdir;
                        while (!clean.empty() && clean.front() == '/') clean.erase(clean.begin());
                        if (!clean.empty()) fs::create_directories(staging_dir / clean);
                        chain_hash = sha256_string(chain_hash + "|WORKDIR|" + expanded);
                    } else if (inst.keyword == "USER") {
                        build_user = expanded;
                        chain_hash = sha256_string(chain_hash + "|USER|" + expanded);
                    } else if (inst.keyword == "COPY") {
                        CopySpec cs = parse_copy_or_add_args(expanded, true);
                        fs::path src_base = fs::path(context_dir);
                        std::string effective_src = cs.src;
                        if (cs.from_stage.has_value()) {
                            auto fit = stage_roots.find(*cs.from_stage);
                            if (fit == stage_roots.end()) {
                                throw std::invalid_argument("COPY --from references unknown stage '" + *cs.from_stage + "'");
                            }
                            src_base = fit->second;
                            while (!effective_src.empty() && effective_src.front() == '/') {
                                effective_src.erase(effective_src.begin());
                            }
                            if (effective_src.empty()) effective_src = ".";
                        }
                        fs::path src_fp_path = fs::weakly_canonical(src_base / effective_src);
                        std::string fp = fingerprint_source_tree(src_fp_path, cs.from_stage.has_value() ? std::vector<std::string>{} : ignore_patterns);
                        chain_hash = sha256_string(chain_hash + "|COPY|" + effective_src + "->" + cs.dst + "|" + fp);
                        fs::path cache_dir_step = layer_cache_root / chain_hash;
                        if (!cache_broken && restore_stage_layer(cache_dir_step, staging_dir)) {
                            std::cout << "BUILD: Using cached COPY layer (" << chain_hash.substr(0, 12) << ")\n";
                        } else {
                            cache_broken = true;
                            apply_copies(
                                {{effective_src, cs.dst}},
                                src_base.string(),
                                staging_dir.string(),
                                cs.from_stage.has_value() ? std::vector<std::string>{} : ignore_patterns);
                            if (cs.chown.has_value()) {
                                std::string cdst = cs.dst;
                                while (!cdst.empty() && cdst.front() == '/') cdst.erase(cdst.begin());
                                apply_chown_recursive(staging_dir / cdst, *cs.chown);
                            }
                            snapshot_stage_layer(staging_dir, cache_dir_step);
                        }
                    } else if (inst.keyword == "ADD") {
                        CopySpec cs = parse_copy_or_add_args(expanded, false);
                        chain_hash = sha256_string(chain_hash + "|ADD|" + expanded);
                        if (cs.src.rfind("http://", 0) == 0 || cs.src.rfind("https://", 0) == 0) {
                            fetch_tarball_with_cache(cs.src, tmp_tar.string(), std::nullopt, dl, no_cache, cache_dir);
                            std::string cdst = cs.dst;
                            while (!cdst.empty() && cdst.front() == '/') cdst.erase(cdst.begin());
                            fs::path dst_p = staging_dir / cdst;
                            if (ends_with_archive_suffix(cs.src)) {
                                safe_extract_tar_file(tmp_tar.string(), dst_p.string());
                            } else {
                                if (!cs.dst.empty() && cs.dst.back() == '/') {
                                    fs::create_directories(dst_p);
                                    dst_p /= fs::path(cs.src).filename();
                                } else {
                                    fs::create_directories(dst_p.parent_path());
                                }
                                fs::copy_file(tmp_tar, dst_p, fs::copy_options::overwrite_existing);
                            }
                            fs::remove(tmp_tar, ec);
                            if (cs.chown.has_value()) apply_chown_recursive(dst_p, *cs.chown);
                        } else {
                            fs::path src_local = fs::weakly_canonical(fs::path(context_dir) / cs.src);
                            if (fs::is_regular_file(src_local, ec) && ends_with_archive_suffix(src_local.filename().string())) {
                                std::string cdst = cs.dst;
                                while (!cdst.empty() && cdst.front() == '/') cdst.erase(cdst.begin());
                                safe_extract_tar_file(src_local.string(), (staging_dir / cdst).string());
                            } else {
                                apply_copies({{cs.src, cs.dst}}, context_dir, staging_dir.string(), ignore_patterns);
                            }
                            if (cs.chown.has_value()) {
                                std::string cdst = cs.dst;
                                while (!cdst.empty() && cdst.front() == '/') cdst.erase(cdst.begin());
                                apply_chown_recursive(staging_dir / cdst, *cs.chown);
                            }
                        }
                    } else if (inst.keyword == "RUN") {
                        chain_hash = sha256_string(chain_hash + "|RUN|" + expanded + "|" + build_workdir);
                        fs::path cache_dir_step = layer_cache_root / chain_hash;
                        if (!cache_broken && !run_step_fn && restore_stage_layer(cache_dir_step, staging_dir)) {
                            std::cout << "BUILD: Using cached RUN layer (" << chain_hash.substr(0, 12) << ")\n";
                        } else {
                            cache_broken = true;
                            int rc = exec_run(staging_dir.string(), expanded, build_env, build_workdir);
                            if (rc != 0) {
                                throw std::runtime_error(
                                    "RUN command '" + expanded + "' exited with code " + std::to_string(rc));
                            }
                            if (!run_step_fn) snapshot_stage_layer(staging_dir, cache_dir_step);
                        }
                    }
                }
            } else if (!spec.copies.empty() && stages.size() == 1) {
                apply_copies(spec.copies, context_dir, staging_dir.string(), ignore_patterns);
            }

            stage_roots[std::to_string(s_idx)] = staging_dir;
            if (!st.alias.empty()) stage_roots[st.alias] = staging_dir;

            if (s_idx + 1 == stages.size()) {
                for (const auto& [k, v] : spec.env) build_env[k] = v;
                if (!build_env.empty()) {
                    JsonObject env_obj;
                    for (const auto& [k, v] : build_env) env_obj[k] = v;
                    runtime_meta["env"] = std::move(env_obj);
                }
                if (!spec.labels.empty()) {
                    JsonObject lbl_obj;
                    for (const auto& [k, v] : spec.labels) lbl_obj[k] = v;
                    runtime_meta["labels"] = std::move(lbl_obj);
                }
                if (!spec.exposed_ports.empty()) {
                    JsonArray arr;
                    for (const auto& p : spec.exposed_ports) arr.emplace_back(p);
                    runtime_meta["exposed_ports"] = std::move(arr);
                }
                if (!spec.volumes.empty()) {
                    JsonArray arr;
                    for (const auto& v : spec.volumes) arr.emplace_back(v);
                    runtime_meta["volumes"] = std::move(arr);
                }
                if (spec.workdir.has_value()) runtime_meta["workdir"] = *spec.workdir;
                if (build_user.has_value()) runtime_meta["user"] = *build_user;
                else if (spec.user.has_value()) runtime_meta["user"] = *spec.user;
                if (spec.cmd.has_value()) {
                    JsonArray arr;
                    for (const auto& item : *spec.cmd) arr.emplace_back(item);
                    runtime_meta["cmd"] = std::move(arr);
                }
                if (spec.entrypoint.has_value()) {
                    JsonArray arr;
                    for (const auto& item : *spec.entrypoint) arr.emplace_back(item);
                    runtime_meta["entrypoint"] = std::move(arr);
                }
                final_meta = runtime_meta;
                final_staging_dir = staging_dir;
            }
        }

        std::ofstream meta_out(final_staging_dir / ".pieces_meta.json");
        if (!meta_out) throw std::runtime_error("Failed to write .pieces_meta.json");
        meta_out << JsonValue(final_meta).dump(2) << "\n";
        meta_out.close();
        configure_container_dns_and_hosts(final_staging_dir, "pieces");

        std::error_code ec;
        fs::path backup_dir = parent_dir / (abs_image.filename().string() + ".old." + pid_str);
        fs::remove_all(backup_dir, ec);
        bool had_existing = fs::exists(abs_image, ec);
        if (had_existing) fs::rename(abs_image, backup_dir);
        try {
            fs::rename(final_staging_dir, abs_image);
        } catch (...) {
            if (had_existing && fs::exists(backup_dir, ec) && !fs::exists(abs_image, ec)) {
                fs::rename(backup_dir, abs_image, ec);
            }
            throw;
        }
        if (had_existing) fs::remove_all(backup_dir, ec);

        cleanup_temp();
        std::cout << "BUILD: Image built successfully at " << image_path << "\n";
        return true;
    } catch (const std::exception& exc) {
        std::cerr << "\nBUILD: Image build failed: " << exc.what() << "\n";
        cleanup_temp();
        return false;
    }
}

std::vector<ImageInfo> list_images(const std::string& image_dir) {
    std::vector<ImageInfo> result;
    std::error_code ec;
    if (!fs::is_directory(image_dir, ec)) return result;

    std::vector<fs::directory_entry> entries;
    for (const auto& entry : fs::directory_iterator(image_dir, ec)) entries.push_back(entry);
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return a.path().filename().string() < b.path().filename().string();
    });

    for (const auto& entry : entries) {
        if (!entry.is_directory(ec)) continue;
        fs::path meta_path = entry.path() / ".pieces_meta.json";
        if (!fs::is_regular_file(meta_path, ec)) continue;
        ImageInfo info;
        info.name = entry.path().filename().string();
        info.path = entry.path().string();
        std::ifstream in(meta_path);
        if (in) {
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            try {
                JsonValue parsed = JsonValue::parse(content);
                if (parsed.is_object()) info.meta = parsed.as_object();
            } catch (const std::exception&) {
            }
        }
        result.push_back(std::move(info));
    }
    return result;
}

void remove_image(const std::string& image_name, const std::string& image_dir) {
    std::string target = resolve_image_path(image_name, image_dir);
    if (!fs::is_directory(target)) throw std::runtime_error("Image '" + image_name + "' not found");
    fs::remove_all(target);
}

void tag_image(const std::string& src_image, const std::string& dst_image, const std::string& image_dir) {
    std::string src_path = resolve_image_path(normalize_local_image_ref(src_image), image_dir);
    if (!fs::is_directory(src_path)) {
        src_path = resolve_image_path(src_image, image_dir);
    }
    if (!fs::is_directory(src_path)) {
        throw std::runtime_error("Source image '" + src_image + "' not found");
    }
    std::string dst_norm = normalize_local_image_ref(dst_image);
    std::string dst_path = resolve_image_path(dst_norm, image_dir);
    if (src_path == dst_path) return;
    fs::path tmp = fs::path(dst_path + ".tmp." + std::to_string(::getpid()));
    std::error_code ec;
    fs::remove_all(tmp, ec);
    copy_directory_contents(src_path, tmp);
    fs::remove_all(dst_path, ec);
    fs::rename(tmp, dst_path);
}

JsonObject inspect_image_json(const std::string& image_name, const std::string& image_dir) {
    std::string path = resolve_image_path(normalize_local_image_ref(image_name), image_dir);
    if (!fs::is_directory(path)) path = resolve_image_path(image_name, image_dir);
    if (!fs::is_directory(path)) throw std::runtime_error("Image '" + image_name + "' not found");

    JsonObject out;
    out["name"] = fs::path(path).filename().string();
    out["path"] = fs::absolute(path).string();
    fs::path meta_path = fs::path(path) / ".pieces_meta.json";
    if (fs::is_regular_file(meta_path)) {
        std::ifstream in(meta_path);
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        try {
            out["config"] = JsonValue::parse(content);
        } catch (const std::exception&) {
            out["config"] = JsonObject{};
        }
    }
    return out;
}

int prune_unused_data(const std::string& containers_dir, const std::string& cache_dir) {
    int removed = 0;
    std::error_code ec;
    if (fs::is_directory(containers_dir, ec)) {
        for (const auto& entry : fs::directory_iterator(containers_dir, ec)) {
            if (!entry.is_directory(ec)) continue;
            fs::path meta_path = entry.path() / "meta.json";
            bool is_running = false;
            if (fs::is_regular_file(meta_path, ec)) {
                std::ifstream in(meta_path);
                if (in) {
                    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                    try {
                        JsonValue v = JsonValue::parse(s);
                        if (const JsonValue* st = v.find("status"); st && st->is_string() && st->as_string() == "running") {
                            if (const JsonValue* pid_v = v.find("pid"); pid_v && pid_v->is_int() && pid_v->as_int() > 0) {
                                int pid = static_cast<int>(pid_v->as_int());
                                if (::kill(pid, 0) == 0 || errno == EPERM) is_running = true;
                            }
                        }
                    } catch (const std::exception&) {
                    }
                }
            }
            if (!is_running) {
                cleanup_container_rootfs(entry.path().string(), "overlay");
                fs::remove_all(entry.path(), ec);
                ++removed;
            }
        }
    }
    if (fs::is_directory(cache_dir, ec)) {
        for (const auto& entry : fs::directory_iterator(cache_dir, ec)) {
            fs::remove_all(entry.path(), ec);
            ++removed;
        }
    }
    return removed;
}

void create_volume(const std::string& name, const std::string& volumes_dir) {
    std::string safe = validate_name(name, "volume");
    fs::path vdir = fs::path(volumes_dir) / safe;
    fs::create_directories(vdir / "_data");
    fs::path meta = vdir / "volume.json";
    if (!fs::exists(meta)) {
        JsonObject obj;
        obj["name"] = safe;
        obj["mountpoint"] = fs::absolute(vdir / "_data").string();
        obj["driver"] = "local";
        std::ofstream out(meta);
        out << JsonValue(obj).dump(2) << "\n";
    }
}

std::vector<JsonObject> list_volumes(const std::string& volumes_dir) {
    std::vector<JsonObject> res;
    std::error_code ec;
    if (!fs::is_directory(volumes_dir, ec)) return res;
    for (const auto& e : fs::directory_iterator(volumes_dir, ec)) {
        if (!e.is_directory(ec)) continue;
        JsonObject obj;
        obj["name"] = e.path().filename().string();
        obj["mountpoint"] = fs::absolute(e.path() / "_data").string();
        obj["driver"] = "local";
        res.push_back(std::move(obj));
    }
    std::sort(res.begin(), res.end(), [](const JsonObject& a, const JsonObject& b) {
        return a.at("name").as_string() < b.at("name").as_string();
    });
    return res;
}

JsonObject inspect_volume_json(const std::string& name, const std::string& volumes_dir) {
    std::string safe = validate_name(name, "volume");
    fs::path vdir = fs::path(volumes_dir) / safe;
    if (!fs::is_directory(vdir)) throw std::runtime_error("Volume '" + name + "' not found");
    JsonObject obj;
    obj["name"] = safe;
    obj["mountpoint"] = fs::absolute(vdir / "_data").string();
    obj["driver"] = "local";
    return obj;
}

void remove_volume(const std::string& name, const std::string& volumes_dir) {
    std::string safe = validate_name(name, "volume");
    fs::path vdir = fs::path(volumes_dir) / safe;
    if (!fs::is_directory(vdir)) throw std::runtime_error("Volume '" + name + "' not found");
    fs::remove_all(vdir);
}

std::string resolve_volume_host_path(const std::string& host_or_volume_name, const std::string& volumes_dir) {
    bool is_path = (!host_or_volume_name.empty() &&
                    (host_or_volume_name[0] == '/' || host_or_volume_name[0] == '.' ||
                     host_or_volume_name.find('/') != std::string::npos));
    if (is_path) {
        return fs::absolute(host_or_volume_name).string();
    }
    create_volume(host_or_volume_name, volumes_dir);
    return fs::absolute(fs::path(volumes_dir) / validate_name(host_or_volume_name, "volume") / "_data").string();
}

RootfsSetup prepare_container_rootfs(
    const std::string& image_path,
    const std::string& container_dir,
    const std::string& /*hostname*/,
    bool readonly_rootfs,
    bool ephemeral_ram) {
    std::string abs_image = fs::absolute(image_path).string();
    if (readonly_rootfs) return {abs_image, "", "", "readonly-bind"};

    fs::path scratch_base = container_dir;
    if (ephemeral_ram && fs::is_directory("/dev/shm")) {
        scratch_base = fs::path("/dev/shm/.pieces-run") / fs::path(container_dir).filename();
    }

    fs::path upper_dir = fs::absolute(scratch_base / "upper");
    fs::path work_dir = fs::absolute(scratch_base / "work");
    fs::path merged_dir = fs::absolute(scratch_base / "rootfs");
    fs::create_directories(upper_dir);
    fs::create_directories(work_dir);
    fs::create_directories(merged_dir);
    return {merged_dir.string(), upper_dir.string(), work_dir.string(), "in-ns-overlay"};
}

void cleanup_container_rootfs(const std::string& container_dir, const std::string& method) {
    if (method == "readonly-bind") return;
    fs::path cdir(container_dir);
    fs::path ram_dir = fs::path("/dev/shm/.pieces-run") / cdir.filename();
    std::error_code ec;
    fs::path target_base = fs::exists(ram_dir, ec) ? ram_dir : cdir;
    fs::path merged_dir = target_base / "rootfs";
    if (fs::exists(merged_dir, ec)) {
        if (method == "overlay") ::umount2(merged_dir.c_str(), MNT_DETACH);
        else if (method == "fuse-overlay") {
            if (run_host_cmd({"fusermount3", "-u", "-z", merged_dir.string()}, true) != 0) {
                run_host_cmd({"fusermount", "-u", "-z", merged_dir.string()}, true);
            }
        }
    }
    if (target_base == ram_dir) fs::remove_all(ram_dir, ec);
}

}  // namespace pieces

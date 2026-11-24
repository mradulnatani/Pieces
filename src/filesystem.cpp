#include "pieces/filesystem.hpp"

#include <archive.h>
#include <archive_entry.h>
#include <curl/curl.h>
#include <sys/mount.h>
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
#include <regex>
#include <stdexcept>
#include <system_error>

namespace fs = std::filesystem;

namespace pieces {

namespace {

const std::regex& valid_name_regex() {
    static const std::regex kRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
    return kRegex;
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

bool is_within_dir(const fs::path& base, const fs::path& target) {
    auto rel = target.lexically_relative(base);
    if (rel.empty()) {
        return false;
    }
    auto it = rel.begin();
    return it != rel.end() && *it != "..";
}

std::string normalize_relative_tar_path(const std::string& raw_path) {
    if (raw_path.empty()) {
        throw std::invalid_argument("Tarball contains empty member path");
    }
    if (raw_path[0] == '/') {
        throw std::invalid_argument("Tarball member uses unsafe absolute path: '" + raw_path + "'");
    }
    fs::path norm = fs::path(raw_path).lexically_normal();
    for (const auto& part : norm) {
        if (part == "..") {
            throw std::invalid_argument("Tarball member escapes destination: '" + raw_path + "'");
        }
    }
    std::string result = norm.string();
    while (result.size() > 1 && result.back() == '/') {
        result.pop_back();
    }
    if (result.empty()) {
        return ".";
    }
    return result;
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
    if (!fp) {
        throw std::runtime_error("Cannot open temporary file for download: " + dest_path);
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        std::fclose(fp);
        throw std::runtime_error("Failed to initialize libcurl");
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
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
        if (fs::is_symlink(resolv_dst, ec)) {
            fs::remove(resolv_dst, ec);
        }
        if (!fs::exists(resolv_dst, ec) || fs::file_size(resolv_dst, ec) == 0) {
            fs::copy_file(host_resolv, resolv_dst, fs::copy_options::overwrite_existing, ec);
        }
    }

    fs::path hosts_dst = etc_dir / "hosts";
    if (!fs::exists(hosts_dst, ec)) {
        std::ofstream out(hosts_dst);
        if (out) {
            out << "127.0.0.1\tlocalhost " << hostname << "\n::1\t\tlocalhost\n";
        }
    }
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
    if (!std::regex_match(name, valid_name_regex())) {
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
        raw = *spec.from_image;
    } else if (spec.from_url.has_value()) {
        std::string url = *spec.from_url;
        auto qpos = url.find_first_of("?#");
        if (qpos != std::string::npos) {
            url = url.substr(0, qpos);
        }
        auto slash = url.find_last_of('/');
        std::string base = (slash == std::string::npos) ? url : url.substr(slash + 1);
        raw = strip_archive_suffix(base);
    } else {
        throw std::invalid_argument("Piecefile must define FROM or FROM_URL.");
    }

    std::replace(raw.begin(), raw.end(), ':', '-');
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

void safe_extract_tar_file(const std::string& tar_path, const std::string& dest_dir) {
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

    if (!reader.a || !writer.ext) {
        throw std::runtime_error("Failed to allocate libarchive handles");
    }

    archive_read_support_format_all(reader.a);
    archive_read_support_filter_all(reader.a);

    int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL |
                ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_SECURE_NODOTDOT;
    if (::geteuid() == 0) {
        flags |= ARCHIVE_EXTRACT_OWNER;
    }
    archive_write_disk_set_options(writer.ext, flags);
    archive_write_disk_set_standard_lookup(writer.ext);

    if (archive_read_open_filename(reader.a, tar_path.c_str(), 10240) != ARCHIVE_OK) {
        throw std::runtime_error(std::string("Failed to open archive: ") + archive_error_string(reader.a));
    }

    archive_entry* entry = nullptr;
    while (true) {
        int r = archive_read_next_header(reader.a, &entry);
        if (r == ARCHIVE_EOF) {
            break;
        }
        if (r < ARCHIVE_OK) {
            const char* err = archive_error_string(reader.a);
            throw std::runtime_error(std::string("Tarball read error: ") + (err ? err : "unknown"));
        }

        const char* raw_name = archive_entry_pathname(entry);
        std::string rel = normalize_relative_tar_path(raw_name ? raw_name : "");
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
                if (dr == ARCHIVE_EOF) {
                    break;
                }
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
    const std::string& rootfs_dir) {
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
        while (!clean_dst.empty() && clean_dst.front() == '/') {
            clean_dst.erase(clean_dst.begin());
        }
        fs::path dst_path = fs::weakly_canonical(rootfs_real / clean_dst);
        if (!is_within_dir(rootfs_real, dst_path) && dst_path != rootfs_real) {
            throw std::invalid_argument("COPY destination escapes rootfs: '" + dst_rel + "'");
        }

        if (fs::is_directory(src_path)) {
            fs::create_directories(dst_path);
            fs::copy(
                src_path,
                dst_path,
                fs::copy_options::recursive | fs::copy_options::copy_symlinks | fs::copy_options::overwrite_existing);
        } else {
            if ((!dst_rel.empty() && dst_rel.back() == '/') || fs::is_directory(dst_path)) {
                fs::create_directories(dst_path);
                fs::copy_file(
                    src_path,
                    dst_path / src_path.filename(),
                    fs::copy_options::overwrite_existing);
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
    const DownloadFn& downloader) {
    std::string url;
    if (spec.from_image.has_value()) {
        auto it = known_images().find(*spec.from_image);
        if (it == known_images().end()) {
            std::cerr << "BUILD: Error: Unknown image tag '" << *spec.from_image << "'.\n";
            return false;
        }
        url = it->second;
    } else if (spec.from_url.has_value()) {
        url = *spec.from_url;
        if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) {
            std::cerr << "BUILD: Error: Unsupported URL scheme in '" << url << "'. Use http or https.\n";
            return false;
        }
    } else {
        std::cerr << "BUILD: Error: Piecefile has neither FROM nor FROM_URL.\n";
        return false;
    }

    fs::path abs_image = fs::absolute(image_path);
    fs::path parent_dir = abs_image.parent_path();
    fs::create_directories(parent_dir);

    std::string pid_str = std::to_string(::getpid());
    fs::path staging_dir = parent_dir / (".staging-" + abs_image.filename().string() + "." + pid_str);
    fs::path tmp_tar = parent_dir / (".download-" + pid_str + ".tar");
    std::error_code ec;
    fs::remove_all(staging_dir, ec);
    fs::remove(tmp_tar, ec);
    fs::create_directories(staging_dir);

    try {
        std::cout << "BUILD: Downloading from " << url << "...\n";
        DownloadFn dl = downloader ? downloader : DownloadFn(default_curl_download);
        dl(url, tmp_tar.string());

        std::cout << "BUILD: Download complete. Unpacking to " << image_path << "...\n";
        safe_extract_tar_file(tmp_tar.string(), staging_dir.string());
        fs::remove(tmp_tar, ec);

        if (!spec.copies.empty()) {
            apply_copies(spec.copies, context_dir, staging_dir.string());
        }

        if (!spec.runs.empty()) {
            std::cerr << "BUILD: Warning: RUN instructions in Piecefile are recorded but build-time "
                         "execution is not enabled yet; skipping RUN steps.\n";
        }

        fs::path meta_path = staging_dir / ".pieces_meta.json";
        std::ofstream meta_out(meta_path);
        if (!meta_out) {
            throw std::runtime_error("Failed to write .pieces_meta.json");
        }
        meta_out << JsonValue(spec.to_metadata()).dump(2) << "\n";
        meta_out.close();

        fs::path backup_dir = parent_dir / (abs_image.filename().string() + ".old." + pid_str);
        fs::remove_all(backup_dir, ec);
        bool had_existing = fs::exists(abs_image, ec);
        if (had_existing) {
            fs::rename(abs_image, backup_dir);
        }
        try {
            fs::rename(staging_dir, abs_image);
        } catch (...) {
            if (had_existing && fs::exists(backup_dir, ec) && !fs::exists(abs_image, ec)) {
                fs::rename(backup_dir, abs_image, ec);
            }
            throw;
        }
        if (had_existing) {
            fs::remove_all(backup_dir, ec);
        }

        std::cout << "BUILD: Image built successfully at " << image_path << "\n";
        return true;
    } catch (const std::exception& exc) {
        std::cerr << "\nBUILD: Image build failed: " << exc.what() << "\n";
        fs::remove(tmp_tar, ec);
        fs::remove_all(staging_dir, ec);
        return false;
    }
}

std::vector<ImageInfo> list_images(const std::string& image_dir) {
    std::vector<ImageInfo> result;
    std::error_code ec;
    if (!fs::is_directory(image_dir, ec)) {
        return result;
    }

    std::vector<fs::directory_entry> entries;
    for (const auto& entry : fs::directory_iterator(image_dir, ec)) {
        entries.push_back(entry);
    }
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return a.path().filename().string() < b.path().filename().string();
    });

    for (const auto& entry : entries) {
        if (!entry.is_directory(ec)) {
            continue;
        }
        fs::path meta_path = entry.path() / ".pieces_meta.json";
        if (!fs::is_regular_file(meta_path, ec)) {
            continue;
        }
        ImageInfo info;
        info.name = entry.path().filename().string();
        info.path = entry.path().string();
        std::ifstream in(meta_path);
        if (in) {
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            try {
                JsonValue parsed = JsonValue::parse(content);
                if (parsed.is_object()) {
                    info.meta = parsed.as_object();
                }
            } catch (const std::exception&) {
            }
        }
        result.push_back(std::move(info));
    }
    return result;
}

void remove_image(const std::string& image_name, const std::string& image_dir) {
    std::string target = resolve_image_path(image_name, image_dir);
    if (!fs::is_directory(target)) {
        throw std::runtime_error("Image '" + image_name + "' not found");
    }
    fs::remove_all(target);
}

RootfsSetup prepare_container_rootfs(
    const std::string& image_path,
    const std::string& container_dir,
    const std::string& hostname) {
    fs::path cdir(container_dir);
    fs::path upper_dir = cdir / "upper";
    fs::path work_dir = cdir / "work";
    fs::path merged_dir = cdir / "rootfs";
    fs::create_directories(upper_dir);
    fs::create_directories(work_dir);
    fs::create_directories(merged_dir);

    std::string opts = "lowerdir=" + fs::absolute(image_path).string() +
                       ",upperdir=" + fs::absolute(upper_dir).string() +
                       ",workdir=" + fs::absolute(work_dir).string();

    if (::mount("overlay", merged_dir.c_str(), "overlay", 0, opts.c_str()) == 0) {
        configure_container_dns_and_hosts(merged_dir, hostname);
        return {merged_dir.string(), "overlay"};
    }

    std::error_code ec;
    fs::remove_all(merged_dir, ec);
    fs::copy(
        image_path,
        merged_dir,
        fs::copy_options::recursive | fs::copy_options::copy_symlinks | fs::copy_options::overwrite_existing);
    configure_container_dns_and_hosts(merged_dir, hostname);
    return {merged_dir.string(), "copy"};
}

void cleanup_container_rootfs(const std::string& container_dir, const std::string& method) {
    if (method == "overlay") {
        fs::path merged_dir = fs::path(container_dir) / "rootfs";
        if (fs::exists(merged_dir)) {
            ::umount2(merged_dir.c_str(), MNT_DETACH);
        }
    }
}

}  // namespace pieces

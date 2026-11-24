#pragma once

#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "pieces/json.hpp"
#include "pieces/parser.hpp"
#include "pieces/registry.hpp"

namespace pieces {

inline constexpr const char* PIECES_DIR = ".pieces";
inline constexpr const char* IMAGE_DIR = ".pieces/images";
inline constexpr const char* CONTAINERS_DIR = ".pieces/containers";
inline constexpr const char* CACHE_DIR = ".pieces/cache";
inline constexpr const char* VOLUMES_DIR = ".pieces/volumes";
inline constexpr const char* NETWORKS_DIR = ".pieces/networks";

struct ImageInfo {
    std::string name;
    std::string path;
    JsonObject meta;
};

struct RootfsSetup {
    std::string rootfs_dir;
    std::string upper_dir;
    std::string work_dir;
    std::string method;  // "readonly-bind", "in-ns-overlay", "overlay", "copy"
};

using DownloadFn = std::function<void(const std::string& url, const std::string& dest_path)>;
using RunStepFn = std::function<int(
    const std::string& rootfs_dir,
    const std::string& command,
    const std::map<std::string, std::string>& env,
    const std::string& workdir)>;

[[nodiscard]] const std::map<std::string, std::string>& known_images();
[[nodiscard]] std::string validate_name(const std::string& name, const std::string& kind = "image");
[[nodiscard]] std::string derive_image_name(const PiecefileSpec& spec, const std::string& tag = "");
[[nodiscard]] std::string resolve_image_path(const std::string& image_name, const std::string& image_dir = IMAGE_DIR);
[[nodiscard]] std::vector<std::string> load_ignore_patterns(const std::string& context_dir);
[[nodiscard]] bool is_path_ignored(const std::string& rel_path, const std::vector<std::string>& patterns);

void safe_extract_tar_file(
    const std::string& tar_path,
    const std::string& dest_dir,
    bool handle_oci_whiteouts = false);
void apply_copies(
    const std::vector<std::pair<std::string, std::string>>& copies,
    const std::string& context_dir,
    const std::string& rootfs_dir,
    const std::vector<std::string>& ignore_patterns = {});

[[nodiscard]] bool build_image(
    const PiecefileSpec& spec,
    const std::string& image_path,
    const std::string& context_dir = ".",
    const DownloadFn& downloader = nullptr,
    const RunStepFn& run_step_fn = nullptr,
    const HttpGetFn& registry_http_get = nullptr,
    bool no_cache = false,
    const std::string& cache_dir = CACHE_DIR,
    const std::map<std::string, std::string>& build_args = {},
    const std::string& image_dir = "");

[[nodiscard]] std::vector<ImageInfo> list_images(const std::string& image_dir = IMAGE_DIR);
void remove_image(const std::string& image_name, const std::string& image_dir = IMAGE_DIR);
void tag_image(const std::string& src_image, const std::string& dst_image, const std::string& image_dir = IMAGE_DIR);
[[nodiscard]] JsonObject inspect_image_json(const std::string& image_name, const std::string& image_dir = IMAGE_DIR);
int prune_unused_data(const std::string& containers_dir = CONTAINERS_DIR, const std::string& cache_dir = CACHE_DIR);

// Named volumes
void create_volume(const std::string& name, const std::string& volumes_dir = VOLUMES_DIR);
[[nodiscard]] std::vector<JsonObject> list_volumes(const std::string& volumes_dir = VOLUMES_DIR);
[[nodiscard]] JsonObject inspect_volume_json(const std::string& name, const std::string& volumes_dir = VOLUMES_DIR);
void remove_volume(const std::string& name, const std::string& volumes_dir = VOLUMES_DIR);
[[nodiscard]] std::string resolve_volume_host_path(
    const std::string& host_or_volume_name,
    const std::string& volumes_dir = VOLUMES_DIR);

[[nodiscard]] RootfsSetup prepare_container_rootfs(
    const std::string& image_path,
    const std::string& container_dir,
    const std::string& hostname,
    bool readonly_rootfs = false,
    bool ephemeral_ram = false);
void cleanup_container_rootfs(const std::string& container_dir, const std::string& method);

}  // namespace pieces

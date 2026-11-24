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

struct ImageInfo {
    std::string name;
    std::string path;
    JsonObject meta;
};

struct RootfsSetup {
    std::string rootfs_dir;
    std::string method;  // "overlay" or "copy"
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

void safe_extract_tar_file(
    const std::string& tar_path,
    const std::string& dest_dir,
    bool handle_oci_whiteouts = false);
void apply_copies(
    const std::vector<std::pair<std::string, std::string>>& copies,
    const std::string& context_dir,
    const std::string& rootfs_dir);

[[nodiscard]] bool build_image(
    const PiecefileSpec& spec,
    const std::string& image_path,
    const std::string& context_dir = ".",
    const DownloadFn& downloader = nullptr,
    const RunStepFn& run_step_fn = nullptr,
    const HttpGetFn& registry_http_get = nullptr);

[[nodiscard]] std::vector<ImageInfo> list_images(const std::string& image_dir = IMAGE_DIR);
void remove_image(const std::string& image_name, const std::string& image_dir = IMAGE_DIR);

[[nodiscard]] RootfsSetup prepare_container_rootfs(
    const std::string& image_path,
    const std::string& container_dir,
    const std::string& hostname);
void cleanup_container_rootfs(const std::string& container_dir, const std::string& method);

}  // namespace pieces

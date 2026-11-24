#pragma once

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "pieces/json.hpp"

namespace pieces {

struct ImageReference {
    std::string registry;
    std::string repository;
    std::string tag;

    [[nodiscard]] std::string default_local_name() const;
};

struct HttpResponse {
    long status_code{0};
    std::map<std::string, std::string> headers;  // lower-cased header keys
    std::string body;
};

using HttpGetFn = std::function<HttpResponse(
    const std::string& url,
    const std::vector<std::string>& headers,
    const std::string& save_to_path)>;

[[nodiscard]] std::string sha256_string(const std::string& data);
[[nodiscard]] std::string sha256_file(const std::string& path);

[[nodiscard]] bool is_docker_hub_registry(const std::string& registry);
[[nodiscard]] ImageReference parse_image_reference(const std::string& ref);
[[nodiscard]] std::map<std::string, std::string> parse_www_authenticate(const std::string& header_value);
[[nodiscard]] std::string host_oci_architecture();
[[nodiscard]] std::optional<std::string> select_manifest_digest(
    const JsonValue& index_doc,
    const std::string& target_os,
    const std::string& target_arch);
[[nodiscard]] JsonObject extract_oci_config_metadata(const JsonValue& config_doc);

bool pull_oci_image(
    const std::string& image_ref,
    const std::string& dest_image_path,
    const HttpGetFn& http_get = nullptr);

}  // namespace pieces

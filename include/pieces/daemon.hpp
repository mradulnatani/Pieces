#pragma once

#include <string>

#include "pieces/filesystem.hpp"

namespace pieces {

struct HttpApiResponse {
    int status_code{200};
    std::string content_type{"application/json"};
    std::string body;
};

[[nodiscard]] HttpApiResponse handle_docker_api_request(
    const std::string& method,
    const std::string& target,
    const std::string& body = "",
    const std::string& image_dir = IMAGE_DIR,
    const std::string& containers_dir = CONTAINERS_DIR,
    const std::string& volumes_dir = VOLUMES_DIR,
    const std::string& networks_dir = NETWORKS_DIR);

int run_docker_api_server(
    const std::string& socket_path = "/run/pieces/docker.sock",
    const std::string& image_dir = IMAGE_DIR,
    const std::string& containers_dir = CONTAINERS_DIR,
    const std::string& volumes_dir = VOLUMES_DIR,
    const std::string& networks_dir = NETWORKS_DIR);

}  // namespace pieces

#include "pieces/daemon.hpp"

#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include "pieces/container.hpp"
#include "pieces/filesystem.hpp"
#include "pieces/json.hpp"
#include "pieces/network.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

volatile sig_atomic_t g_serve_stop = 0;

void handle_serve_sig(int) {
    g_serve_stop = 1;
}

std::string strip_api_version(const std::string& raw_target) {
    std::string path = raw_target;
    if (auto q = path.find('?'); q != std::string::npos) path = path.substr(0, q);
    // Strip leading /v1.xx prefix if present
    if (path.size() > 3 && path.rfind("/v1.", 0) == 0) {
        auto next_slash = path.find('/', 2);
        if (next_slash != std::string::npos) {
            return path.substr(next_slash);
        }
    }
    return path;
}

std::string reason_phrase(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 409: return "Conflict";
        default: return "Internal Server Error";
    }
}

}  // namespace

HttpApiResponse handle_docker_api_request(
    const std::string& method,
    const std::string& raw_target,
    const std::string& body,
    const std::string& image_dir,
    const std::string& containers_dir,
    const std::string& volumes_dir,
    const std::string& networks_dir) {
    std::string path = strip_api_version(raw_target);

    try {
        if (method == "GET" && path == "/_ping") {
            return {200, "text/plain", "OK"};
        }
        if (method == "GET" && path == "/version") {
            JsonObject ver{
                {"Version", "1.0.0-pieces"},
                {"ApiVersion", "1.43"},
                {"Os", "linux"},
                {"Arch", host_oci_architecture()},
            };
            return {200, "application/json", JsonValue(ver).dump(2)};
        }
        if (method == "GET" && path == "/info") {
            JsonObject info{
                {"Name", "pieces"},
                {"Driver", "in-ns-overlay"},
                {"CgroupDriver", "systemd/cgroupfs"},
                {"CgroupVersion", "2"},
                {"Containers", static_cast<int64_t>(list_containers(true, containers_dir).size())},
                {"Images", static_cast<int64_t>(list_images(image_dir).size())},
            };
            return {200, "application/json", JsonValue(info).dump(2)};
        }
        if (method == "GET" && path == "/images/json") {
            JsonArray arr;
            for (const auto& img : list_images(image_dir)) {
                arr.emplace_back(JsonObject{
                    {"Id", img.name},
                    {"RepoTags", JsonArray{img.name}},
                    {"Path", img.path},
                });
            }
            return {200, "application/json", JsonValue(arr).dump(2)};
        }
        if (method == "GET" && path == "/containers/json") {
            bool all = (raw_target.find("all=1") != std::string::npos || raw_target.find("all=true") != std::string::npos);
            JsonArray arr;
            for (const auto& c : list_containers(all, containers_dir)) arr.emplace_back(c);
            return {200, "application/json", JsonValue(arr).dump(2)};
        }
        if (method == "GET" && path == "/volumes") {
            JsonArray arr;
            for (const auto& v : list_volumes(volumes_dir)) arr.emplace_back(v);
            return {200, "application/json", JsonValue(JsonObject{{"Volumes", std::move(arr)}}).dump(2)};
        }
        if (method == "GET" && path == "/networks") {
            JsonArray arr;
            for (const auto& n : list_networks(networks_dir)) arr.emplace_back(n);
            return {200, "application/json", JsonValue(arr).dump(2)};
        }
        if (method == "POST" && path == "/containers/create") {
            JsonValue req = JsonValue::parse(body.empty() ? "{}" : body);
            const auto* img_v = req.find("Image");
            if (!img_v || !img_v->is_string() || img_v->as_string().empty()) {
                return {400, "application/json", R"({"message":"Image is required"})"};
            }
            ContainerRunConfig cfg;
            cfg.image = img_v->as_string();
            cfg.detach = true;
            cfg.image_dir = image_dir;
            cfg.containers_dir = containers_dir;
            cfg.volumes_dir = volumes_dir;
            cfg.networks_dir = networks_dir;
            if (const auto* cmd = req.find("Cmd"); cmd && cmd->is_array()) {
                for (const auto& item : cmd->as_array()) {
                    if (item.is_string()) cfg.cmd_args.push_back(item.as_string());
                }
            }
            if (const auto* env = req.find("Env"); env && env->is_array()) {
                for (const auto& item : env->as_array()) {
                    if (item.is_string()) cfg.env_specs.push_back(item.as_string());
                }
            }
            auto q = raw_target.find("name=");
            if (q != std::string::npos) {
                auto end_q = raw_target.find('&', q + 5);
                cfg.name = raw_target.substr(q + 5, end_q == std::string::npos ? std::string::npos : end_q - (q + 5));
            }
            int rc = run_container(cfg);
            if (rc != 0) return {500, "application/json", R"({"message":"Container launch failed"})"};
            auto list = list_containers(true, containers_dir);
            std::string cid = list.empty() ? "" : list.front().at("id").as_string();
            return {201, "application/json", JsonValue(JsonObject{{"Id", cid}}).dump(0)};
        }

        // /containers/{id}/...
        if (path.rfind("/containers/", 0) == 0) {
            std::string rest = path.substr(12);
            auto sl = rest.find('/');
            std::string cid = (sl == std::string::npos) ? rest : rest.substr(0, sl);
            std::string sub = (sl == std::string::npos) ? "" : rest.substr(sl);

            if (method == "GET" && sub == "/json") {
                return {200, "application/json", JsonValue(inspect_container_json(cid, containers_dir)).dump(2)};
            }
            if (method == "POST" && sub == "/stop") {
                stop_container(cid, 10, containers_dir);
                return {204, "application/json", ""};
            }
            if (method == "POST" && sub == "/start") {
                return {204, "application/json", ""};
            }
            if (method == "DELETE" && sub.empty()) {
                bool force = raw_target.find("force=1") != std::string::npos || raw_target.find("force=true") != std::string::npos;
                remove_container(cid, force, containers_dir);
                return {204, "application/json", ""};
            }
        }

        return {404, "application/json", R"({"message":"Endpoint not implemented"})"};
    } catch (const std::exception& exc) {
        return {400, "application/json", JsonValue(JsonObject{{"message", exc.what()}}).dump(0)};
    }
}

int run_docker_api_server(
    const std::string& socket_path,
    const std::string& image_dir,
    const std::string& containers_dir,
    const std::string& volumes_dir,
    const std::string& networks_dir) {
    ::signal(SIGPIPE, SIG_IGN);
    ::signal(SIGINT, handle_serve_sig);
    ::signal(SIGTERM, handle_serve_sig);

    fs::path sock_p(socket_path);
    fs::create_directories(sock_p.parent_path());
    std::error_code ec;
    fs::remove(sock_p, ec);

    int srv = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv < 0) throw std::system_error(errno, std::generic_category(), "socket(AF_UNIX)");

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        ::close(srv);
        throw std::invalid_argument("Socket path too long: " + socket_path);
    }
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(srv, 16) != 0) {
        int err = errno;
        ::close(srv);
        throw std::system_error(err, std::generic_category(), "bind/listen(" + socket_path + ")");
    }
    ::chmod(socket_path.c_str(), 0660);
    std::cout << "SERVE: Listening for Docker REST API requests on unix://" << socket_path << "\n" << std::flush;

    while (!g_serve_stop) {
        int cli = ::accept(srv, nullptr, nullptr);
        if (cli < 0) {
            if (errno == EINTR) continue;
            break;
        }

        std::string req;
        char buf[4096];
        size_t hdr_end = std::string::npos;
        while (req.size() < 65536) {
            ssize_t n = ::read(cli, buf, sizeof(buf));
            if (n <= 0) break;
            req.append(buf, static_cast<size_t>(n));
            hdr_end = req.find("\r\n\r\n");
            if (hdr_end != std::string::npos) break;
        }

        if (hdr_end != std::string::npos) {
            std::istringstream hss(req.substr(0, hdr_end));
            std::string req_line;
            std::getline(hss, req_line);
            if (!req_line.empty() && req_line.back() == '\r') req_line.pop_back();
            std::istringstream lss(req_line);
            std::string method, target;
            lss >> method >> target;

            size_t content_len = 0;
            std::string hdr;
            while (std::getline(hss, hdr)) {
                auto colon = hdr.find(':');
                if (colon == std::string::npos) continue;
                std::string k = hdr.substr(0, colon);
                for (char& c : k) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (k == "content-length") content_len = std::stoul(hdr.substr(colon + 1));
            }
            std::string req_body = req.substr(hdr_end + 4);
            while (req_body.size() < content_len) {
                ssize_t n = ::read(cli, buf, sizeof(buf));
                if (n <= 0) break;
                req_body.append(buf, static_cast<size_t>(n));
            }
            if (req_body.size() > content_len) req_body.resize(content_len);

            HttpApiResponse api_resp = handle_docker_api_request(
                method, target, req_body, image_dir, containers_dir, volumes_dir, networks_dir);

            std::ostringstream out;
            out << "HTTP/1.1 " << api_resp.status_code << " " << reason_phrase(api_resp.status_code) << "\r\n"
                << "Content-Type: " << api_resp.content_type << "\r\n"
                << "Content-Length: " << api_resp.body.size() << "\r\n"
                << "Connection: close\r\n\r\n"
                << api_resp.body;
            std::string payload = out.str();
            size_t off = 0;
            while (off < payload.size()) {
                ssize_t w = ::write(cli, payload.data() + off, payload.size() - off);
                if (w <= 0) break;
                off += static_cast<size_t>(w);
            }
        }
        ::close(cli);
    }

    ::close(srv);
    fs::remove(sock_p, ec);
    return 0;
}

}  // namespace pieces

#include "pieces/compose.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>

#include "pieces/container.hpp"
#include "pieces/network.hpp"
#include "pieces/parser.hpp"
#include "pieces/registry.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

std::string trim_yaml(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string strip_quotes(std::string s) {
    s = trim_yaml(s);
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

std::string strip_inline_comment(const std::string& line) {
    bool in_single = false;
    bool in_double = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '\'' && !in_double) in_single = !in_single;
        else if (c == '"' && !in_single) in_double = !in_double;
        else if (c == '#' && !in_single && !in_double && (i == 0 || std::isspace(static_cast<unsigned char>(line[i - 1])))) {
            return line.substr(0, i);
        }
    }
    return line;
}

std::vector<std::string> parse_inline_list(const std::string& val) {
    std::vector<std::string> out;
    std::string inner = trim_yaml(val);
    if (inner.size() >= 2 && inner.front() == '[' && inner.back() == ']') {
        inner = inner.substr(1, inner.size() - 2);
    }
    std::string cur;
    bool in_q = false;
    char qchar = 0;
    for (char c : inner) {
        if (!in_q && (c == '"' || c == '\'')) {
            in_q = true;
            qchar = c;
        } else if (in_q && c == qchar) {
            in_q = false;
        } else if (!in_q && c == ',') {
            std::string item = strip_quotes(cur);
            if (!item.empty()) out.push_back(item);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    std::string last = strip_quotes(cur);
    if (!last.empty()) out.push_back(last);
    return out;
}

std::string default_service_container_name(const ComposeProject& proj, const ComposeService& svc) {
    if (!svc.container_name.empty()) return svc.container_name;
    return proj.project_name + "-" + svc.name;
}

}  // namespace

std::string resolve_compose_file(const std::string& explicit_path, const std::string& dir) {
    if (!explicit_path.empty()) return explicit_path;
    for (const char* name : {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}) {
        fs::path cand = fs::path(dir) / name;
        if (fs::exists(cand)) return cand.string();
    }
    return (fs::path(dir) / "compose.yaml").string();
}

ComposeProject parse_compose_yaml(const std::string& content, const std::string& project_name) {
    ComposeProject proj;
    proj.project_name = project_name.empty() ? "pieces" : project_name;

    std::istringstream in(content);
    std::string raw_line;
    std::string section;       // "services", "networks", "volumes"
    std::string cur_key;       // list or nested map key under a service
    std::string sub_section;   // "build" / "deploy" etc.
    ComposeService* cur_svc = nullptr;
    int svc_indent = -1;
    int key_indent = -1;

    while (std::getline(in, raw_line)) {
        std::string line = strip_inline_comment(raw_line);
        std::string trimmed = trim_yaml(line);
        if (trimmed.empty()) continue;

        int indent = 0;
        while (indent < static_cast<int>(line.size()) && line[static_cast<size_t>(indent)] == ' ') ++indent;

        if (indent == 0) {
            cur_svc = nullptr;
            cur_key.clear();
            sub_section.clear();
            svc_indent = -1;
            key_indent = -1;
            auto colon = trimmed.find(':');
            if (colon != std::string::npos) {
                section = trimmed.substr(0, colon);
            }
            continue;
        }

        if (section == "networks") {
            if (trimmed[0] != '-' && trimmed.back() == ':') {
                proj.networks.push_back(trimmed.substr(0, trimmed.size() - 1));
            }
            continue;
        }
        if (section == "volumes") {
            if (trimmed[0] != '-' && trimmed.back() == ':') {
                proj.volumes.push_back(trimmed.substr(0, trimmed.size() - 1));
            }
            continue;
        }
        if (section != "services") continue;

        if (svc_indent < 0 || indent <= svc_indent) {
            if (trimmed.back() == ':') {
                svc_indent = indent;
                proj.services.push_back({});
                cur_svc = &proj.services.back();
                cur_svc->name = trimmed.substr(0, trimmed.size() - 1);
                cur_key.clear();
                sub_section.clear();
                key_indent = -1;
            }
            continue;
        }

        if (!cur_svc) continue;

        if (trimmed.rfind("- ", 0) == 0 || trimmed == "-") {
            std::string item = strip_quotes(trimmed.size() > 1 ? trimmed.substr(2) : "");
            if (cur_key == "ports") cur_svc->ports.push_back(item);
            else if (cur_key == "volumes") cur_svc->volumes.push_back(item);
            else if (cur_key == "environment") cur_svc->environment.push_back(item);
            else if (cur_key == "env_file") cur_svc->env_files.push_back(item);
            else if (cur_key == "depends_on") cur_svc->depends_on.push_back(item);
            else if (cur_key == "cap_add") cur_svc->cap_add.push_back(item);
            else if (cur_key == "cap_drop") cur_svc->cap_drop.push_back(item);
            else if (cur_key == "security_opt") cur_svc->security_opts.push_back(item);
            else if (cur_key == "tmpfs") cur_svc->tmpfs.push_back(item);
            else if (cur_key == "dns") cur_svc->dns.push_back(item);
            else if (cur_key == "networks") cur_svc->networks.push_back(item);
            else if (cur_key == "command") cur_svc->command.push_back(item);
            continue;
        }

        auto colon = trimmed.find(':');
        if (colon == std::string::npos) continue;
        std::string k = trim_yaml(trimmed.substr(0, colon));
        std::string v = trim_yaml(trimmed.substr(colon + 1));

        if (key_indent >= 0 && indent > key_indent && (cur_key == "environment" || cur_key == "build" || cur_key == "depends_on")) {
            if (cur_key == "environment") {
                cur_svc->environment.push_back(k + "=" + strip_quotes(v));
            } else if (cur_key == "build") {
                if (k == "context") cur_svc->build_context = strip_quotes(v);
                else if (k == "dockerfile" || k == "piecefile") cur_svc->build_file = strip_quotes(v);
            } else if (cur_key == "depends_on" && v.empty()) {
                cur_svc->depends_on.push_back(k);
            }
            continue;
        }

        key_indent = indent;
        cur_key = k;
        sub_section.clear();

        if (v.empty()) continue;

        std::string sv = strip_quotes(v);
        if (k == "image") cur_svc->image = sv;
        else if (k == "build") cur_svc->build_context = sv;
        else if (k == "container_name") cur_svc->container_name = sv;
        else if (k == "working_dir") cur_svc->working_dir = sv;
        else if (k == "user") cur_svc->user = sv;
        else if (k == "mem_limit") cur_svc->mem_limit = sv;
        else if (k == "cpus") cur_svc->cpus = std::stod(sv);
        else if (k == "pids_limit") cur_svc->pids_limit = std::stoi(sv);
        else if (k == "restart") cur_svc->restart = sv;
        else if (k == "read_only") cur_svc->read_only = (sv == "true" || sv == "1");
        else if (k == "privileged") cur_svc->privileged = (sv == "true" || sv == "1");
        else if (k == "command") {
            if (v.front() == '[') cur_svc->command = parse_inline_list(v);
            else cur_svc->command = split_shell_words(sv);
        } else if (k == "ports" && v.front() == '[') cur_svc->ports = parse_inline_list(v);
        else if (k == "volumes" && v.front() == '[') cur_svc->volumes = parse_inline_list(v);
        else if (k == "depends_on" && v.front() == '[') cur_svc->depends_on = parse_inline_list(v);
        else if (k == "environment" && v.front() == '[') cur_svc->environment = parse_inline_list(v);
        else if (k == "networks" && v.front() == '[') cur_svc->networks = parse_inline_list(v);
    }
    return proj;
}

ComposeProject parse_compose_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Cannot open compose file: " + path);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::string proj_name = fs::weakly_canonical(fs::absolute(path)).parent_path().filename().string();
    return parse_compose_yaml(content, proj_name);
}

std::vector<std::string> topo_sort_services(const std::vector<ComposeService>& services) {
    std::map<std::string, const ComposeService*> by_name;
    for (const auto& s : services) by_name[s.name] = &s;

    std::vector<std::string> order;
    std::map<std::string, int> state;  // 0=unvisited, 1=visiting, 2=done

    auto visit = [&](auto& self, const std::string& name) -> void {
        if (state[name] == 2) return;
        if (state[name] == 1) throw std::invalid_argument("Cyclic depends_on detected at service '" + name + "'");
        state[name] = 1;
        auto it = by_name.find(name);
        if (it != by_name.end()) {
            for (const auto& dep : it->second->depends_on) {
                if (!by_name.contains(dep)) {
                    throw std::invalid_argument("Service '" + name + "' depends_on unknown service '" + dep + "'");
                }
                self(self, dep);
            }
            order.push_back(name);
        }
        state[name] = 2;
    };

    for (const auto& s : services) visit(visit, s.name);
    return order;
}

int compose_up(
    const std::string& compose_path,
    bool detach,
    bool force_build,
    const std::string& image_dir,
    const std::string& containers_dir,
    const std::string& volumes_dir,
    const std::string& networks_dir) {
    ComposeProject proj = parse_compose_file(compose_path);
    fs::path compose_dir = fs::weakly_canonical(fs::absolute(compose_path)).parent_path();

    for (const auto& vol : proj.volumes) create_volume(vol, volumes_dir);

    std::string default_net = proj.project_name + "_default";
    std::vector<std::string> nets = proj.networks.empty() ? std::vector<std::string>{default_net} : proj.networks;
    for (const auto& net : nets) {
        std::error_code ec;
        if (!fs::exists(fs::path(networks_dir) / (net + ".json"), ec)) {
            create_network(net, "", false, networks_dir);
        }
    }

    auto order = topo_sort_services(proj.services);
    std::map<std::string, const ComposeService*> by_name;
    for (const auto& s : proj.services) by_name[s.name] = &s;

    for (const auto& svc_name : order) {
        const ComposeService& svc = *by_name.at(svc_name);
        std::string image_name = svc.image.empty() ? (proj.project_name + "-" + svc.name) : svc.image;
        std::string normalized_img = image_name;
        std::replace(normalized_img.begin(), normalized_img.end(), ':', '-');
        std::replace(normalized_img.begin(), normalized_img.end(), '/', '-');

        if (!svc.build_context.empty() &&
            (force_build || !fs::is_directory(fs::path(image_dir) / normalized_img))) {
            fs::path ctx = (compose_dir / svc.build_context).lexically_normal();
            std::string pf_path = resolve_piecefile_path(ctx.string(), svc.build_file.empty() ? "" : (ctx / svc.build_file).string());
            auto spec = parse_piecefile(pf_path);
            if (!spec.has_value()) return 1;
            std::string img_path = resolve_image_path(normalized_img, image_dir);
            if (!build_image(*spec, img_path, ctx.string(), nullptr, nullptr, nullptr, false, CACHE_DIR, {}, image_dir)) {
                return 1;
            }
        } else if (!fs::is_directory(fs::path(image_dir) / normalized_img) && svc.image.find('/') != std::string::npos) {
            std::string img_path = resolve_image_path(normalized_img, image_dir);
            if (!pull_oci_image(svc.image, img_path)) return 1;
        }

        ContainerRunConfig cfg;
        cfg.image = normalized_img;
        cfg.name = default_service_container_name(proj, svc);
        cfg.detach = detach || (proj.services.size() > 1);
        cfg.isolate_net = false;
        cfg.network_mode = svc.networks.empty() ? default_net : svc.networks.front();
        cfg.cmd_args = svc.command;
        cfg.env_specs = svc.environment;
        for (const auto& ef : svc.env_files) cfg.env_files.push_back((compose_dir / ef).string());
        cfg.volume_specs = svc.volumes;
        cfg.tmpfs_specs = svc.tmpfs;
        cfg.port_specs = svc.ports;
        cfg.dns_servers = svc.dns;
        cfg.cap_add = svc.cap_add;
        cfg.cap_drop = svc.cap_drop;
        cfg.security_opts = svc.security_opts;
        cfg.workdir = svc.working_dir;
        cfg.user_spec = svc.user;
        cfg.memory_limit = svc.mem_limit;
        cfg.cpu_limit = svc.cpus;
        cfg.pids_limit = svc.pids_limit;
        cfg.restart_policy = parse_restart_policy(svc.restart);
        cfg.readonly_rootfs = svc.read_only;
        cfg.privileged = svc.privileged;
        cfg.image_dir = image_dir;
        cfg.containers_dir = containers_dir;
        cfg.volumes_dir = volumes_dir;
        cfg.networks_dir = networks_dir;

        if (run_container(cfg) != 0) return 1;
    }
    return 0;
}

int compose_down(
    const std::string& compose_path,
    const std::string& containers_dir,
    const std::string& networks_dir) {
    ComposeProject proj = parse_compose_file(compose_path);
    for (const auto& svc : proj.services) {
        std::string cname = default_service_container_name(proj, svc);
        try {
            stop_container(cname, 5, containers_dir);
        } catch (const std::exception&) {
        }
        try {
            remove_container(cname, true, containers_dir);
        } catch (const std::exception&) {
        }
    }
    std::string default_net = proj.project_name + "_default";
    std::vector<std::string> nets = proj.networks.empty() ? std::vector<std::string>{default_net} : proj.networks;
    for (const auto& net : nets) {
        try {
            remove_network(net, networks_dir);
        } catch (const std::exception&) {
        }
    }
    return 0;
}

int compose_ps(const std::string& compose_path, const std::string& containers_dir) {
    ComposeProject proj = parse_compose_file(compose_path);
    std::set<std::string> names;
    for (const auto& s : proj.services) names.insert(default_service_container_name(proj, s));
    for (const auto& c : list_containers(true, containers_dir)) {
        auto it = c.find("name");
        if (it != c.end() && it->second.is_string() && names.contains(it->second.as_string())) {
            std::cout << it->second.as_string() << "\t"
                      << c.at("status").as_string() << "\t"
                      << (c.contains("ip") ? c.at("ip").as_string() : "-") << "\n";
        }
    }
    return 0;
}

int compose_logs(
    const std::string& compose_path,
    bool follow,
    int tail_lines,
    const std::string& containers_dir) {
    ComposeProject proj = parse_compose_file(compose_path);
    for (const auto& s : proj.services) {
        std::string cname = default_service_container_name(proj, s);
        std::cout << "==> " << cname << " <==\n";
        try {
            show_container_logs(cname, follow && proj.services.size() == 1, tail_lines, containers_dir);
        } catch (const std::exception& e) {
            std::cerr << e.what() << "\n";
        }
    }
    return 0;
}

}  // namespace pieces

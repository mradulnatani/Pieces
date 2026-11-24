#include "pieces/registry.hpp"

#include <curl/curl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <system_error>

#include "pieces/filesystem.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

std::string to_lower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string trim(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string url_encode(const std::string& val) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : val) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

size_t write_string_cb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* str = static_cast<std::string*>(userdata);
    str->append(static_cast<const char*>(ptr), size * nmemb);
    return size * nmemb;
}

size_t write_file_cb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* fp = static_cast<FILE*>(userdata);
    return std::fwrite(ptr, size, nmemb, fp);
}

size_t header_cb(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t total = size * nitems;
    auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
    std::string line(buffer, total);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = to_lower(trim(line.substr(0, colon)));
        std::string val = trim(line.substr(colon + 1));
        (*headers)[key] = val;
    }
    return total;
}

HttpResponse default_http_get(
    const std::string& url,
    const std::vector<std::string>& headers,
    const std::string& save_to_path) {
    static const bool curl_inited = []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        return true;
    }();
    (void)curl_inited;

    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize libcurl");
    }

    HttpResponse resp;
    FILE* fp = nullptr;
    if (!save_to_path.empty()) {
        fp = std::fopen(save_to_path.c_str(), "wb");
        if (!fp) {
            curl_easy_cleanup(curl);
            throw std::runtime_error("Failed to open file for download: " + save_to_path);
        }
    }

    curl_slist* hdr_list = nullptr;
    for (const auto& h : headers) {
        hdr_list = curl_slist_append(hdr_list, h.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr_list);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp.headers);
    if (fp) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    } else {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_string_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
    }

    CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.status_code);

    if (hdr_list) curl_slist_free_all(hdr_list);
    curl_easy_cleanup(curl);
    if (fp) std::fclose(fp);

    if (rc != CURLE_OK) {
        throw std::runtime_error(std::string("HTTP request failed: ") + curl_easy_strerror(rc));
    }
    return resp;
}

std::string scheme_for_registry(const std::string& registry) {
    if (registry.rfind("localhost", 0) == 0 || registry.rfind("127.0.0.1", 0) == 0) {
        return "http://";
    }
    return "https://";
}

std::string fetch_bearer_token(const std::string& www_auth, const HttpGetFn& http_get) {
    auto params = parse_www_authenticate(www_auth);
    auto realm_it = params.find("realm");
    if (realm_it == params.end() || realm_it->second.empty()) {
        throw std::runtime_error("Registry returned 401 without Bearer realm");
    }
    std::string token_url = realm_it->second;
    char sep = (token_url.find('?') == std::string::npos) ? '?' : '&';
    if (auto it = params.find("service"); it != params.end() && !it->second.empty()) {
        token_url += sep + std::string("service=") + url_encode(it->second);
        sep = '&';
    }
    if (auto it = params.find("scope"); it != params.end() && !it->second.empty()) {
        token_url += sep + std::string("scope=") + url_encode(it->second);
    }

    HttpResponse tok_resp = http_get(token_url, {"Accept: application/json"}, "");
    if (tok_resp.status_code < 200 || tok_resp.status_code >= 300) {
        throw std::runtime_error("Token endpoint returned HTTP " + std::to_string(tok_resp.status_code));
    }
    JsonValue doc = JsonValue::parse(tok_resp.body);
    if (const JsonValue* t = doc.find("token"); t && t->is_string() && !t->as_string().empty()) {
        return t->as_string();
    }
    if (const JsonValue* t = doc.find("access_token"); t && t->is_string() && !t->as_string().empty()) {
        return t->as_string();
    }
    throw std::runtime_error("Token endpoint response missing 'token'");
}

HttpResponse registry_get_with_auth(
    const std::string& url,
    const std::vector<std::string>& extra_headers,
    std::string& cached_token,
    const HttpGetFn& http_get,
    const std::string& save_to_path = "") {
    auto build_hdrs = [&](const std::string& tok) {
        std::vector<std::string> hdrs = extra_headers;
        if (!tok.empty()) {
            hdrs.push_back("Authorization: Bearer " + tok);
        }
        return hdrs;
    };

    HttpResponse resp = http_get(url, build_hdrs(cached_token), save_to_path);
    if (resp.status_code == 401) {
        auto it = resp.headers.find("www-authenticate");
        if (it != resp.headers.end()) {
            cached_token = fetch_bearer_token(it->second, http_get);
            resp = http_get(url, build_hdrs(cached_token), save_to_path);
        }
    }
    return resp;
}

}  // namespace

std::string ImageReference::default_local_name() const {
    std::string base = repository;
    if (registry == "registry-1.docker.io" && base.rfind("library/", 0) == 0) {
        base = base.substr(8);
    }
    std::replace(base.begin(), base.end(), '/', '-');
    std::string raw = base + "-" + tag;
    std::replace(raw.begin(), raw.end(), ':', '-');
    return validate_name(raw, "image");
}

ImageReference parse_image_reference(const std::string& ref) {
    if (ref.empty()) {
        throw std::invalid_argument("Image reference cannot be empty");
    }

    std::string remainder = ref;
    std::string registry = "registry-1.docker.io";

    auto first_slash = remainder.find('/');
    if (first_slash != std::string::npos) {
        std::string first_part = remainder.substr(0, first_slash);
        if (first_part.find('.') != std::string::npos ||
            first_part.find(':') != std::string::npos ||
            first_part == "localhost") {
            registry = (first_part == "docker.io") ? "registry-1.docker.io" : first_part;
            remainder = remainder.substr(first_slash + 1);
        }
    }

    if (remainder.empty()) {
        throw std::invalid_argument("Image reference missing repository: '" + ref + "'");
    }

    std::string tag = "latest";
    auto last_slash = remainder.find_last_of('/');
    auto last_colon = remainder.find_last_of(':');
    if (last_colon != std::string::npos && (last_slash == std::string::npos || last_colon > last_slash)) {
        tag = remainder.substr(last_colon + 1);
        remainder = remainder.substr(0, last_colon);
    }

    if (registry == "registry-1.docker.io" && remainder.find('/') == std::string::npos) {
        remainder = "library/" + remainder;
    }

    if (remainder.empty() || tag.empty()) {
        throw std::invalid_argument("Invalid image reference: '" + ref + "'");
    }

    return {registry, remainder, tag};
}

std::map<std::string, std::string> parse_www_authenticate(const std::string& header_value) {
    std::map<std::string, std::string> params;
    std::string s = trim(header_value);
    if (to_lower(s.substr(0, 6)) == "bearer") {
        s = trim(s.substr(6));
    }
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ',' || std::isspace(static_cast<unsigned char>(s[i])))) {
            ++i;
        }
        size_t eq = s.find('=', i);
        if (eq == std::string::npos) break;
        std::string key = to_lower(trim(s.substr(i, eq - i)));
        i = eq + 1;
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        std::string val;
        if (i < s.size() && s[i] == '"') {
            ++i;
            while (i < s.size() && s[i] != '"') {
                if (s[i] == '\\' && i + 1 < s.size()) ++i;
                val.push_back(s[i++]);
            }
            if (i < s.size() && s[i] == '"') ++i;
        } else {
            size_t comma = s.find(',', i);
            val = trim(comma == std::string::npos ? s.substr(i) : s.substr(i, comma - i));
            i = (comma == std::string::npos) ? s.size() : comma;
        }
        params[key] = val;
    }
    return params;
}

std::string host_oci_architecture() {
    struct utsname uts{};
    if (::uname(&uts) != 0) {
        return "amd64";
    }
    std::string m(uts.machine);
    if (m == "x86_64" || m == "amd64") return "amd64";
    if (m == "aarch64" || m == "arm64") return "arm64";
    if (m == "armv7l" || m == "arm") return "arm";
    if (m == "i386" || m == "i686") return "386";
    if (m == "riscv64") return "riscv64";
    return m;
}

std::optional<std::string> select_manifest_digest(
    const JsonValue& index_doc,
    const std::string& target_os,
    const std::string& target_arch) {
    const JsonValue* manifests = index_doc.find("manifests");
    if (!manifests || !manifests->is_array()) {
        return std::nullopt;
    }
    for (const auto& entry : manifests->as_array()) {
        const JsonValue* plat = entry.find("platform");
        const JsonValue* digest = entry.find("digest");
        if (!plat || !plat->is_object() || !digest || !digest->is_string()) {
            continue;
        }
        const JsonValue* os_v = plat->find("os");
        const JsonValue* arch_v = plat->find("architecture");
        if (os_v && os_v->is_string() && os_v->as_string() == target_os &&
            arch_v && arch_v->is_string() && arch_v->as_string() == target_arch) {
            return digest->as_string();
        }
    }
    throw std::runtime_error("No matching manifest found for " + target_os + "/" + target_arch);
}

JsonObject extract_oci_config_metadata(const JsonValue& config_doc) {
    JsonObject meta;
    const JsonValue* cfg = config_doc.find("config");
    if (!cfg || !cfg->is_object()) {
        return meta;
    }
    if (const JsonValue* cmd = cfg->find("Cmd"); cmd && cmd->is_array()) {
        meta["cmd"] = *cmd;
    }
    if (const JsonValue* ep = cfg->find("Entrypoint"); ep && ep->is_array()) {
        meta["entrypoint"] = *ep;
    }
    if (const JsonValue* wd = cfg->find("WorkingDir"); wd && wd->is_string() && !wd->as_string().empty()) {
        meta["workdir"] = *wd;
    }
    if (const JsonValue* env = cfg->find("Env"); env && env->is_array()) {
        JsonObject env_obj;
        for (const auto& item : env->as_array()) {
            if (!item.is_string()) continue;
            const std::string& kv = item.as_string();
            auto eq = kv.find('=');
            if (eq != std::string::npos && eq > 0) {
                env_obj[kv.substr(0, eq)] = kv.substr(eq + 1);
            }
        }
        if (!env_obj.empty()) {
            meta["env"] = std::move(env_obj);
        }
    }
    return meta;
}

bool pull_oci_image(
    const std::string& image_ref,
    const std::string& dest_image_path,
    const HttpGetFn& http_get) {
    HttpGetFn get_fn = http_get ? http_get : HttpGetFn(default_http_get);
    ImageReference ref = parse_image_reference(image_ref);
    std::string base_url = scheme_for_registry(ref.registry) + ref.registry + "/v2/" + ref.repository;

    fs::path abs_dest = fs::absolute(dest_image_path);
    fs::path parent_dir = abs_dest.parent_path();
    fs::create_directories(parent_dir);

    std::string pid_str = std::to_string(::getpid());
    fs::path staging_dir = parent_dir / (".oci-staging-" + abs_dest.filename().string() + "." + pid_str);
    fs::path tmp_blob = parent_dir / (".oci-layer-" + pid_str + ".tar.gz");
    std::error_code ec;
    fs::remove_all(staging_dir, ec);
    fs::remove(tmp_blob, ec);
    fs::create_directories(staging_dir);

    try {
        std::string token;
        std::vector<std::string> manifest_accept = {
            "Accept: application/vnd.oci.image.index.v1+json, "
            "application/vnd.docker.distribution.manifest.list.v2+json, "
            "application/vnd.oci.image.manifest.v1+json, "
            "application/vnd.docker.distribution.manifest.v2+json"
        };

        std::cout << "PULL: Fetching manifest for " << ref.registry << "/" << ref.repository << ":" << ref.tag << "...\n";
        HttpResponse m_resp = registry_get_with_auth(
            base_url + "/manifests/" + ref.tag,
            manifest_accept,
            token,
            get_fn);
        if (m_resp.status_code < 200 || m_resp.status_code >= 300) {
            throw std::runtime_error("Manifest fetch failed with HTTP " + std::to_string(m_resp.status_code));
        }

        JsonValue manifest = JsonValue::parse(m_resp.body);
        if (auto digest = select_manifest_digest(manifest, "linux", host_oci_architecture())) {
            HttpResponse arch_resp = registry_get_with_auth(
                base_url + "/manifests/" + *digest,
                {"Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"},
                token,
                get_fn);
            if (arch_resp.status_code < 200 || arch_resp.status_code >= 300) {
                throw std::runtime_error("Arch manifest fetch failed with HTTP " + std::to_string(arch_resp.status_code));
            }
            manifest = JsonValue::parse(arch_resp.body);
        }

        JsonObject meta;
        if (const JsonValue* cfg = manifest.find("config"); cfg && cfg->is_object()) {
            if (const JsonValue* cfg_digest = cfg->find("digest"); cfg_digest && cfg_digest->is_string()) {
                HttpResponse cfg_resp = registry_get_with_auth(
                    base_url + "/blobs/" + cfg_digest->as_string(),
                    {},
                    token,
                    get_fn);
                if (cfg_resp.status_code >= 200 && cfg_resp.status_code < 300) {
                    meta = extract_oci_config_metadata(JsonValue::parse(cfg_resp.body));
                }
            }
        }

        const JsonValue* layers = manifest.find("layers");
        if (!layers || !layers->is_array() || layers->as_array().empty()) {
            throw std::runtime_error("OCI manifest contains no layers");
        }

        const auto& layer_arr = layers->as_array();
        for (size_t i = 0; i < layer_arr.size(); ++i) {
            const JsonValue* digest_v = layer_arr[i].find("digest");
            if (!digest_v || !digest_v->is_string()) {
                throw std::runtime_error("Layer entry missing digest");
            }
            std::cout << "PULL: Downloading & extracting layer " << (i + 1) << "/" << layer_arr.size()
                      << " (" << digest_v->as_string().substr(0, 19) << ")...\n";
            HttpResponse layer_resp = registry_get_with_auth(
                base_url + "/blobs/" + digest_v->as_string(),
                {},
                token,
                get_fn,
                tmp_blob.string());
            if (layer_resp.status_code < 200 || layer_resp.status_code >= 300) {
                throw std::runtime_error("Layer blob download failed with HTTP " + std::to_string(layer_resp.status_code));
            }
            safe_extract_tar_file(tmp_blob.string(), staging_dir.string(), true);
            fs::remove(tmp_blob, ec);
        }

        std::ofstream meta_out(staging_dir / ".pieces_meta.json");
        meta_out << JsonValue(meta).dump(2) << "\n";
        meta_out.close();

        fs::path backup_dir = parent_dir / (abs_dest.filename().string() + ".old." + pid_str);
        fs::remove_all(backup_dir, ec);
        bool had_existing = fs::exists(abs_dest, ec);
        if (had_existing) {
            fs::rename(abs_dest, backup_dir);
        }
        try {
            fs::rename(staging_dir, abs_dest);
        } catch (...) {
            if (had_existing && fs::exists(backup_dir, ec) && !fs::exists(abs_dest, ec)) {
                fs::rename(backup_dir, abs_dest, ec);
            }
            throw;
        }
        if (had_existing) {
            fs::remove_all(backup_dir, ec);
        }

        std::cout << "PULL: Image ready at " << dest_image_path << "\n";
        return true;
    } catch (const std::exception& exc) {
        std::cerr << "PULL: Failed to pull '" << image_ref << "': " << exc.what() << "\n";
        fs::remove(tmp_blob, ec);
        fs::remove_all(staging_dir, ec);
        return false;
    }
}

}  // namespace pieces

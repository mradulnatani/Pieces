#include "pieces/parser.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>

namespace pieces {

namespace {

std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string ltrim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    return s.substr(start);
}

std::string rtrim(const std::string& s) {
    size_t end = s.size();
    while (end > 0 && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(0, end);
}

std::string to_upper(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string to_lower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

const std::set<std::string>& supported_instructions() {
    static const std::set<std::string> kSupported = {
        "FROM", "FROM_URL", "SHA256", "ENV", "WORKDIR", "COPY", "RUN", "CMD", "ENTRYPOINT",
    };
    return kSupported;
}

std::map<std::string, std::string> parse_env_assignments(const std::string& value) {
    auto tokens = split_shell_words(value);
    if (tokens.empty()) {
        throw std::invalid_argument("ENV instruction requires at least one key/value");
    }

    if (tokens[0].find('=') != std::string::npos) {
        std::map<std::string, std::string> env_map;
        for (const auto& token : tokens) {
            auto eq = token.find('=');
            if (eq == std::string::npos) {
                throw std::invalid_argument("Invalid ENV assignment '" + token + "'; expected KEY=VALUE");
            }
            std::string key = token.substr(0, eq);
            std::string val = token.substr(eq + 1);
            if (key.empty()) {
                throw std::invalid_argument("ENV variable name cannot be empty");
            }
            env_map[key] = val;
        }
        return env_map;
    }

    std::string trimmed = trim(value);
    size_t ws = 0;
    while (ws < trimmed.size() && !std::isspace(static_cast<unsigned char>(trimmed[ws]))) {
        ++ws;
    }
    if (ws == 0 || ws == trimmed.size()) {
        throw std::invalid_argument("Invalid ENV instruction '" + value + "'; expected KEY=VALUE or KEY VALUE");
    }
    std::string key = trimmed.substr(0, ws);
    std::string val = trim(trimmed.substr(ws));
    if (val.empty()) {
        throw std::invalid_argument("Invalid ENV instruction '" + value + "'; expected KEY=VALUE or KEY VALUE");
    }
    return {{key, val}};
}

std::vector<std::pair<int, std::string>> join_logical_lines(const std::vector<std::string>& raw_lines) {
    std::vector<std::pair<int, std::string>> logical;
    std::string buffer;
    int start_line = 0;

    for (size_t i = 0; i < raw_lines.size(); ++i) {
        std::string line = raw_lines[i];
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }
        if (buffer.empty()) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') {
                continue;
            }
            start_line = static_cast<int>(i) + 1;
        }

        std::string segment = buffer.empty() ? line : ltrim(line);
        if (!segment.empty() && segment.back() == '\\') {
            segment.pop_back();
            buffer += rtrim(segment) + " ";
            continue;
        }

        buffer += segment;
        std::string cleaned = trim(buffer);
        if (!cleaned.empty() && cleaned[0] != '#') {
            logical.emplace_back(start_line, cleaned);
        }
        buffer.clear();
    }

    if (!trim(buffer).empty()) {
        logical.emplace_back(start_line, trim(buffer));
    }
    return logical;
}

}  // namespace

JsonObject PiecefileSpec::to_metadata() const {
    JsonObject meta;
    if (cmd.has_value()) {
        JsonArray arr;
        for (const auto& item : *cmd) {
            arr.emplace_back(item);
        }
        meta["cmd"] = std::move(arr);
    }
    if (entrypoint.has_value()) {
        JsonArray arr;
        for (const auto& item : *entrypoint) {
            arr.emplace_back(item);
        }
        meta["entrypoint"] = std::move(arr);
    }
    if (!env.empty()) {
        JsonObject env_obj;
        for (const auto& [k, v] : env) {
            env_obj[k] = v;
        }
        meta["env"] = std::move(env_obj);
    }
    if (workdir.has_value()) {
        meta["workdir"] = *workdir;
    }
    return meta;
}

std::vector<std::string> split_shell_words(const std::string& input) {
    std::vector<std::string> tokens;
    std::string current;
    bool in_token = false;
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (in_single) {
            if (c == '\'') {
                in_single = false;
            } else {
                current.push_back(c);
            }
            in_token = true;
        } else if (in_double) {
            if (c == '"') {
                in_double = false;
            } else if (c == '\\' && i + 1 < input.size()) {
                char next = input[i + 1];
                if (next == '"' || next == '\\' || next == '$' || next == '`') {
                    current.push_back(next);
                    ++i;
                } else {
                    current.push_back(c);
                }
            } else {
                current.push_back(c);
            }
            in_token = true;
        } else {
            if (std::isspace(static_cast<unsigned char>(c))) {
                if (in_token) {
                    tokens.push_back(std::move(current));
                    current.clear();
                    in_token = false;
                }
            } else if (c == '\'') {
                in_single = true;
                in_token = true;
            } else if (c == '"') {
                in_double = true;
                in_token = true;
            } else if (c == '\\' && i + 1 < input.size()) {
                current.push_back(input[++i]);
                in_token = true;
            } else {
                current.push_back(c);
                in_token = true;
            }
        }
    }
    if (in_single || in_double) {
        throw std::invalid_argument("Unterminated quote in Piecefile command");
    }
    if (in_token) {
        tokens.push_back(std::move(current));
    }
    return tokens;
}

std::vector<std::string> parse_command_value(const std::string& value) {
    std::string stripped = trim(value);
    if (stripped.empty()) {
        return {};
    }
    if (stripped.front() == '[') {
        try {
            JsonValue parsed = JsonValue::parse(stripped);
            if (parsed.is_array()) {
                std::vector<std::string> result;
                bool all_strings = true;
                for (const auto& item : parsed.as_array()) {
                    if (!item.is_string()) {
                        all_strings = false;
                        break;
                    }
                    result.push_back(item.as_string());
                }
                if (all_strings) {
                    return result;
                }
            }
        } catch (const std::exception&) {
        }
    }
    return split_shell_words(stripped);
}

std::optional<PiecefileSpec> parse_piecefile(const std::string& path) {
    if (!std::filesystem::exists(path)) {
        std::cout << "Error: Piecefile not found at '" << path << "'\n";
        return std::nullopt;
    }

    std::ifstream in(path);
    if (!in) {
        std::cout << "Error: Could not open Piecefile at '" << path << "'\n";
        return std::nullopt;
    }

    std::vector<std::string> raw_lines;
    std::string line;
    while (std::getline(in, line)) {
        raw_lines.push_back(line);
    }

    auto logical_lines = join_logical_lines(raw_lines);
    PiecefileSpec spec;

    for (const auto& [line_no, cleaned] : logical_lines) {
        size_t ws = 0;
        while (ws < cleaned.size() && !std::isspace(static_cast<unsigned char>(cleaned[ws]))) {
            ++ws;
        }
        if (ws == 0 || ws == cleaned.size()) {
            std::cout << "Error: Invalid Piecefile line " << line_no << ": '" << cleaned << "'\n";
            return std::nullopt;
        }

        std::string keyword = to_upper(cleaned.substr(0, ws));
        std::string value = trim(cleaned.substr(ws));
        if (value.empty()) {
            std::cout << "Error: Invalid Piecefile line " << line_no << ": '" << cleaned << "'\n";
            return std::nullopt;
        }
        if (!supported_instructions().contains(keyword)) {
            std::cout << "Error: Unsupported Piecefile instruction '" << keyword << "' on line " << line_no << "\n";
            return std::nullopt;
        }

        spec.instructions.push_back({keyword, value, line_no});

        try {
            if (keyword == "FROM") {
                spec.from_image = value;
            } else if (keyword == "FROM_URL") {
                spec.from_url = value;
            } else if (keyword == "SHA256") {
                std::string hex = to_lower(value);
                if (hex.rfind("sha256:", 0) == 0) {
                    hex = hex.substr(7);
                }
                if (hex.size() != 64 || !std::all_of(hex.begin(), hex.end(), [](unsigned char c) { return std::isxdigit(c); })) {
                    throw std::invalid_argument("SHA256 must be a 64-character hex digest");
                }
                spec.sha256 = hex;
            } else if (keyword == "ENV") {
                for (const auto& [k, v] : parse_env_assignments(value)) {
                    spec.env[k] = v;
                }
            } else if (keyword == "WORKDIR") {
                spec.workdir = value;
            } else if (keyword == "COPY") {
                auto copy_parts = split_shell_words(value);
                if (copy_parts.size() != 2) {
                    throw std::invalid_argument("COPY requires <src> <dst>, got: " + value);
                }
                spec.copies.emplace_back(copy_parts[0], copy_parts[1]);
            } else if (keyword == "RUN") {
                spec.runs.push_back(value);
            } else if (keyword == "CMD") {
                spec.cmd = parse_command_value(value);
            } else if (keyword == "ENTRYPOINT") {
                spec.entrypoint = parse_command_value(value);
            }
        } catch (const std::exception& exc) {
            std::cout << "Error: Piecefile line " << line_no << ": " << exc.what() << "\n";
            return std::nullopt;
        }
    }

    if (!spec.from_image.has_value() && !spec.from_url.has_value()) {
        std::cout << "Error: Piecefile must specify either FROM or FROM_URL.\n";
        return std::nullopt;
    }

    return spec;
}

}  // namespace pieces

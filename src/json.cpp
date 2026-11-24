#include "pieces/json.hpp"

#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace pieces {

namespace {

void escape_string(const std::string& s, std::ostringstream& out) {
    out << '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
                break;
        }
    }
    out << '"';
}

void dump_impl(const JsonValue& v, std::ostringstream& out, int indent, int depth) {
    if (v.is_null()) {
        out << "null";
    } else if (v.is_bool()) {
        out << (std::get<bool>(v.data) ? "true" : "false");
    } else if (v.is_int()) {
        out << std::get<int64_t>(v.data);
    } else if (v.is_double()) {
        out << std::get<double>(v.data);
    } else if (v.is_string()) {
        escape_string(v.as_string(), out);
    } else if (v.is_array()) {
        const auto& arr = v.as_array();
        if (arr.empty()) {
            out << "[]";
            return;
        }
        out << '[';
        for (size_t i = 0; i < arr.size(); ++i) {
            if (indent > 0) {
                out << '\n' << std::string((depth + 1) * indent, ' ');
            }
            dump_impl(arr[i], out, indent, depth + 1);
            if (i + 1 < arr.size()) {
                out << ',';
            }
        }
        if (indent > 0) {
            out << '\n' << std::string(depth * indent, ' ');
        }
        out << ']';
    } else if (v.is_object()) {
        const auto& obj = v.as_object();
        if (obj.empty()) {
            out << "{}";
            return;
        }
        out << '{';
        size_t idx = 0;
        for (const auto& [k, val] : obj) {
            if (indent > 0) {
                out << '\n' << std::string((depth + 1) * indent, ' ');
            }
            escape_string(k, out);
            out << (indent > 0 ? ": " : ":");
            dump_impl(val, out, indent, depth + 1);
            if (++idx < obj.size()) {
                out << ',';
            }
        }
        if (indent > 0) {
            out << '\n' << std::string(depth * indent, ' ');
        }
        out << '}';
    }
}

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}

    JsonValue parse_root() {
        skip_ws();
        JsonValue val = parse_value();
        skip_ws();
        if (pos_ != s_.size()) {
            throw std::runtime_error("Unexpected trailing characters in JSON");
        }
        return val;
    }

private:
    void skip_ws() {
        while (pos_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[pos_]))) {
            ++pos_;
        }
    }

    char peek() const {
        if (pos_ >= s_.size()) {
            throw std::runtime_error("Unexpected end of JSON");
        }
        return s_[pos_];
    }

    char get() {
        char c = peek();
        ++pos_;
        return c;
    }

    JsonValue parse_value() {
        skip_ws();
        char c = peek();
        if (c == 'n') return parse_null();
        if (c == 't' || c == 'f') return parse_bool();
        if (c == '"') return JsonValue(parse_string());
        if (c == '[') return parse_array();
        if (c == '{') return parse_object();
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parse_number();
        throw std::runtime_error(std::string("Unexpected JSON token: ") + c);
    }

    JsonValue parse_null() {
        if (s_.compare(pos_, 4, "null") != 0) {
            throw std::runtime_error("Invalid JSON literal");
        }
        pos_ += 4;
        return JsonValue(nullptr);
    }

    JsonValue parse_bool() {
        if (s_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            return JsonValue(true);
        }
        if (s_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            return JsonValue(false);
        }
        throw std::runtime_error("Invalid JSON boolean");
    }

    std::string parse_string() {
        if (get() != '"') {
            throw std::runtime_error("Expected '\"'");
        }
        std::string out;
        while (true) {
            char c = get();
            if (c == '"') break;
            if (c == '\\') {
                char esc = get();
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (pos_ + 4 > s_.size()) {
                            throw std::runtime_error("Incomplete \\u escape in JSON");
                        }
                        unsigned int cp = std::stoul(s_.substr(pos_, 4), nullptr, 16);
                        pos_ += 4;
                        if (cp < 0x80) {
                            out.push_back(static_cast<char>(cp));
                        } else if (cp < 0x800) {
                            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default:
                        throw std::runtime_error("Invalid JSON escape sequence");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    JsonValue parse_number() {
        size_t start = pos_;
        if (s_[pos_] == '-') ++pos_;
        bool is_float = false;
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if (std::isdigit(static_cast<unsigned char>(c))) {
                ++pos_;
            } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                if ((c == '+' || c == '-') && pos_ > start && s_[pos_ - 1] != 'e' && s_[pos_ - 1] != 'E') {
                    break;
                }
                is_float = true;
                ++pos_;
            } else {
                break;
            }
        }
        std::string num_str = s_.substr(start, pos_ - start);
        if (is_float) {
            return JsonValue(std::stod(num_str));
        }
        return JsonValue(static_cast<int64_t>(std::stoll(num_str)));
    }

    JsonValue parse_array() {
        get();  // '['
        JsonArray arr;
        skip_ws();
        if (peek() == ']') {
            get();
            return JsonValue(std::move(arr));
        }
        while (true) {
            arr.push_back(parse_value());
            skip_ws();
            char c = get();
            if (c == ']') break;
            if (c != ',') throw std::runtime_error("Expected ',' or ']' in JSON array");
        }
        return JsonValue(std::move(arr));
    }

    JsonValue parse_object() {
        get();  // '{'
        JsonObject obj;
        skip_ws();
        if (peek() == '}') {
            get();
            return JsonValue(std::move(obj));
        }
        while (true) {
            skip_ws();
            std::string key = parse_string();
            skip_ws();
            if (get() != ':') throw std::runtime_error("Expected ':' in JSON object");
            obj[std::move(key)] = parse_value();
            skip_ws();
            char c = get();
            if (c == '}') break;
            if (c != ',') throw std::runtime_error("Expected ',' or '}' in JSON object");
        }
        return JsonValue(std::move(obj));
    }

    const std::string& s_;
    size_t pos_{0};
};

}  // namespace

const JsonValue* JsonValue::find(const std::string& key) const {
    if (!is_object()) return nullptr;
    const auto& obj = as_object();
    auto it = obj.find(key);
    return it == obj.end() ? nullptr : &it->second;
}

std::string JsonValue::dump(int indent) const {
    std::ostringstream out;
    dump_impl(*this, out, indent, 0);
    return out.str();
}

JsonValue JsonValue::parse(const std::string& input) {
    Parser parser(input);
    return parser.parse_root();
}

}  // namespace pieces

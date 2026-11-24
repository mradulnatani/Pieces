#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace pieces {

struct JsonValue;
using JsonArray = std::vector<JsonValue>;
using JsonObject = std::map<std::string, JsonValue>;

struct JsonValue {
    using Storage = std::variant<std::nullptr_t, bool, int64_t, double, std::string, JsonArray, JsonObject>;

    Storage data{nullptr};

    JsonValue() = default;
    JsonValue(std::nullptr_t) : data(nullptr) {}
    JsonValue(bool b) : data(b) {}
    JsonValue(int i) : data(static_cast<int64_t>(i)) {}
    JsonValue(int64_t i) : data(i) {}
    JsonValue(double d) : data(d) {}
    JsonValue(const char* s) : data(std::string(s)) {}
    JsonValue(std::string s) : data(std::move(s)) {}
    JsonValue(JsonArray arr) : data(std::move(arr)) {}
    JsonValue(JsonObject obj) : data(std::move(obj)) {}

    [[nodiscard]] bool is_null() const { return std::holds_alternative<std::nullptr_t>(data); }
    [[nodiscard]] bool is_bool() const { return std::holds_alternative<bool>(data); }
    [[nodiscard]] bool is_int() const { return std::holds_alternative<int64_t>(data); }
    [[nodiscard]] bool is_double() const { return std::holds_alternative<double>(data); }
    [[nodiscard]] bool is_string() const { return std::holds_alternative<std::string>(data); }
    [[nodiscard]] bool is_array() const { return std::holds_alternative<JsonArray>(data); }
    [[nodiscard]] bool is_object() const { return std::holds_alternative<JsonObject>(data); }

    [[nodiscard]] const std::string& as_string() const { return std::get<std::string>(data); }
    [[nodiscard]] const JsonArray& as_array() const { return std::get<JsonArray>(data); }
    [[nodiscard]] const JsonObject& as_object() const { return std::get<JsonObject>(data); }
    [[nodiscard]] JsonObject& as_object_mut() { return std::get<JsonObject>(data); }
    [[nodiscard]] int64_t as_int() const { return std::get<int64_t>(data); }

    [[nodiscard]] const JsonValue* find(const std::string& key) const;
    [[nodiscard]] std::string dump(int indent = 2) const;

    static JsonValue parse(const std::string& input);
};

}  // namespace pieces

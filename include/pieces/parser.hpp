#pragma once

#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "pieces/json.hpp"

namespace pieces {

struct PiecefileInstruction {
    std::string keyword;
    std::string value;
    int line_number{0};
};

struct PiecefileSpec {
    std::optional<std::string> from_image;
    std::optional<std::string> from_url;
    std::optional<std::string> sha256;
    std::map<std::string, std::string> env;
    std::optional<std::string> workdir;
    std::vector<std::pair<std::string, std::string>> copies;
    std::vector<std::string> runs;
    std::optional<std::vector<std::string>> entrypoint;
    std::optional<std::vector<std::string>> cmd;
    std::vector<PiecefileInstruction> instructions;

    [[nodiscard]] JsonObject to_metadata() const;
};

[[nodiscard]] std::vector<std::string> split_shell_words(const std::string& input);
[[nodiscard]] std::vector<std::string> parse_command_value(const std::string& value);
[[nodiscard]] std::optional<PiecefileSpec> parse_piecefile(const std::string& path = "Piecefile");

}  // namespace pieces

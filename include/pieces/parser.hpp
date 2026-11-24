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

struct PiecefileStage {
    std::optional<std::string> from_image;
    std::optional<std::string> from_url;
    std::optional<std::string> sha256;
    std::string alias;
    std::vector<PiecefileInstruction> instructions;
};

struct CopySpec {
    std::string src;
    std::string dst;
    std::optional<std::string> from_stage;
    std::optional<std::string> chown;
};

struct PiecefileSpec {
    std::optional<std::string> from_image;
    std::optional<std::string> from_url;
    std::optional<std::string> sha256;
    std::map<std::string, std::string> env;
    std::map<std::string, std::string> args;
    std::map<std::string, std::string> labels;
    std::optional<std::string> workdir;
    std::optional<std::string> user;
    std::vector<std::pair<std::string, std::string>> copies;
    std::vector<std::string> runs;
    std::vector<std::string> exposed_ports;
    std::vector<std::string> volumes;
    std::optional<std::vector<std::string>> entrypoint;
    std::optional<std::vector<std::string>> cmd;
    std::vector<PiecefileInstruction> instructions;
    std::vector<PiecefileStage> stages;

    [[nodiscard]] JsonObject to_metadata() const;
};

[[nodiscard]] std::vector<std::string> split_shell_words(const std::string& input);
[[nodiscard]] std::vector<std::string> parse_command_value(const std::string& value);
[[nodiscard]] std::string expand_variables(
    const std::string& input,
    const std::map<std::string, std::string>& vars);
[[nodiscard]] CopySpec parse_copy_or_add_args(const std::string& value, bool allow_from_flag);
[[nodiscard]] std::string resolve_piecefile_path(
    const std::string& context_dir,
    const std::string& explicit_file = "");
[[nodiscard]] std::optional<PiecefileSpec> parse_piecefile(const std::string& path = "Piecefile");

}  // namespace pieces

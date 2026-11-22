#include "bca/script/permissions.h"

#include <algorithm>
#include <cctype>
#include <format>

namespace bca::script {
namespace {

std::string_view trim(std::string_view text)
{
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
        text.remove_suffix(1);
    }
    return text;
}

std::string lower(std::string_view text)
{
    std::string out{text};
    std::ranges::transform(out, out.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

}

std::map<std::string, unsigned> parse_permissions(std::string_view text, std::string *problems)
{
    std::map<std::string, unsigned> grants;
    std::size_t line_number = 0;
    while (!text.empty()) {
        ++line_number;
        const auto end = text.find('\n');
        auto line = text.substr(0, end);
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        if (const auto hash = line.find('#'); hash != std::string_view::npos) {
            line = line.substr(0, hash);
        }
        line = trim(line);
        if (line.empty()) {
            continue;
        }
        const auto equals = line.find('=');
        auto name = trim(equals == std::string_view::npos ? line : line.substr(0, equals));
        if (equals == std::string_view::npos || name.empty()) {
            if (problems != nullptr) {
                *problems += std::format("line {}: expected \"name = fs, http, websocket\"\n", line_number);
            }
            continue;
        }
        if (name.size() > 3 && lower(name.substr(name.size() - 3)) == ".js") {
            name.remove_suffix(3);
        }
        auto words = line.substr(equals + 1);
        unsigned granted = 0;
        while (!words.empty()) {
            const auto cut = words.find_first_of(", \t");
            const auto word = lower(trim(words.substr(0, cut)));
            words = cut == std::string_view::npos ? std::string_view{} : words.substr(cut + 1);
            if (word.empty()) {
                continue;
            }
            if (word == "fs" || word == "files") {
                granted |= kGrantFiles;
            }
            else if (word == "http" || word == "net") {
                granted |= kGrantHttp;
            }
            else if (word == "websocket" || word == "ws") {
                granted |= kGrantWebSocket;
            }
            else if (problems != nullptr) {
                *problems += std::format("line {}: unknown permission \"{}\" (fs, http, websocket)\n", line_number, word);
            }
        }
        grants[std::string{name}] |= granted;
    }
    return grants;
}

}

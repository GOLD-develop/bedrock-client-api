#pragma once

#include <map>
#include <string>
#include <string_view>

namespace bca::script {

enum Grant : unsigned {
    kGrantFiles = 1U << 0U,
    kGrantHttp = 1U << 1U,
    kGrantWebSocket = 1U << 2U,
};

[[nodiscard]] std::map<std::string, unsigned> parse_permissions(std::string_view text, std::string *problems = nullptr);

}

#pragma once

#include <string_view>

namespace bca {

void log_line(std::string_view source, std::string_view text, bool error) noexcept;

void open_console() noexcept;

inline void log_error(const std::string_view text) noexcept
{
    log_line("bedrock-client-api", text, true);
}

}

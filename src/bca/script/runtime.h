#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "bca/core/direction.h"

namespace bca::script {

struct Verdict {
    bool cancel{false};
    std::optional<std::string> body;
};

using Sender = bool (*)(Side side, Direction direction, int id, std::string_view body, int player);

void start(std::vector<std::string> packet_names, Sender sender);

[[nodiscard]] bool wants(Side side, Direction direction, int id) noexcept;

[[nodiscard]] Verdict dispatch(Side side, Direction direction, int id, std::string_view body, int player, int connection);

void tick();

}

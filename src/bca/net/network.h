#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "bca/core/direction.h"

namespace bca::net {

inline constexpr std::size_t kPacketIdLimit = 512;

struct Status {
    bool create_packet{false};
    bool send_internal{false};
    std::size_t packet_classes{0};
    std::size_t handlers{0};
};

void install();
void report_stuck();

const Status &status();

const std::vector<std::string> &packet_names();

[[nodiscard]] std::optional<std::string> login_of(int player);

[[nodiscard]] std::optional<std::string> start_game_of(int player);

[[nodiscard]] std::optional<std::string> last_received(int id);

[[nodiscard]] std::vector<int> known_logins();

[[nodiscard]] bool send(Side side, Direction direction, int id, std::string_view body, int player = -1);

}

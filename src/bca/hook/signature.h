#pragma once

#include <string_view>

#include "bca/hook/version.h"

namespace bca {

struct Signatures {
    std::string_view name;
    std::string_view create_packet;
    std::string_view send;
    std::string_view send_internal_call;
};

const Signatures &signatures();

void verify_client();

}

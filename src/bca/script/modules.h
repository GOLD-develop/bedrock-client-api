#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace bca::script {

struct EmbeddedModule {
    std::string_view name;
    bool internal;
    std::string source;
};

const std::vector<EmbeddedModule> &embedded_modules();

}

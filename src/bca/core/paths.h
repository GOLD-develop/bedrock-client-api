#pragma once

#include <filesystem>
#include <string>

namespace bca {

const std::filesystem::path &dll_directory();

std::filesystem::path scripts_directory();

const std::filesystem::path &data_directory();

std::string utf8(const std::filesystem::path &path);

}

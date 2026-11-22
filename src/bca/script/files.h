#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace bca::script::files {

inline constexpr std::uintmax_t kMaxFileSize = 16U << 20U;

struct Info {
    bool found{false};
    std::uintmax_t size{0};
    double mtime_ms{0};
    bool is_file{false};
    bool is_directory{false};
};

[[nodiscard]] std::string read(const std::filesystem::path &root, std::string_view path);
void write(const std::filesystem::path &root, std::string_view path, std::string_view data, bool append);
[[nodiscard]] bool exists(const std::filesystem::path &root, std::string_view path);
void make_directory(const std::filesystem::path &root, std::string_view path, bool recursive);
[[nodiscard]] std::vector<std::string> list(const std::filesystem::path &root, std::string_view path);
void remove(const std::filesystem::path &root, std::string_view path, bool recursive, bool force);
[[nodiscard]] Info stat(const std::filesystem::path &root, std::string_view path);

[[nodiscard]] bool is_inside(const std::filesystem::path &root, const std::filesystem::path &target);

[[nodiscard]] std::filesystem::path resolve(const std::filesystem::path &root, std::string_view path);

}

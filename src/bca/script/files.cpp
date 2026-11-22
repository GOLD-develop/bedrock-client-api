#include "bca/script/files.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <stdexcept>
#include <system_error>

namespace bca::script::files {
namespace {

namespace fs = std::filesystem;

[[noreturn]] void fail(const std::string_view code, const std::string_view what, const std::string_view verb, const std::string_view path)
{
    throw std::runtime_error{std::format("{}: {}, {} '{}'", code, what, verb, path)};
}

[[noreturn]] void fail_with(const std::error_code &ec, const std::string_view verb, const std::string_view path)
{
    const auto condition = ec.default_error_condition();
    if (condition == std::errc::no_such_file_or_directory) {
        fail("ENOENT", "no such file or directory", verb, path);
    }
    if (condition == std::errc::permission_denied) {
        fail("EACCES", "permission denied", verb, path);
    }
    if (condition == std::errc::is_a_directory) {
        fail("EISDIR", "illegal operation on a directory", verb, path);
    }
    if (condition == std::errc::not_a_directory) {
        fail("ENOTDIR", "not a directory", verb, path);
    }
    if (condition == std::errc::file_exists) {
        fail("EEXIST", "file already exists", verb, path);
    }
    if (condition == std::errc::directory_not_empty) {
        fail("ENOTEMPTY", "directory not empty", verb, path);
    }
    fail("EIO", ec.message(), verb, path);
}

}

bool is_inside(const fs::path &root, const fs::path &target)
{
    std::error_code ec;
    const auto base = fs::weakly_canonical(root, ec);
    if (ec) {
        return false;
    }
    const auto full = fs::weakly_canonical(target, ec);
    if (ec) {
        return false;
    }
    const auto relative = full.lexically_relative(base);
    return !relative.empty() && *relative.begin() != ".." && relative != ".";
}

fs::path resolve(const fs::path &root, const std::string_view path)
{
    if (path.find_first_of("\\:*?\"<>|") != std::string_view::npos ||
        std::ranges::any_of(path, [](const char c) { return static_cast<unsigned char>(c) < 0x20; })) {
        fail("EACCES", "this path is not allowed in a script's folder", "access", path);
    }
    std::vector<std::string> parts;
    std::size_t begin = 0;
    while (begin <= path.size()) {
        const auto slash = path.find('/', begin);
        const auto part = path.substr(begin, slash == std::string_view::npos ? std::string_view::npos : slash - begin);
        begin = slash == std::string_view::npos ? path.size() + 1 : slash + 1;
        if (part.empty() || part == ".") {
            continue;
        }
        if (part == "..") {
            if (parts.empty()) {
                fail("EACCES", "the path leaves the script's folder", "access", path);
            }
            parts.pop_back();
            continue;
        }
        parts.emplace_back(part);
    }
    fs::path target = root;
    for (const auto &part : parts) {
        target /= fs::path{std::u8string{reinterpret_cast<const char8_t *>(part.data()), part.size()}};
    }
    if (!parts.empty() && !is_inside(root, target)) {
        fail("EACCES", "the path leaves the script's folder", "access", path);
    }
    return target;
}

std::string read(const fs::path &root, const std::string_view path)
{
    const auto target = resolve(root, path);
    std::error_code ec;
    const auto status = fs::status(target, ec);
    if (ec || !fs::exists(status)) {
        fail("ENOENT", "no such file or directory", "open", path);
    }
    if (fs::is_directory(status)) {
        fail("EISDIR", "illegal operation on a directory", "read", path);
    }
    const auto size = fs::file_size(target, ec);
    if (ec) {
        fail_with(ec, "open", path);
    }
    if (size > kMaxFileSize) {
        fail("EFBIG", "file too large", "read", path);
    }
    std::ifstream file{target, std::ios::binary};
    if (!file) {
        fail("EACCES", "permission denied", "open", path);
    }
    std::string data(static_cast<std::size_t>(size), '\0');
    file.read(data.data(), static_cast<std::streamsize>(data.size()));
    data.resize(static_cast<std::size_t>(file.gcount()));
    return data;
}

void write(const fs::path &root, const std::string_view path, const std::string_view data, const bool append)
{
    const auto target = resolve(root, path);
    if (target == root) {
        fail("EISDIR", "illegal operation on a directory", "open", path);
    }
    std::error_code ec;
    if (fs::is_directory(target, ec)) {
        fail("EISDIR", "illegal operation on a directory", "open", path);
    }
    if (data.size() > kMaxFileSize) {
        fail("EFBIG", "file too large", "write", path);
    }
    if (append) {
        const auto existing = fs::exists(target, ec) ? fs::file_size(target, ec) : 0;
        if (!ec && existing + data.size() > kMaxFileSize) {
            fail("EFBIG", "file too large", "write", path);
        }
    }
    if (!fs::exists(target.parent_path(), ec)) {
        fail("ENOENT", "no such file or directory", "open", path);
    }
    std::ofstream file{target, std::ios::binary | (append ? std::ios::app : std::ios::trunc)};
    if (!file) {
        fail("EACCES", "permission denied", "open", path);
    }
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!file) {
        fail("EIO", "the file could not be written", "write", path);
    }
}

bool exists(const fs::path &root, const std::string_view path)
{
    std::error_code ec;
    return fs::exists(resolve(root, path), ec);
}

void make_directory(const fs::path &root, const std::string_view path, const bool recursive)
{
    const auto target = resolve(root, path);
    std::error_code ec;
    if (recursive) {
        fs::create_directories(target, ec);
    }
    else {
        if (fs::exists(target, ec)) {
            fail("EEXIST", "file already exists", "mkdir", path);
        }
        fs::create_directory(target, ec);
    }
    if (ec) {
        fail_with(ec, "mkdir", path);
    }
}

std::vector<std::string> list(const fs::path &root, const std::string_view path)
{
    const auto target = resolve(root, path);
    std::error_code ec;
    if (!fs::exists(target, ec)) {
        fail("ENOENT", "no such file or directory", "scandir", path);
    }
    if (!fs::is_directory(target, ec)) {
        fail("ENOTDIR", "not a directory", "scandir", path);
    }
    std::vector<std::string> names;
    for (fs::directory_iterator it{target, ec}, end; !ec && it != end; it.increment(ec)) {
        const auto name = it->path().filename().u8string();
        names.emplace_back(name.begin(), name.end());
    }
    if (ec) {
        fail_with(ec, "scandir", path);
    }
    std::ranges::sort(names);
    return names;
}

void remove(const fs::path &root, const std::string_view path, const bool recursive, const bool force)
{
    const auto target = resolve(root, path);
    if (target == root) {
        fail("EACCES", "the script's folder itself cannot be removed", "rm", path);
    }
    std::error_code ec;
    if (!fs::exists(fs::symlink_status(target, ec))) {
        if (force) {
            return;
        }
        fail("ENOENT", "no such file or directory", "unlink", path);
    }
    if (fs::is_directory(target, ec)) {
        if (!recursive) {
            fail("EISDIR", "illegal operation on a directory", "rm", path);
        }
        fs::remove_all(target, ec);
    }
    else {
        fs::remove(target, ec);
    }
    if (ec) {
        fail_with(ec, "rm", path);
    }
}

Info stat(const fs::path &root, const std::string_view path)
{
    const auto target = resolve(root, path);
    std::error_code ec;
    const auto status = fs::status(target, ec);
    Info info;
    if (ec || !fs::exists(status)) {
        return info;
    }
    info.found = true;
    info.is_directory = fs::is_directory(status);
    info.is_file = fs::is_regular_file(status);
    if (info.is_file) {
        info.size = fs::file_size(target, ec);
    }
    const auto time = fs::last_write_time(target, ec);
    if (!ec) {
        const auto system_time = std::chrono::clock_cast<std::chrono::system_clock>(time);
        info.mtime_ms = static_cast<double>(
            std::chrono::duration_cast<std::chrono::milliseconds>(system_time.time_since_epoch()).count());
    }
    return info;
}

}

#include "bca/core/paths.h"

#include <Windows.h>

#include <string>
#include <system_error>

namespace bca {
namespace {

std::filesystem::path locate_dll_directory()
{
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&locate_dll_directory), &self)) {
        return {};
    }
    std::wstring path(32768, L'\0');
    path.resize(GetModuleFileNameW(self, path.data(), static_cast<DWORD>(path.size())));
    return std::filesystem::path{path}.parent_path();
}

std::filesystem::path locate_data_directory()
{
    std::filesystem::path directory;
    if (const auto length = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0); length != 0) {
        std::wstring local(length, L'\0');
        local.resize(GetEnvironmentVariableW(L"LOCALAPPDATA", local.data(), length));
        directory = std::filesystem::path{local} / L"bedrock-client-api";
    }
    std::error_code ec;
    if (directory.empty()) {
        directory = std::filesystem::temp_directory_path(ec) / L"bedrock-client-api";
    }
    std::filesystem::create_directories(directory, ec);
    return directory;
}

}

const std::filesystem::path &dll_directory()
{
    static const auto directory = locate_dll_directory();
    return directory;
}

std::filesystem::path scripts_directory()
{
    return dll_directory() / L"scripts";
}

const std::filesystem::path &data_directory()
{
    static const auto directory = locate_data_directory();
    return directory;
}

std::string utf8(const std::filesystem::path &path)
{
    const auto text = path.u8string();
    return std::string{text.begin(), text.end()};
}

}

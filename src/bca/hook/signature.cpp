#include "bca/hook/signature.h"

#include <Windows.h>
#include <appmodel.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cwchar>
#include <format>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include <libhat/process.hpp>


namespace bca {
namespace {

#if MINECRAFT_PREVIEW

#if MINECRAFT_VERSION_HEX >= MINECRAFT_VERSION(1, 26, 70, 0)

constexpr Signatures kClient{
    .name = MINECRAFT_CLIENT,
    .create_packet = "56 48 83 EC 30 48 89 CE 81 FA ? 01 00 00 0F 87 ? ? ? ? "
                     "89 D0 48 8D 0D ? ? ? ? 48 63 04 81 48 01 "
                     "C8 FF E0 0F 57 C0 0F 11 06 48 89 F0 48 83 C4 30 5E",
};

#elif MINECRAFT_VERSION_HEX >= MINECRAFT_VERSION(1, 26, 60, 30)

constexpr Signatures kClient{
    .name = MINECRAFT_CLIENT,
    .create_packet = "56 48 83 EC 30 48 89 CE 81 FA ? 01 00 00 77 ? 89 D0 48 "
                     "8D 0D ? ? ? ? 48 63 04 81 48 01 C8 FF E0 "
                     "0F 57 C0 0F 11 06 48 89 F0 48 83 C4 30 5E",
};

#else

constexpr Signatures kClient{
    .name = MINECRAFT_CLIENT,
    .create_packet = "56 48 83 EC 30 48 89 CE 81 FA ? 01 00 00 0F 87 ? ? ? ? "
                     "89 D0 48 8D 0D ? ? ? ? 48 63 04 81 48 01 "
                     "C8 FF E0 0F 57 C0 0F 11 06 48 89 F0 48 83 C4 30 5E",
};

#endif

#elif MINECRAFT_VERSION_HEX >= MINECRAFT_VERSION(1, 26, 70, 0)

#error "no Windows release patterns for the 1.26.70 line; it is preview only so far"

#elif MINECRAFT_VERSION_HEX >= MINECRAFT_VERSION(1, 26, 60, 0)

constexpr Signatures kClient{
    .name = MINECRAFT_CLIENT,
    .create_packet = "56 48 83 EC 20 48 89 CE 81 FA ? 01 00 00 77 ? 89 D0 48 "
                     "8D 0D ? ? ? ? 48 63 04 81 48 01 C8 FF E0 "
                     "0F 57 C0 0F 11 06 48 89 F0 48 83 C4 20 5E",
    .send = "55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC 08 01 00 00 48 8D AC "
            "24 80 00 00 00 48 C7 85 80 00 00 00 FE FF FF FF 45 89 CD 4C 89 C6 "
            "48 89 CB 48 8D 4D A8 41 B8 B0 00 00 00 48 89 55 78 E8 ? ? ? ? 48 8B 0D "
            "? ? ? ? 48 8B 01 48 8B 40 08 BA B8 00 00 00 FF 15 ? ? ? ?",
    .send_internal_call = "48 89 D9 48 8B 55 78 49 89 F0 E8",
};

#else

constexpr Signatures kClient{
    .name = MINECRAFT_CLIENT,
    .create_packet = "56 48 83 EC 20 48 89 CE 81 FA ? 01 00 00 77 ? 89 D0 48 "
                     "8D 0D ? ? ? ? 48 63 04 81 48 01 C8 FF E0 "
                     "0F 57 C0 0F 11 06 48 89 F0 48 83 C4 20 5E",
    .send = "55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC 08 01 00 00 48 8D AC "
            "24 80 00 00 00 48 C7 85 80 00 00 00 FE FF FF FF 45 89 CD 4C 89 C6 "
            "48 89 D7 48 89 CB 48 8D 4D B0 41 B8 B0 00 00 00 E8 ? ? ? ? 48 8B 0D "
            "? ? ? ? 48 8B 01 48 8B 40 08 BA B8 00 00 00 FF 15 ? ? ? ?",
    .send_internal_call = "48 89 D9 48 89 FA 49 89 F0 E8",
};

#endif

using Version = std::array<unsigned, 4>;

bool client_is_preview()
{
    constexpr std::wstring_view name = L"Minecraft Preview";
    const auto rdata = hat::process::get_process_module().get_section_data(".rdata");
    const auto *const bytes = reinterpret_cast<const std::byte *>(name.data());
    return std::search(rdata.begin(), rdata.end(), bytes, bytes + name.size() * sizeof(wchar_t)) != rdata.end();
}

std::optional<Version> version_from_package()
{
    UINT32 length = 0;
    if (GetCurrentPackageFullName(&length, nullptr) != ERROR_INSUFFICIENT_BUFFER) {
        return std::nullopt;
    }
    std::wstring package(length, L'\0');
    if (GetCurrentPackageFullName(&length, package.data()) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    package.resize(length - 1);

    const auto first = package.find(L'_');
    const auto second = first == std::wstring::npos ? first : package.find(L'_', first + 1);
    if (second == std::wstring::npos) {
        return std::nullopt;
    }

    std::array<unsigned, 3> numbers{};
    std::wstring_view fields{package.data() + first + 1, second - first - 1};
    for (auto &number : numbers) {
        const auto dot = fields.find(L'.');
        number = static_cast<unsigned>(std::wcstoul(std::wstring{fields.substr(0, dot)}.c_str(), nullptr, 10));
        fields = dot == std::wstring_view::npos ? std::wstring_view{} : fields.substr(dot + 1);
    }
    return Version{numbers[0], numbers[1], numbers[2] / 100, numbers[2] % 100};
}

std::optional<Version> version_from_resource()
{
    auto *const self = GetModuleHandleW(nullptr);
    auto *const found = FindResourceW(self, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION);
    auto *const loaded = found != nullptr ? LoadResource(self, found) : nullptr;
    auto *const block = loaded != nullptr ? LockResource(loaded) : nullptr;

    VS_FIXEDFILEINFO *info = nullptr;
    UINT size = 0;
    if (block == nullptr || VerQueryValueW(block, L"\\", reinterpret_cast<void **>(&info), &size) == 0 ||
        size < sizeof(VS_FIXEDFILEINFO)) {
        return std::nullopt;
    }
    return Version{HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS), HIWORD(info->dwFileVersionLS),
                   LOWORD(info->dwFileVersionLS)};
}

}

const Signatures &signatures()
{
    return kClient;
}

void verify_client()
{
    if (client_is_preview() != static_cast<bool>(MINECRAFT_PREVIEW)) {
        throw std::runtime_error{std::format("built for {} but this is the {} client, load the other DLL",
                                             MINECRAFT_CLIENT, MINECRAFT_PREVIEW ? "release" : "preview")};
    }
    auto version = version_from_package();
    if (!version) {
        version = version_from_resource();
    }
    if (version && MINECRAFT_VERSION((*version)[0], (*version)[1], (*version)[2], 0) <
                       MINECRAFT_VERSION(MINECRAFT_VERSION_MAJOR, MINECRAFT_VERSION_MINOR, MINECRAFT_VERSION_PATCH, 0)) {
        throw std::runtime_error{std::format("built for {} but this client is {}.{}.{}.{}, load an older DLL",
                                             MINECRAFT_CLIENT, (*version)[0], (*version)[1], (*version)[2], (*version)[3])};
    }
}

}

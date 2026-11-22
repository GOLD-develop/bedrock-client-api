#include "bca/hook/hook.h"

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <exception>
#include <format>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <funchook.h>
#include <libhat/process.hpp>
#include <libhat/scanner.hpp>
#include <libhat/signature.hpp>

#include "bca/core/log.h"

namespace bca {
namespace {

std::mutex g_slot_mutex;
std::unordered_map<void **, void *> g_replaced;

template <typename Signature>
std::vector<const std::byte *> matches_in(const std::span<const std::byte> region, const Signature &signature)
{
    std::vector<const std::byte *> matches;
    for (const auto match : hat::find_all_pattern(region.begin(), region.end(), signature)) {
        matches.push_back(match.get());
    }
    return matches;
}

bool write_slot(void **slot, void *value)
{
    DWORD previous = 0;
    if (VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &previous) == 0) {
        return false;
    }
    std::atomic_ref<void *>{*slot}.store(value, std::memory_order_release);
    VirtualProtect(slot, sizeof(void *), previous, &previous);
    return true;
}

}

void *scan(const std::string_view pattern)
{
    const auto signature = hat::parse_signature(pattern);
    if (!signature.has_value()) {
        throw std::runtime_error{"malformed pattern"};
    }
    const auto text = hat::process::get_process_module().get_section_data(".text");
    if (text.empty()) {
        throw std::runtime_error{"the game's code section is not mapped yet"};
    }
    const auto matches = matches_in(text, signature.value());
    if (matches.empty()) {
        throw std::runtime_error{"pattern not found, this client build is not supported"};
    }
    if (matches.size() > 1) {
        throw std::runtime_error{std::format("pattern matches {} places, refusing to guess", matches.size())};
    }
    return const_cast<std::byte *>(matches.front());
}

void *scan_within(const void *begin, const std::size_t size, const std::string_view pattern)
{
    const auto signature = hat::parse_signature(pattern);
    if (!signature.has_value()) {
        throw std::runtime_error{"malformed pattern"};
    }
    const std::span<const std::byte> region{static_cast<const std::byte *>(begin), size};
    const auto matches = matches_in(region, signature.value());
    if (matches.size() != 1) {
        throw std::runtime_error{std::format("pattern matches {} places in the function, expected exactly one",
                                             matches.size())};
    }
    return const_cast<std::byte *>(matches.front());
}

void install_inline_hook(const std::string_view name, void *target, void *detour, void **trampoline)
{
    auto *const hook = funchook_create();
    if (hook == nullptr) {
        throw std::runtime_error{std::format("{}: funchook_create failed", name)};
    }
    *trampoline = target;
    if (funchook_prepare(hook, trampoline, detour) != FUNCHOOK_ERROR_SUCCESS ||
        funchook_install(hook, 0) != FUNCHOOK_ERROR_SUCCESS) {
        const std::string message{funchook_error_message(hook)};
        funchook_destroy(hook);
        throw std::runtime_error{std::format("{}: {}", name, message)};
    }
}

bool swap_vtable_slot(const std::string_view name, void **vtable, const std::size_t slot, void *detour)
{
    void **const entry = vtable + slot;
    const std::lock_guard lock{g_slot_mutex};
    if (g_replaced.contains(entry)) {
        return true;
    }
    void *const original = *entry;
    if (!write_slot(entry, detour)) {
        log_error(std::format("{}: the vtable slot could not be made writable", name));
        return false;
    }
    g_replaced.emplace(entry, original);
    return true;
}

void *original_in_slot(void **vtable, const std::size_t slot)
{
    const std::lock_guard lock{g_slot_mutex};
    const auto found = g_replaced.find(vtable + slot);
    return found == g_replaced.end() ? nullptr : found->second;
}

}

#pragma once

#include <cstddef>
#include <cstring>
#include <string_view>
#include <utility>

namespace bca {


void *scan(std::string_view pattern);

void *scan_within(const void *begin, std::size_t size, std::string_view pattern);


void install_inline_hook(std::string_view name, void *target, void *detour, void **trampoline);

bool swap_vtable_slot(std::string_view name, void **vtable, std::size_t slot, void *detour);

void *original_in_slot(void **vtable, std::size_t slot);


template <typename Member>
void *address_of(Member member)
{
    static_assert(sizeof(Member) >= sizeof(void *));
    void *address = nullptr;
    std::memcpy(&address, &member, sizeof(address));
    return address;
}

template <typename Member>
Member member_at(void *address)
{
    Member member{};
    std::memcpy(&member, &address, sizeof(address));
    return member;
}

template <typename Member, typename Self, typename... Args>
decltype(auto) call_original(void *address, Self *self, Args &&...args)
{
    return (self->*member_at<Member>(address))(std::forward<Args>(args)...);
}

}

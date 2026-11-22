#pragma once


#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

#include "bca/hook/hook.h"

namespace bca::game {


inline constexpr std::size_t kPacketGetIdSlot = 1;
inline constexpr std::size_t kPacketGetNameSlot = 2;
inline constexpr std::size_t kPacketReadSlot = 9;
inline constexpr std::size_t kPacketSenderSubIdOffset = 16;
inline constexpr std::size_t kPacketHandlerOffset = 32;

inline constexpr std::size_t kHandlerHandleSlot = 1;

inline constexpr std::size_t kStreamViewOffset = 40;
inline constexpr std::size_t kStreamReadPointerOffset = 56;
inline constexpr std::size_t kStreamOverflowOffset = 64;
inline constexpr std::size_t kStreamSize = 72;

inline constexpr std::size_t kIdentifierSize = 176;
inline constexpr std::size_t kIdentifierComparable = 172;
inline constexpr std::size_t kIdentifierTypeOffset = 168;

inline constexpr std::size_t kResultSize = 72;
inline constexpr std::size_t kResultOkOffset = 64;


class NetEventCallback;

struct NetworkIdentifier {
    alignas(8) unsigned char bytes[kIdentifierSize];
};
static_assert(sizeof(NetworkIdentifier) == kIdentifierSize);

[[nodiscard]] inline bool same_connection(const NetworkIdentifier &a, const NetworkIdentifier &b)
{
    return std::memcmp(a.bytes, b.bytes, kIdentifierComparable) == 0;
}

[[nodiscard]] inline int connection_type(const NetworkIdentifier &id)
{
    std::uint32_t type = 0;
    std::memcpy(&type, id.bytes + kIdentifierTypeOffset, sizeof(type));
    return static_cast<int>(type);
}

struct Result {
    alignas(8) unsigned char bytes[kResultSize];

    [[nodiscard]] bool ok() const { return bytes[kResultOkOffset] != 0; }

    [[nodiscard]] std::string message() const
    {
        if (ok()) {
            return {};
        }
        std::error_code code;
        std::memcpy(&code, bytes, sizeof(code));
        return code.message();
    }

    [[nodiscard]] static Result success()
    {
        Result result{};
        result.bytes[kResultOkOffset] = 1;
        return result;
    }

    [[nodiscard]] static Result seek_error()
    {
        Result result{};
        const auto code = std::make_error_code(std::errc::invalid_seek);
        std::memcpy(result.bytes, &code, sizeof(code));
        return result;
    }
};
static_assert(sizeof(Result) == kResultSize);
static_assert(sizeof(std::error_code) <= kResultOkOffset);

class ReadStream {
public:
    explicit ReadStream(const std::string_view bytes) : owned_(bytes), view_(owned_) {}
    ReadStream(const ReadStream &) = delete;
    ReadStream &operator=(const ReadStream &) = delete;
    virtual ~ReadStream() = default;

    virtual Result read(void *target, const std::uint64_t count)
    {
        if (overflowed_) {
            return Result::seek_error();
        }
        if (count == 0) {
            return Result::success();
        }
        if (const auto end = read_pointer_ + count; end < read_pointer_ || end > view_.size()) {
            overflowed_ = true;
            return Result::seek_error();
        }
        std::memcpy(target, view_.data() + read_pointer_, count);
        read_pointer_ += count;
        return Result::success();
    }

    [[nodiscard]] std::string_view view() const { return view_; }
    [[nodiscard]] std::size_t read_pointer() const { return read_pointer_; }

private:
    std::string owned_;
    std::string_view view_;
    std::size_t read_pointer_{0};
    bool overflowed_{false};
};
static_assert(sizeof(ReadStream) == kStreamSize);

struct Packet {
    Result readDetour(ReadStream &stream, const void *reflection_ctx);
};

struct PacketHandler {
    void handleDetour(const NetworkIdentifier &id, NetEventCallback &callback, std::shared_ptr<Packet> &packet) const;
};

struct NetworkSystem {
    void sendInternalDetour(const NetworkIdentifier &id, const Packet &packet, const std::string &bytes);
};

struct MinecraftPackets {
    static std::shared_ptr<Packet> createPacket(int id);
};


struct PacketCalls {
    int getId() const;
    std::string_view getName() const;
};

[[nodiscard]] inline void **vtable_of(const void *object)
{
    return *reinterpret_cast<void ***>(const_cast<void *>(object));
}

[[nodiscard]] inline int packet_id(const Packet *packet)
{
    return call_original<int (PacketCalls::*)() const>(vtable_of(packet)[kPacketGetIdSlot],
                                                       reinterpret_cast<const PacketCalls *>(packet));
}

[[nodiscard]] inline std::string_view packet_name(const Packet *packet)
{
    return call_original<std::string_view (PacketCalls::*)() const>(vtable_of(packet)[kPacketGetNameSlot],
                                                                    reinterpret_cast<const PacketCalls *>(packet));
}

[[nodiscard]] inline const PacketHandler *packet_handler(const Packet *packet)
{
    const PacketHandler *handler = nullptr;
    std::memcpy(&handler, reinterpret_cast<const unsigned char *>(packet) + kPacketHandlerOffset, sizeof(handler));
    return handler;
}

inline void set_sender_sub_id(Packet *packet, const std::uint8_t sub_client)
{
    std::memcpy(reinterpret_cast<unsigned char *>(packet) + kPacketSenderSubIdOffset, &sub_client, sizeof(sub_client));
}

inline void deliver(const PacketHandler *handler, const NetworkIdentifier &id, NetEventCallback &callback,
                    std::shared_ptr<Packet> &packet)
{
    call_original<void (PacketHandler::*)(const NetworkIdentifier &, NetEventCallback &, std::shared_ptr<Packet> &) const>(
        vtable_of(handler)[kHandlerHandleSlot], handler, id, callback, packet);
}

}

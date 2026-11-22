#include "bca/script/runtime.h"

#include <quickjs.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "bca/core/log.h"
#include "bca/core/paths.h"
#include "bca/net/network.h"
#include "bca/script/files.h"
#include "bca/script/modules.h"
#include "bca/script/permissions.h"
#include "bca/script/web.h"


namespace bca::script {
namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

constexpr std::size_t kIdLimit = 512;
constexpr std::size_t kScriptLimit = 64;
constexpr std::size_t kSubscriptionLimit = 4096;
constexpr std::size_t kTimerLimit = 256;
constexpr std::size_t kMaxBody = 1U << 20U;
constexpr std::size_t kMaxSource = 4U << 20U;
constexpr auto kCallbackBudget = 100ms;
constexpr auto kLoadBudget = 2000ms;
constexpr auto kScanInterval = 1000ms;
constexpr std::size_t kRequestLimit = 32;
constexpr std::size_t kSocketLimit = 8;
constexpr std::size_t kQueueLimit = 4096;

struct Subscription {
    int handle;
    int id;
    int mask;
    JSValue callback;
};

struct Timer {
    int handle;
    Clock::time_point due;
    std::chrono::milliseconds interval;
    JSValue callback;
};

struct Request {
    JSValue resolve;
    JSValue reject;
};

struct SocketEntry {
    std::shared_ptr<web::Socket> socket;
    JSValue callback;
};

struct Script {
    std::string name;
    std::filesystem::path path;
    std::filesystem::file_time_type stamp;
    JSContext *ctx{nullptr};
    int serial{0};
    unsigned grants{0};
    std::filesystem::path data_root;
    std::map<std::string, std::filesystem::file_time_type> dependencies;
    std::vector<Subscription> subscriptions;
    std::vector<Timer> timers;
    std::map<int, Request> requests;
    std::map<int, SocketEntry> sockets;
    int next_handle{1};
};

struct Completion {
    int serial;
    std::function<void(Script &)> run;
};

std::mutex g_mutex;
std::atomic_int g_ticker_waiting{0};
JSRuntime *g_runtime = nullptr;
std::vector<std::unique_ptr<Script>> g_scripts;
std::vector<std::string> g_names;
Sender g_sender = nullptr;
Clock::time_point g_deadline;
Clock::time_point g_next_scan;
std::map<std::string, std::filesystem::file_time_type> g_failed;
int g_folder_state = 0;
bool g_told_empty = false;
bool g_loading = false;
std::string g_permission_problems;
std::atomic<int> g_next_serial{1};
std::mutex g_queue_mutex;
std::vector<Completion> g_queue;

std::array<std::array<std::atomic<std::uint16_t>, kIdLimit>, 4> g_watching{};

void watch(const int mask, const int id, const bool add)
{
    for (std::size_t slot = 0; slot < 4; ++slot) {
        if ((mask & (1 << slot)) != 0) {
            auto &count = g_watching[slot][static_cast<std::size_t>(id)];
            if (add) {
                count.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                count.fetch_sub(1, std::memory_order_relaxed);
            }
        }
    }
}


std::string text_of(JSContext *ctx, JSValueConst value)
{
    const auto *const chars = JS_ToCString(ctx, value);
    if (chars == nullptr) {
        JS_FreeValue(ctx, JS_GetException(ctx));
        return "<unprintable>";
    }
    std::string text{chars};
    JS_FreeCString(ctx, chars);
    return text;
}

std::string error_text(JSContext *ctx, JSValueConst error)
{
    auto text = text_of(ctx, error);
    if (JS_IsObject(error)) {
        const auto stack = JS_GetPropertyStr(ctx, error, "stack");
        if (!JS_IsUndefined(stack)) {
            text += '\n';
            text += text_of(ctx, stack);
        }
        JS_FreeValue(ctx, stack);
    }
    return text;
}

std::string exception_text(JSContext *ctx)
{
    const auto exception = JS_GetException(ctx);
    auto text = error_text(ctx, exception);
    JS_FreeValue(ctx, exception);
    return text;
}

Script *script_of(JSContext *ctx)
{
    return static_cast<Script *>(JS_GetContextOpaque(ctx));
}

void say(const Script *script, const std::string_view text, const bool error)
{
    log_line(script != nullptr ? script->name : std::string{"bedrock-client-api"}, text, error);
}

std::optional<std::string> bytes_of(JSContext *ctx, JSValueConst value)
{
    const auto typed = JS_GetTypedArrayType(value) >= 0;
    std::size_t offset = 0;
    std::size_t length = 0;
    std::size_t element = 0;
    auto buffer = JS_DupValue(ctx, value);
    if (typed) {
        JS_FreeValue(ctx, buffer);
        buffer = JS_GetTypedArrayBuffer(ctx, value, &offset, &length, &element);
        if (JS_IsException(buffer)) {
            JS_FreeValue(ctx, JS_GetException(ctx));
            return std::nullopt;
        }
    }
    std::size_t size = 0;
    const auto *const data = JS_GetArrayBuffer(ctx, &size, buffer);
    if (data == nullptr) {
        const auto exception = JS_GetException(ctx);
        const auto failed = !JS_IsNull(exception) && !JS_IsUndefined(exception);
        JS_FreeValue(ctx, exception);
        JS_FreeValue(ctx, buffer);
        if (failed) {
            return std::nullopt;
        }
        return std::string{};
    }
    std::string bytes{reinterpret_cast<const char *>(data) + offset, typed ? length : size};
    JS_FreeValue(ctx, buffer);
    return bytes;
}

std::string hex_of(const std::string_view bytes, const std::size_t limit)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    const auto count = std::min(bytes.size(), limit);
    for (std::size_t i = 0; i < count; ++i) {
        if (i != 0) {
            text += ' ';
        }
        const auto byte = static_cast<std::uint8_t>(bytes[i]);
        text += kDigits[byte >> 4U];
        text += kDigits[byte & 0xFU];
    }
    if (count < bytes.size()) {
        text += " ...";
    }
    return text;
}

std::string describe(JSContext *ctx, JSValueConst value)
{
    if (JS_IsObject(value) && !JS_IsFunction(ctx, value)) {
        if (JS_GetTypedArrayType(value) >= 0) {
            if (const auto bytes = bytes_of(ctx, value)) {
                return std::format("<{} bytes: {}>", bytes->size(), hex_of(*bytes, 64));
            }
        }
        const auto json = JS_JSONStringify(ctx, value, JS_UNDEFINED, JS_UNDEFINED);
        auto text = JS_IsException(json) ? text_of(ctx, value) : text_of(ctx, json);
        JS_FreeValue(ctx, json);
        return text;
    }
    return text_of(ctx, value);
}

void drain_jobs()
{
    JSContext *job_ctx = nullptr;
    for (auto status = JS_ExecutePendingJob(g_runtime, &job_ctx); status != 0;
         status = JS_ExecutePendingJob(g_runtime, &job_ctx)) {
        if (status < 0 && job_ctx != nullptr) {
            say(script_of(job_ctx), exception_text(job_ctx), true);
        }
    }
}

JSValue call(Script &script, JSValueConst function, const int argc, JSValueConst *argv)
{
    JS_UpdateStackTop(g_runtime);
    g_deadline = Clock::now() + kCallbackBudget;
    auto result = JS_Call(script.ctx, function, JS_UNDEFINED, argc, argv);
    if (JS_IsException(result)) {
        say(&script, exception_text(script.ctx), true);
    }
    return result;
}


JSValue native_names(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto names = JS_NewArray(ctx);
    for (std::size_t i = 0; i < g_names.size(); ++i) {
        JS_SetPropertyUint32(ctx, names, static_cast<std::uint32_t>(i), JS_NewString(ctx, g_names[i].c_str()));
    }
    return names;
}

JSValue native_subscribe(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    auto *const script = script_of(ctx);
    std::int32_t id = 0;
    std::int32_t mask = 0;
    if (script == nullptr || argc < 3 || JS_ToInt32(ctx, &id, argv[0]) != 0 || JS_ToInt32(ctx, &mask, argv[1]) != 0 ||
        !JS_IsFunction(ctx, argv[2])) {
        return JS_ThrowTypeError(ctx, "subscribe(packetId, directionMask, callback)");
    }
    if (id < 1 || id >= static_cast<std::int32_t>(std::min(g_names.size(), kIdLimit)) || mask < 1 || mask > 15) {
        return JS_ThrowRangeError(ctx, "packet id or direction out of range");
    }
    if (script->subscriptions.size() >= kSubscriptionLimit) {
        return JS_ThrowRangeError(ctx, "too many subscriptions");
    }
    const auto handle = script->next_handle++;
    script->subscriptions.push_back({handle, id, mask, JS_DupValue(ctx, argv[2])});
    watch(mask, id, true);
    return JS_NewInt32(ctx, handle);
}

JSValue native_unsubscribe(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    auto *const script = script_of(ctx);
    std::int32_t handle = 0;
    if (script == nullptr || argc < 1 || JS_ToInt32(ctx, &handle, argv[0]) != 0) {
        return JS_ThrowTypeError(ctx, "unsubscribe(handle)");
    }
    auto &list = script->subscriptions;
    const auto found = std::ranges::find(list, handle, &Subscription::handle);
    if (found == list.end()) {
        return JS_FALSE;
    }
    watch(found->mask, found->id, false);
    JS_FreeValue(ctx, found->callback);
    list.erase(found);
    return JS_TRUE;
}

JSValue native_send(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    std::int32_t id = 0;
    std::int32_t direction = 0;
    std::int32_t side = 0;
    std::int32_t player = -1;
    if (argc < 3 || JS_ToInt32(ctx, &id, argv[0]) != 0 || JS_ToInt32(ctx, &direction, argv[2]) != 0 ||
        (direction != 0 && direction != 1) || (argc > 3 && JS_ToInt32(ctx, &side, argv[3]) != 0) ||
        (side != 0 && side != 1) || (argc > 4 && JS_ToInt32(ctx, &player, argv[4]) != 0)) {
        return JS_ThrowTypeError(ctx, "send(packetId, bytes, direction, side, player)");
    }
    const auto bytes = bytes_of(ctx, argv[1]);
    if (!bytes) {
        return JS_ThrowTypeError(ctx, "the packet body must be a Uint8Array or an ArrayBuffer");
    }
    if (g_sender == nullptr || bytes->size() > kMaxBody) {
        return JS_FALSE;
    }
    return JS_NewBool(ctx, g_sender(static_cast<Side>(side), static_cast<Direction>(direction), id, *bytes, player));
}

JSValue native_utf8_decode(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    const auto bytes = argc < 1 ? std::nullopt : bytes_of(ctx, argv[0]);
    if (!bytes) {
        return JS_ThrowTypeError(ctx, "utf8Decode(bytes) needs a Uint8Array or an ArrayBuffer");
    }
    return JS_NewStringLen(ctx, bytes->data(), bytes->size());
}

JSValue native_utf8_encode(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "utf8Encode(text)");
    }
    std::size_t length = 0;
    const auto *const chars = JS_ToCStringLen(ctx, &length, argv[0]);
    if (chars == nullptr) {
        return JS_EXCEPTION;
    }
    const auto result = JS_NewUint8ArrayCopy(ctx, reinterpret_cast<const std::uint8_t *>(chars), length);
    JS_FreeCString(ctx, chars);
    return result;
}

JSValue native_login_of(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    std::int32_t player = 0;
    if (argc < 1 || JS_ToInt32(ctx, &player, argv[0]) != 0) {
        return JS_ThrowTypeError(ctx, "loginOf(connection)");
    }
    const auto login = bca::net::login_of(player);
    if (!login) {
        return JS_UNDEFINED;
    }
    return JS_NewUint8ArrayCopy(ctx, reinterpret_cast<const std::uint8_t *>(login->data()), login->size());
}

JSValue native_start_game_of(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    std::int32_t player = 0;
    if (argc < 1 || JS_ToInt32(ctx, &player, argv[0]) != 0) {
        return JS_ThrowTypeError(ctx, "startGameOf(connection)");
    }
    const auto body = bca::net::start_game_of(player);
    if (!body) {
        return JS_UNDEFINED;
    }
    return JS_NewUint8ArrayCopy(ctx, reinterpret_cast<const std::uint8_t *>(body->data()), body->size());
}

JSValue native_last_packet(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    std::int32_t id = 0;
    if (argc < 1 || JS_ToInt32(ctx, &id, argv[0]) != 0) {
        return JS_ThrowTypeError(ctx, "lastPacket(packetId)");
    }
    const auto body = bca::net::last_received(id);
    if (!body) {
        return JS_UNDEFINED;
    }
    return JS_NewUint8ArrayCopy(ctx, reinterpret_cast<const std::uint8_t *>(body->data()), body->size());
}

JSValue native_hooks(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto &status = bca::net::status();
    const auto object = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, object, "createPacket", JS_NewBool(ctx, status.create_packet));
    JS_SetPropertyStr(ctx, object, "sendInternal", JS_NewBool(ctx, status.send_internal));
    JS_SetPropertyStr(ctx, object, "handlers", JS_NewInt32(ctx, static_cast<std::int32_t>(status.handlers)));
    JS_SetPropertyStr(ctx, object, "packetClasses", JS_NewInt32(ctx, static_cast<std::int32_t>(status.packet_classes)));
    return object;
}

JSValue native_game(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto object = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, object, "major", JS_NewInt32(ctx, MINECRAFT_VERSION_MAJOR));
    JS_SetPropertyStr(ctx, object, "minor", JS_NewInt32(ctx, MINECRAFT_VERSION_MINOR));
    JS_SetPropertyStr(ctx, object, "patch", JS_NewInt32(ctx, MINECRAFT_VERSION_PATCH));
    JS_SetPropertyStr(ctx, object, "build", JS_NewInt32(ctx, MINECRAFT_VERSION_BUILD));
    JS_SetPropertyStr(ctx, object, "preview", JS_NewBool(ctx, MINECRAFT_PREVIEW != 0));
    return object;
}

JSValue native_known_connections(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto list = JS_NewArray(ctx);
    std::uint32_t at = 0;
    for (const auto player : bca::net::known_logins()) {
        JS_SetPropertyUint32(ctx, list, at++, JS_NewInt32(ctx, player));
    }
    return list;
}


std::optional<std::string> decode_base64(const std::string_view text)
{
    static const auto table = [] {
        std::array<std::int8_t, 256> values{};
        values.fill(-1);
        constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (std::size_t i = 0; i < kAlphabet.size(); ++i) {
            values[static_cast<std::uint8_t>(kAlphabet[i])] = static_cast<std::int8_t>(i);
        }
        values[static_cast<std::uint8_t>('-')] = 62;
        values[static_cast<std::uint8_t>('_')] = 63;
        return values;
    }();
    std::string out;
    out.reserve(text.size() / 4 * 3 + 3);
    std::uint32_t buffer = 0;
    int bits = 0;
    for (const char c : text) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') {
            continue;
        }
        const auto value = table[static_cast<std::uint8_t>(c)];
        if (value < 0) {
            return std::nullopt;
        }
        buffer = (buffer << 6U) | static_cast<std::uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> static_cast<unsigned>(bits)) & 0xFFU));
        }
    }
    if (bits >= 6) {
        return std::nullopt;
    }
    return out;
}

std::string encode_base64(const std::string_view bytes, const bool url)
{
    const char *const alphabet = url ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                                     : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    std::uint32_t buffer = 0;
    int bits = 0;
    for (const char c : bytes) {
        buffer = (buffer << 8U) | static_cast<std::uint8_t>(c);
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(alphabet[(buffer >> static_cast<unsigned>(bits)) & 0x3FU]);
        }
    }
    if (bits > 0) {
        out.push_back(alphabet[(buffer << static_cast<unsigned>(6 - bits)) & 0x3FU]);
    }
    if (!url) {
        while (out.size() % 4 != 0) {
            out.push_back('=');
        }
    }
    return out;
}

JSValue native_base64_decode(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "base64Decode(text)");
    }
    std::size_t length = 0;
    const auto *const chars = JS_ToCStringLen(ctx, &length, argv[0]);
    if (chars == nullptr) {
        return JS_EXCEPTION;
    }
    const auto decoded = decode_base64(std::string_view{chars, length});
    JS_FreeCString(ctx, chars);
    if (!decoded) {
        return JS_ThrowRangeError(ctx, "not valid base64");
    }
    return JS_NewUint8ArrayCopy(ctx, reinterpret_cast<const std::uint8_t *>(decoded->data()), decoded->size());
}

JSValue native_base64_encode(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    const auto bytes = argc < 1 ? std::nullopt : bytes_of(ctx, argv[0]);
    if (!bytes) {
        return JS_ThrowTypeError(ctx, "base64Encode(bytes, url) needs a Uint8Array or an ArrayBuffer");
    }
    const auto text = encode_base64(*bytes, argc > 1 && JS_ToBool(ctx, argv[1]) > 0);
    return JS_NewStringLen(ctx, text.data(), text.size());
}

JSValue native_console(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv, const int magic)
{
    std::string line = magic == 2 ? "warning: " : "";
    for (int i = 0; i < argc; ++i) {
        if (i != 0) {
            line += ' ';
        }
        line += describe(ctx, argv[i]);
    }
    say(script_of(ctx), line, magic == 3);
    return JS_UNDEFINED;
}

JSValue native_timer(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv, const int repeat)
{
    auto *const script = script_of(ctx);
    if (script == nullptr) {
        return JS_ThrowInternalError(ctx, "the script is unloaded");
    }
    if (argc < 1 || !JS_IsFunction(ctx, argv[0])) {
        return JS_ThrowTypeError(ctx, "expected a function");
    }
    if (script->timers.size() >= kTimerLimit) {
        return JS_ThrowRangeError(ctx, "too many timers");
    }
    double delay = 0;
    if (argc > 1) {
        JS_ToFloat64(ctx, &delay, argv[1]);
    }
    const std::chrono::milliseconds wait{static_cast<std::int64_t>(delay >= 1 ? std::min(delay, 2147483647.0) : 1)};
    const auto handle = script->next_handle++;
    script->timers.push_back({handle, Clock::now() + wait, repeat != 0 ? wait : 0ms, JS_DupValue(ctx, argv[0])});
    return JS_NewInt32(ctx, handle);
}

JSValue native_clear_timer(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    auto *const script = script_of(ctx);
    std::int32_t handle = 0;
    if (script == nullptr || argc < 1 || JS_ToInt32(ctx, &handle, argv[0]) != 0) {
        return JS_UNDEFINED;
    }
    auto &list = script->timers;
    if (const auto found = std::ranges::find(list, handle, &Timer::handle); found != list.end()) {
        JS_FreeValue(ctx, found->callback);
        list.erase(found);
    }
    return JS_UNDEFINED;
}



std::optional<std::string> string_arg(JSContext *ctx, JSValueConst value)
{
    if (!JS_IsString(value)) {
        return std::nullopt;
    }
    std::size_t length = 0;
    const auto *const chars = JS_ToCStringLen(ctx, &length, value);
    if (chars == nullptr) {
        JS_FreeValue(ctx, JS_GetException(ctx));
        return std::nullopt;
    }
    std::string text{chars, length};
    JS_FreeCString(ctx, chars);
    return text;
}

std::optional<std::string> string_property(JSContext *ctx, JSValueConst object, const char *name)
{
    const auto value = JS_GetPropertyStr(ctx, object, name);
    auto text = string_arg(ctx, value);
    JS_FreeValue(ctx, value);
    return text;
}

web::Headers flat_headers(JSContext *ctx, JSValueConst list)
{
    web::Headers headers;
    if (!JS_IsObject(list)) {
        return headers;
    }
    const auto length_value = JS_GetPropertyStr(ctx, list, "length");
    std::uint32_t length = 0;
    if (JS_ToUint32(ctx, &length, length_value) != 0) {
        JS_FreeValue(ctx, JS_GetException(ctx));
        length = 0;
    }
    JS_FreeValue(ctx, length_value);
    for (std::uint32_t i = 0; i + 1 < length && i < 512; i += 2) {
        const auto name = JS_GetPropertyUint32(ctx, list, i);
        const auto value = JS_GetPropertyUint32(ctx, list, i + 1);
        auto name_text = string_arg(ctx, name);
        auto value_text = string_arg(ctx, value);
        if (name_text && value_text) {
            headers.emplace_back(std::move(*name_text), std::move(*value_text));
        }
        JS_FreeValue(ctx, name);
        JS_FreeValue(ctx, value);
    }
    return headers;
}

void post(const int serial, std::function<void(Script &)> run)
{
    const std::lock_guard lock{g_queue_mutex};
    if (g_queue.size() < kQueueLimit) {
        g_queue.push_back({serial, std::move(run)});
    }
}

JSValue native_script_name(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto *const script = script_of(ctx);
    return JS_NewString(ctx, script != nullptr ? script->name.c_str() : "");
}

JSValue native_permitted(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    const auto *const script = script_of(ctx);
    const auto what = argc < 1 ? std::nullopt : string_arg(ctx, argv[0]);
    if (script == nullptr || !what) {
        return JS_FALSE;
    }
    unsigned grant = 0;
    if (*what == "fs") {
        grant = kGrantFiles;
    }
    else if (*what == "http") {
        grant = kGrantHttp;
    }
    else if (*what == "websocket") {
        grant = kGrantWebSocket;
    }
    return JS_NewBool(ctx, (script->grants & grant) != 0);
}

template <typename Fn>
JSValue with_files(JSContext *ctx, const int argc, JSValueConst *argv, Fn &&fn)
{
    auto *const script = script_of(ctx);
    if (script == nullptr || (script->grants & kGrantFiles) == 0) {
        return JS_ThrowInternalError(ctx, "EACCES: this script is not allowed to use files");
    }
    const auto path = argc < 1 ? std::nullopt : string_arg(ctx, argv[0]);
    if (!path) {
        return JS_ThrowTypeError(ctx, "a path must be a string");
    }
    std::error_code ec;
    std::filesystem::create_directories(script->data_root, ec);
    if (ec && !std::filesystem::is_directory(script->data_root)) {
        return JS_ThrowInternalError(ctx, "EACCES: cannot create the script's folder '%s': %s",
                                     utf8(script->data_root).c_str(), ec.message().c_str());
    }
    try {
        return fn(script->data_root, *path);
    }
    catch (const std::exception &e) {
        return JS_ThrowInternalError(ctx, "%s", e.what());
    }
}

JSValue native_fs_read(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    return with_files(ctx, argc, argv, [&](const std::filesystem::path &root, const std::string &path) {
        const auto data = files::read(root, path);
        return JS_NewUint8ArrayCopy(ctx, reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
    });
}

JSValue native_fs_write(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    return with_files(ctx, argc, argv, [&](const std::filesystem::path &root, const std::string &path) {
        const auto data = argc < 2 ? std::nullopt : bytes_of(ctx, argv[1]);
        if (!data) {
            return JS_ThrowTypeError(ctx, "fs: data must be a Uint8Array");
        }
        files::write(root, path, *data, argc > 2 && JS_ToBool(ctx, argv[2]) > 0);
        return JS_UNDEFINED;
    });
}

JSValue native_fs_exists(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    return with_files(ctx, argc, argv, [&](const std::filesystem::path &root, const std::string &path) {
        return JS_NewBool(ctx, files::exists(root, path));
    });
}

JSValue native_fs_mkdir(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    return with_files(ctx, argc, argv, [&](const std::filesystem::path &root, const std::string &path) {
        files::make_directory(root, path, argc > 1 && JS_ToBool(ctx, argv[1]) > 0);
        return JS_UNDEFINED;
    });
}

JSValue native_fs_list(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    return with_files(ctx, argc, argv, [&](const std::filesystem::path &root, const std::string &path) {
        const auto names = files::list(root, path);
        const auto list = JS_NewArray(ctx);
        for (std::size_t i = 0; i < names.size(); ++i) {
            JS_SetPropertyUint32(ctx, list, static_cast<std::uint32_t>(i), JS_NewString(ctx, names[i].c_str()));
        }
        return list;
    });
}

JSValue native_fs_remove(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    return with_files(ctx, argc, argv, [&](const std::filesystem::path &root, const std::string &path) {
        files::remove(root, path, argc > 1 && JS_ToBool(ctx, argv[1]) > 0, argc > 2 && JS_ToBool(ctx, argv[2]) > 0);
        return JS_UNDEFINED;
    });
}

JSValue native_fs_stat(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    return with_files(ctx, argc, argv, [&](const std::filesystem::path &root, const std::string &path) {
        const auto info = files::stat(root, path);
        if (!info.found) {
            return JS_NULL;
        }
        const auto object = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, object, "size", JS_NewFloat64(ctx, static_cast<double>(info.size)));
        JS_SetPropertyStr(ctx, object, "mtimeMs", JS_NewFloat64(ctx, info.mtime_ms));
        JS_SetPropertyStr(ctx, object, "isFile", JS_NewBool(ctx, info.is_file));
        JS_SetPropertyStr(ctx, object, "isDirectory", JS_NewBool(ctx, info.is_directory));
        return object;
    });
}

void finish_request(Script &script, const int id, const web::HttpResponse &response)
{
    const auto found = script.requests.find(id);
    if (found == script.requests.end()) {
        return;
    }
    const auto request = found->second;
    script.requests.erase(found);
    auto *const ctx = script.ctx;

    JSValue value;
    JSValue settle;
    if (!response.error.empty()) {
        value = JS_NewError(ctx);
        JS_SetPropertyStr(ctx, value, "message", JS_NewString(ctx, response.error.c_str()));
        settle = request.reject;
    }
    else {
        value = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, value, "status", JS_NewInt32(ctx, response.status));
        const auto headers = JS_NewArray(ctx);
        std::uint32_t at = 0;
        for (const auto &[name, text] : response.headers) {
            JS_SetPropertyUint32(ctx, headers, at++, JS_NewString(ctx, name.c_str()));
            JS_SetPropertyUint32(ctx, headers, at++, JS_NewString(ctx, text.c_str()));
        }
        JS_SetPropertyStr(ctx, value, "headers", headers);
        JS_SetPropertyStr(ctx, value, "body",
                          JS_NewUint8ArrayCopy(ctx, reinterpret_cast<const std::uint8_t *>(response.body.data()),
                                               response.body.size()));
        settle = request.resolve;
    }
    JS_FreeValue(ctx, call(script, settle, 1, &value));
    JS_FreeValue(ctx, value);
    JS_FreeValue(ctx, request.resolve);
    JS_FreeValue(ctx, request.reject);
}

JSValue native_http_request(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    auto *const script = script_of(ctx);
    if (script == nullptr || (script->grants & kGrantHttp) == 0) {
        return JS_ThrowInternalError(ctx, "EACCES: this script is not allowed to use the network");
    }
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "httpRequest({ url, method, headers, body, timeout })");
    }
    if (script->requests.size() >= kRequestLimit) {
        return JS_ThrowRangeError(ctx, "too many web requests at once");
    }
    web::HttpRequest request;
    const auto url = string_property(ctx, argv[0], "url");
    if (!url) {
        return JS_ThrowTypeError(ctx, "the request needs a url");
    }
    request.url = *url;
    if (const auto method = string_property(ctx, argv[0], "method")) {
        request.method = *method;
    }
    const auto headers = JS_GetPropertyStr(ctx, argv[0], "headers");
    request.headers = flat_headers(ctx, headers);
    JS_FreeValue(ctx, headers);
    const auto body = JS_GetPropertyStr(ctx, argv[0], "body");
    if (!JS_IsNull(body) && !JS_IsUndefined(body)) {
        auto bytes = bytes_of(ctx, body);
        if (!bytes) {
            JS_FreeValue(ctx, body);
            return JS_ThrowTypeError(ctx, "the body must be bytes");
        }
        request.body = std::move(*bytes);
    }
    JS_FreeValue(ctx, body);
    const auto timeout = JS_GetPropertyStr(ctx, argv[0], "timeout");
    double timeout_ms = 0;
    if (JS_ToFloat64(ctx, &timeout_ms, timeout) == 0 && timeout_ms >= 1) {
        request.timeout_ms = static_cast<int>(std::min(timeout_ms, 600000.0));
    }
    JS_FreeValue(ctx, timeout);

    JSValue functions[2];
    const auto promise = JS_NewPromiseCapability(ctx, functions);
    if (JS_IsException(promise)) {
        return promise;
    }
    const auto id = script->next_handle++;
    script->requests.emplace(id, Request{functions[0], functions[1]});
    std::thread{[serial = script->serial, id, request = std::move(request)] {
        auto response = web::perform(request);
        post(serial, [id, response = std::move(response)](Script &s) { finish_request(s, id, response); });
    }}.detach();
    return promise;
}

void deliver_socket_event(Script &script, const int id, const web::SocketEvent &event)
{
    const auto found = script.sockets.find(id);
    if (found == script.sockets.end()) {
        return;
    }
    auto *const ctx = script.ctx;
    const auto callback = JS_DupValue(ctx, found->second.callback);
    JSValue arguments[3] = {JS_UNDEFINED, JS_UNDEFINED, JS_UNDEFINED};
    int count = 1;
    switch (event.kind) {
    case web::SocketEvent::Kind::Open:
        arguments[0] = JS_NewString(ctx, "open");
        break;
    case web::SocketEvent::Kind::Message:
        arguments[0] = JS_NewString(ctx, "message");
        arguments[1] = event.binary ? JS_NewUint8ArrayCopy(ctx, reinterpret_cast<const std::uint8_t *>(event.data.data()),
                                                           event.data.size())
                                    : JS_NewStringLen(ctx, event.data.data(), event.data.size());
        count = 2;
        break;
    case web::SocketEvent::Kind::Close:
        arguments[0] = JS_NewString(ctx, "close");
        arguments[1] = JS_NewInt32(ctx, event.code);
        arguments[2] = JS_NewStringLen(ctx, event.data.data(), event.data.size());
        count = 3;
        break;
    case web::SocketEvent::Kind::Error:
        arguments[0] = JS_NewString(ctx, "error");
        arguments[1] = JS_NewStringLen(ctx, event.data.data(), event.data.size());
        count = 2;
        break;
    }
    JS_FreeValue(ctx, call(script, callback, count, arguments));
    for (auto &argument : arguments) {
        JS_FreeValue(ctx, argument);
    }
    JS_FreeValue(ctx, callback);
    if (event.kind == web::SocketEvent::Kind::Close) {
        if (const auto again = script.sockets.find(id); again != script.sockets.end()) {
            JS_FreeValue(ctx, again->second.callback);
            script.sockets.erase(again);
        }
    }
}

JSValue native_ws_open(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    auto *const script = script_of(ctx);
    if (script == nullptr || (script->grants & kGrantWebSocket) == 0) {
        return JS_ThrowInternalError(ctx, "EACCES: this script is not allowed to use sockets");
    }
    const auto url = argc < 1 ? std::nullopt : string_arg(ctx, argv[0]);
    if (!url || argc < 3 || !JS_IsFunction(ctx, argv[2])) {
        return JS_ThrowTypeError(ctx, "wsOpen(url, headers, callback)");
    }
    if (script->sockets.size() >= kSocketLimit) {
        return JS_ThrowRangeError(ctx, "too many WebSockets at once");
    }
    const auto id = script->next_handle++;
    std::shared_ptr<web::Socket> socket;
    try {
        socket = web::Socket::open(*url, flat_headers(ctx, argv[1]), [serial = script->serial, id](web::SocketEvent event) {
            post(serial, [id, event = std::move(event)](Script &s) { deliver_socket_event(s, id, event); });
        });
    }
    catch (const std::exception &e) {
        return JS_ThrowInternalError(ctx, "%s", e.what());
    }
    script->sockets.emplace(id, SocketEntry{std::move(socket), JS_DupValue(ctx, argv[2])});
    return JS_NewInt32(ctx, id);
}

std::shared_ptr<web::Socket> socket_of(JSContext *ctx, JSValueConst id_value)
{
    auto *const script = script_of(ctx);
    std::int32_t id = 0;
    if (script == nullptr || JS_ToInt32(ctx, &id, id_value) != 0) {
        return nullptr;
    }
    const auto found = script->sockets.find(id);
    return found == script->sockets.end() ? nullptr : found->second.socket;
}

JSValue native_ws_send(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    const auto socket = argc < 2 ? nullptr : socket_of(ctx, argv[0]);
    if (!socket) {
        return JS_ThrowInternalError(ctx, "WebSocket is not open");
    }
    try {
        if (const auto text = string_arg(ctx, argv[1])) {
            socket->send(*text, false);
        }
        else if (const auto bytes = bytes_of(ctx, argv[1])) {
            socket->send(*bytes, true);
        }
        else {
            return JS_ThrowTypeError(ctx, "send(data): data is a string or bytes");
        }
    }
    catch (const std::exception &e) {
        return JS_ThrowInternalError(ctx, "%s", e.what());
    }
    return JS_UNDEFINED;
}

JSValue native_ws_close(JSContext *ctx, JSValueConst, const int argc, JSValueConst *argv)
{
    const auto socket = argc < 1 ? nullptr : socket_of(ctx, argv[0]);
    if (!socket) {
        return JS_UNDEFINED;
    }
    std::int32_t code = 1000;
    if (argc > 1) {
        JS_ToInt32(ctx, &code, argv[1]);
    }
    const auto reason = argc > 2 ? string_arg(ctx, argv[2]).value_or("") : std::string{};
    socket->close(code, reason);
    return JS_UNDEFINED;
}

void install_natives(JSContext *ctx)
{
    const auto global = JS_GetGlobalObject(ctx);

    const auto native = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, native, "names", JS_NewCFunction(ctx, native_names, "names", 0));
    JS_SetPropertyStr(ctx, native, "subscribe", JS_NewCFunction(ctx, native_subscribe, "subscribe", 3));
    JS_SetPropertyStr(ctx, native, "unsubscribe", JS_NewCFunction(ctx, native_unsubscribe, "unsubscribe", 1));
    JS_SetPropertyStr(ctx, native, "send", JS_NewCFunction(ctx, native_send, "send", 5));
    JS_SetPropertyStr(ctx, native, "utf8Decode", JS_NewCFunction(ctx, native_utf8_decode, "utf8Decode", 1));
    JS_SetPropertyStr(ctx, native, "utf8Encode", JS_NewCFunction(ctx, native_utf8_encode, "utf8Encode", 1));
    JS_SetPropertyStr(ctx, native, "loginOf", JS_NewCFunction(ctx, native_login_of, "loginOf", 1));
    JS_SetPropertyStr(ctx, native, "startGameOf", JS_NewCFunction(ctx, native_start_game_of, "startGameOf", 1));
    JS_SetPropertyStr(ctx, native, "game", JS_NewCFunction(ctx, native_game, "game", 0));
    JS_SetPropertyStr(ctx, native, "hooks", JS_NewCFunction(ctx, native_hooks, "hooks", 0));
    JS_SetPropertyStr(ctx, native, "lastPacket", JS_NewCFunction(ctx, native_last_packet, "lastPacket", 1));
    JS_SetPropertyStr(ctx, native, "knownConnections", JS_NewCFunction(ctx, native_known_connections, "knownConnections", 0));
    JS_SetPropertyStr(ctx, native, "scriptName", JS_NewCFunction(ctx, native_script_name, "scriptName", 0));
    JS_SetPropertyStr(ctx, native, "permitted", JS_NewCFunction(ctx, native_permitted, "permitted", 1));
    JS_SetPropertyStr(ctx, native, "fsRead", JS_NewCFunction(ctx, native_fs_read, "fsRead", 1));
    JS_SetPropertyStr(ctx, native, "fsWrite", JS_NewCFunction(ctx, native_fs_write, "fsWrite", 3));
    JS_SetPropertyStr(ctx, native, "fsExists", JS_NewCFunction(ctx, native_fs_exists, "fsExists", 1));
    JS_SetPropertyStr(ctx, native, "fsMkdir", JS_NewCFunction(ctx, native_fs_mkdir, "fsMkdir", 2));
    JS_SetPropertyStr(ctx, native, "fsList", JS_NewCFunction(ctx, native_fs_list, "fsList", 1));
    JS_SetPropertyStr(ctx, native, "fsRemove", JS_NewCFunction(ctx, native_fs_remove, "fsRemove", 3));
    JS_SetPropertyStr(ctx, native, "fsStat", JS_NewCFunction(ctx, native_fs_stat, "fsStat", 1));
    JS_SetPropertyStr(ctx, native, "httpRequest", JS_NewCFunction(ctx, native_http_request, "httpRequest", 1));
    JS_SetPropertyStr(ctx, native, "wsOpen", JS_NewCFunction(ctx, native_ws_open, "wsOpen", 3));
    JS_SetPropertyStr(ctx, native, "wsSend", JS_NewCFunction(ctx, native_ws_send, "wsSend", 2));
    JS_SetPropertyStr(ctx, native, "wsClose", JS_NewCFunction(ctx, native_ws_close, "wsClose", 3));
    JS_SetPropertyStr(ctx, native, "base64Decode", JS_NewCFunction(ctx, native_base64_decode, "base64Decode", 1));
    JS_SetPropertyStr(ctx, native, "base64Encode", JS_NewCFunction(ctx, native_base64_encode, "base64Encode", 2));
    JS_SetPropertyStr(ctx, global, "__native", native);

    JS_SetPropertyStr(ctx, global, "setTimeout",
                      JS_NewCFunctionMagic(ctx, native_timer, "setTimeout", 2, JS_CFUNC_generic_magic, 0));
    JS_SetPropertyStr(ctx, global, "setInterval",
                      JS_NewCFunctionMagic(ctx, native_timer, "setInterval", 2, JS_CFUNC_generic_magic, 1));
    JS_SetPropertyStr(ctx, global, "clearTimeout", JS_NewCFunction(ctx, native_clear_timer, "clearTimeout", 1));
    JS_SetPropertyStr(ctx, global, "clearInterval", JS_NewCFunction(ctx, native_clear_timer, "clearInterval", 1));

    const auto console = JS_NewObject(ctx);
    constexpr std::array<const char *, 5> kLevels{"log", "info", "warn", "error", "debug"};
    constexpr std::array<int, 5> kMagic{0, 0, 2, 3, 0};
    for (std::size_t i = 0; i < kLevels.size(); ++i) {
        JS_SetPropertyStr(ctx, console, kLevels[i],
                          JS_NewCFunctionMagic(ctx, native_console, kLevels[i], 0, JS_CFUNC_generic_magic, kMagic[i]));
    }
    JS_SetPropertyStr(ctx, global, "console", console);

    JS_FreeValue(ctx, global);
}


void destroy(Script &script)
{
    for (const auto &subscription : script.subscriptions) {
        watch(subscription.mask, subscription.id, false);
        JS_FreeValue(script.ctx, subscription.callback);
    }
    for (const auto &timer : script.timers) {
        JS_FreeValue(script.ctx, timer.callback);
    }
    for (const auto &[id, request] : script.requests) {
        JS_FreeValue(script.ctx, request.resolve);
        JS_FreeValue(script.ctx, request.reject);
    }
    for (const auto &[id, entry] : script.sockets) {
        entry.socket->abort();
        JS_FreeValue(script.ctx, entry.callback);
    }
    script.subscriptions.clear();
    script.timers.clear();
    script.requests.clear();
    script.sockets.clear();
    JS_SetContextOpaque(script.ctx, nullptr);
    JS_FreeContext(script.ctx);
    script.ctx = nullptr;
}


const EmbeddedModule *find_embedded(const std::string_view name)
{
    for (const auto &module : embedded_modules()) {
        if (module.name == name) {
            return &module;
        }
    }
    return nullptr;
}

std::optional<std::string> clean_path(const std::string_view path)
{
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= path.size()) {
        auto end = path.find('/', start);
        if (end == std::string_view::npos) {
            end = path.size();
        }
        const auto part = path.substr(start, end - start);
        if (part == "..") {
            if (parts.empty()) {
                return std::nullopt;
            }
            parts.pop_back();
        }
        else if (!part.empty() && part != ".") {
            parts.emplace_back(part);
        }
        start = end + 1;
    }
    std::string joined;
    for (const auto &part : parts) {
        if (!joined.empty()) {
            joined += '/';
        }
        joined += part;
    }
    return joined;
}

char *module_normalize(JSContext *ctx, const char *base, const char *name, void *)
{
    std::string_view request{name};
    const std::string_view importer{base};
    if (request.starts_with("node:")) {
        request.remove_prefix(5);
    }
    const auto relative = request.starts_with("./") || request.starts_with("../");
    if (!relative) {
        if (const auto *const module = find_embedded(request)) {
            if (module->internal && find_embedded(importer) == nullptr) {
                JS_ThrowReferenceError(ctx, "the module '%s' is internal to bedrock-client-api: a script cannot import it", name);
                return nullptr;
            }
            return js_strdup(ctx, std::string{request}.c_str());
        }
        JS_ThrowReferenceError(ctx,
                               "cannot find the module '%s'. A script imports \"bedrock-client-api\", \"fs\", \"path\", \"http\", "
                               "\"websocket\", or a file of the scripts folder written like \"./lib/name.js\"",
                               name);
        return nullptr;
    }
    if (find_embedded(importer) != nullptr || request.find('\\') != std::string_view::npos ||
        request.find(':') != std::string_view::npos) {
        JS_ThrowReferenceError(ctx, "cannot import '%s' from here", name);
        return nullptr;
    }
    const auto slash = importer.rfind('/');
    const std::string folder{slash == std::string_view::npos ? std::string_view{} : importer.substr(0, slash)};
    auto resolved = clean_path(folder + "/" + std::string{request});
    if (!resolved || resolved->empty()) {
        JS_ThrowReferenceError(ctx, "'%s' leaves the scripts folder", name);
        return nullptr;
    }
    if (!resolved->ends_with(".js")) {
        *resolved += ".js";
    }
    return js_strdup(ctx, resolved->c_str());
}

JSModuleDef *compile_module(JSContext *ctx, const std::string &source, const char *name)
{
    const auto compiled = JS_Eval(ctx, source.data(), source.size(), name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(compiled)) {
        return nullptr;
    }
    auto *const module = static_cast<JSModuleDef *>(JS_VALUE_GET_PTR(compiled));
    JS_FreeValue(ctx, compiled);
    return module;
}

std::optional<std::string> read_source(const std::filesystem::path &path);

JSModuleDef *module_load(JSContext *ctx, const char *name, void *)
{
    if (const auto *const module = find_embedded(name)) {
        return compile_module(ctx, module->source, name);
    }
    auto *const script = script_of(ctx);
    const std::string text{name};
    const auto root = scripts_directory();
    const auto path = root / std::filesystem::path{std::u8string{text.begin(), text.end()}};
    std::error_code ec;
    if (script == nullptr || !std::filesystem::is_regular_file(path, ec) || !files::is_inside(root, path)) {
        JS_ThrowReferenceError(ctx, "cannot find the file '%s' in the scripts folder", name);
        return nullptr;
    }
    const auto source = read_source(path);
    if (!source) {
        JS_ThrowReferenceError(ctx, "cannot read '%s' (over 4 MB, or the game has no access: run grant-access.bat)", name);
        return nullptr;
    }
    const auto stamp = std::filesystem::last_write_time(path, ec);
    if (!ec) {
        script->dependencies[text] = stamp;
    }
    return compile_module(ctx, *source, name);
}

void rejection_tracker(JSContext *ctx, JSValueConst, JSValueConst reason, const bool is_handled, void *)
{
    if (is_handled || g_loading) {
        return;
    }
    say(script_of(ctx), "unhandled promise rejection: " + error_text(ctx, reason), true);
}

bool run_module(Script &script, const std::string &source, const char *file_name)
{
    JS_UpdateStackTop(g_runtime);
    g_deadline = Clock::now() + kLoadBudget;
    g_loading = true;
    const auto result = JS_Eval(script.ctx, source.data(), source.size(), file_name, JS_EVAL_TYPE_MODULE);
    auto failed = JS_IsException(result);
    if (failed) {
        say(&script, exception_text(script.ctx), true);
    }
    drain_jobs();
    if (!failed && JS_PromiseState(script.ctx, result) == JS_PROMISE_REJECTED) {
        const auto reason = JS_PromiseResult(script.ctx, result);
        say(&script, error_text(script.ctx, reason), true);
        JS_FreeValue(script.ctx, reason);
        failed = true;
    }
    JS_FreeValue(script.ctx, result);
    g_loading = false;
    return !failed;
}

std::optional<std::string> read_source(const std::filesystem::path &path)
{
    std::ifstream file{path, std::ios::binary};
    if (!file) {
        return std::nullopt;
    }
    std::string source{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
    if (source.size() > kMaxSource) {
        return std::nullopt;
    }
    if (source.starts_with("\xEF\xBB\xBF")) {
        source.erase(0, 3);
    }
    return source;
}

std::map<std::string, unsigned> load_permissions()
{
    std::ifstream file{scripts_directory() / "permissions.txt", std::ios::binary};
    if (!file) {
        g_permission_problems.clear();
        return {};
    }
    std::string text{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
    if (text.starts_with("\xEF\xBB\xBF")) {
        text.erase(0, 3);
    }
    std::string problems;
    auto permissions = parse_permissions(text, &problems);
    if (problems != g_permission_problems) {
        g_permission_problems = problems;
        if (!problems.empty()) {
            log_error("permissions.txt: " + problems);
        }
    }
    return permissions;
}

unsigned grants_of(const std::map<std::string, unsigned> &permissions, const std::string &name)
{
    const auto found = permissions.find(name);
    return kGrantFiles | (found == permissions.end() ? 0U : found->second);
}

bool dependencies_changed(const Script &script)
{
    const auto root = scripts_directory();
    for (const auto &[name, stamp] : script.dependencies) {
        std::error_code ec;
        const auto now = std::filesystem::last_write_time(root / std::filesystem::path{std::u8string{name.begin(), name.end()}}, ec);
        if (ec || now != stamp) {
            return true;
        }
    }
    return false;
}

bool load(const std::string &name, const std::filesystem::path &path, const std::filesystem::file_time_type stamp,
          const unsigned grants)
{
    const auto source = read_source(path);
    if (!source) {
        log_error(std::format("{}: cannot read {} (missing, over 4 MB, or the game has no access: run grant-access.bat on "
                              "the DLL)",
                              name, utf8(path)));
        return false;
    }
    auto script = std::make_unique<Script>();
    script->name = name;
    script->path = path;
    script->stamp = stamp;
    script->serial = g_next_serial.fetch_add(1);
    script->grants = grants;
    script->data_root = data_directory() / "data" / path.stem();
    script->ctx = JS_NewContext(g_runtime);
    if (script->ctx == nullptr) {
        log_error(std::format("{}: out of memory", name));
        return false;
    }
    JS_SetContextOpaque(script->ctx, script.get());
    install_natives(script->ctx);

    const auto file_name = utf8(path.filename());
    if (!run_module(*script, *source, file_name.c_str())) {
        destroy(*script);
        return false;
    }
    log_line("bedrock-client-api",
             std::format("loaded {} ({} subscription(s), {} timer(s))", name, script->subscriptions.size(),
                         script->timers.size()),
             false);
    g_scripts.push_back(std::move(script));
    return true;
}

void rescan()
{
    struct Found {
        std::filesystem::path path;
        std::filesystem::file_time_type stamp;
    };
    std::map<std::string, Found> found;

    const auto folder = scripts_directory();
    std::error_code ec;
    std::filesystem::directory_iterator it{folder, ec};
    if (ec) {
        if (g_folder_state != 2) {
            log_error(std::format("scripts folder {} cannot be read ({}). Create it next to the DLL; if it exists, run "
                                  "grant-access.bat on the DLL so the game may read it",
                                  utf8(folder), ec.message()));
        }
        g_folder_state = 2;
    }
    else {
        if (g_folder_state != 1) {
            log_line("bedrock-client-api", std::format("scripts folder: {}", utf8(folder)), false);
        }
        g_folder_state = 1;
        for (const std::filesystem::directory_iterator end; it != end; it.increment(ec)) {
            if (ec) {
                break;
            }
            std::error_code entry_ec;
            const auto &entry = *it;
            if (!entry.is_regular_file(entry_ec) || entry.path().extension() != ".js") {
                continue;
            }
            const auto name = utf8(entry.path().stem());
            if (name.empty() || name.front() == '_' || name.front() == '.') {
                continue;
            }
            const auto stamp = entry.last_write_time(entry_ec);
            if (!entry_ec) {
                found[name] = {entry.path(), stamp};
            }
        }
    }

    const auto permissions = load_permissions();

    for (auto script = g_scripts.begin(); script != g_scripts.end();) {
        const auto now = found.find((*script)->name);
        if (now == found.end() || now->second.stamp != (*script)->stamp || dependencies_changed(**script) ||
            grants_of(permissions, (*script)->name) != (*script)->grants) {
            log_line("bedrock-client-api", std::format("{} {}", now == found.end() ? "unloaded" : "reloading", (*script)->name),
                     false);
            destroy(**script);
            script = g_scripts.erase(script);
        }
        else {
            ++script;
        }
    }
    std::erase_if(g_failed, [&](const auto &entry) { return !found.contains(entry.first); });

    for (const auto &[name, file] : found) {
        const auto loaded = std::ranges::any_of(g_scripts, [&](const auto &script) { return script->name == name; });
        if (loaded) {
            continue;
        }
        if (const auto failed = g_failed.find(name); failed != g_failed.end() && failed->second == file.stamp) {
            continue;
        }
        if (g_scripts.size() >= kScriptLimit) {
            log_error(std::format("{}: not loaded, at most {} scripts run at once", name, kScriptLimit));
            continue;
        }
        if (load(name, file.path, file.stamp, grants_of(permissions, name))) {
            g_failed.erase(name);
        }
        else {
            g_failed[name] = file.stamp;
        }
    }

    if (g_folder_state == 1 && g_scripts.empty() && g_failed.empty() && !g_told_empty) {
        g_told_empty = true;
        log_line("bedrock-client-api", "no scripts yet: copy some from the examples folder into the scripts folder", false);
    }
}

void run_timers(Script &script, const Clock::time_point now)
{
    std::vector<int> due;
    for (const auto &timer : script.timers) {
        if (timer.due <= now) {
            due.push_back(timer.handle);
        }
    }
    for (const auto handle : due) {
        auto found = std::ranges::find(script.timers, handle, &Timer::handle);
        if (found == script.timers.end()) {
            continue;
        }
        const auto callback = JS_DupValue(script.ctx, found->callback);
        if (found->interval.count() > 0) {
            found->due = now + found->interval;
        }
        else {
            JS_FreeValue(script.ctx, found->callback);
            script.timers.erase(found);
        }
        JS_FreeValue(script.ctx, call(script, callback, 0, nullptr));
        JS_FreeValue(script.ctx, callback);
        drain_jobs();
    }
}

void run_completions()
{
    std::vector<Completion> ready;
    {
        const std::lock_guard lock{g_queue_mutex};
        ready.swap(g_queue);
    }
    for (auto &completion : ready) {
        const auto script = std::ranges::find(g_scripts, completion.serial, [](const auto &s) { return s->serial; });
        if (script == g_scripts.end()) {
            continue;
        }
        JS_UpdateStackTop(g_runtime);
        g_deadline = Clock::now() + kCallbackBudget;
        completion.run(**script);
        drain_jobs();
    }
}

}


void start(std::vector<std::string> packet_names, const Sender sender)
{
    const std::lock_guard lock{g_mutex};
    if (g_runtime != nullptr) {
        return;
    }
    g_names = std::move(packet_names);
    if (g_names.size() > kIdLimit) {
        g_names.resize(kIdLimit);
    }
    g_sender = sender;

    g_runtime = JS_NewRuntime();
    JS_SetMemoryLimit(g_runtime, 128U * 1024U * 1024U);
    JS_SetMaxStackSize(g_runtime, 256U * 1024U);
    JS_SetInterruptHandler(
        g_runtime, [](JSRuntime *, void *) { return Clock::now() > g_deadline ? 1 : 0; }, nullptr);
    JS_SetModuleLoaderFunc(g_runtime, module_normalize, module_load, nullptr);
    JS_SetHostPromiseRejectionTracker(g_runtime, rejection_tracker, nullptr);

    g_next_scan = Clock::now() + kScanInterval;
    try {
        rescan();
    }
    catch (const std::exception &e) {
        log_error(std::format("scanning the scripts folder failed: {}", e.what()));
    }
}

bool wants(const Side side, const Direction direction, const int id) noexcept
{
    if (id < 1 || id >= static_cast<int>(kIdLimit)) {
        return false;
    }
    const auto slot = static_cast<std::size_t>(side) * 2 + static_cast<std::size_t>(direction);
    return g_watching[slot][static_cast<std::size_t>(id)].load(std::memory_order_relaxed) != 0;
}

Verdict dispatch(const Side side, const Direction direction, const int id, const std::string_view body, const int player,
                 const int connection)
{
    Verdict verdict;
    try {
        for (auto turns = 0; turns < 64 && g_ticker_waiting.load(std::memory_order_relaxed) != 0; ++turns) {
            std::this_thread::yield();
        }
        const std::lock_guard lock{g_mutex};
        if (g_runtime == nullptr) {
            return verdict;
        }
        const auto mask = 1 << (static_cast<int>(side) * 2 + static_cast<int>(direction));

        struct Target {
            Script *script;
            JSValue callback;
        };
        std::vector<Target> targets;
        for (const auto &script : g_scripts) {
            for (const auto &subscription : script->subscriptions) {
                if (subscription.id == id && (subscription.mask & mask) != 0) {
                    targets.push_back({script.get(), JS_DupValue(script->ctx, subscription.callback)});
                }
            }
        }

        std::string current{body};
        auto changed = false;
        for (const auto &target : targets) {
            auto *const script = target.script;
            if (verdict.cancel) {
                JS_FreeValue(script->ctx, target.callback);
                continue;
            }
            JSValue arguments[6] = {
                JS_NewInt32(script->ctx, id),
                JS_NewInt32(script->ctx, static_cast<int>(direction)),
                JS_NewUint8ArrayCopy(script->ctx, reinterpret_cast<const std::uint8_t *>(current.data()), current.size()),
                JS_NewInt32(script->ctx, static_cast<int>(side)),
                JS_NewInt32(script->ctx, player),
                JS_NewInt32(script->ctx, connection),
            };
            const auto result = call(*script, target.callback, 6, arguments);
            for (auto &argument : arguments) {
                JS_FreeValue(script->ctx, argument);
            }
            if (JS_IsNull(result)) {
                verdict.cancel = true;
            }
            else if (!JS_IsException(result) && !JS_IsUndefined(result)) {
                if (auto replacement = bytes_of(script->ctx, result); replacement && replacement->size() <= kMaxBody) {
                    changed = changed || *replacement != current;
                    current = std::move(*replacement);
                }
                else {
                    say(script, "a packet callback returned something that is not a packet body", true);
                }
            }
            JS_FreeValue(script->ctx, result);
            JS_FreeValue(script->ctx, target.callback);
            drain_jobs();
        }
        if (!verdict.cancel && changed) {
            verdict.body = std::move(current);
        }
    }
    catch (const std::exception &e) {
        log_error(std::format("dispatch failed: {}", e.what()));
        return Verdict{};
    }
    catch (...) {
        return Verdict{};
    }
    return verdict;
}

void tick()
{
    g_ticker_waiting.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock{g_mutex};
    g_ticker_waiting.fetch_sub(1, std::memory_order_relaxed);
    if (g_runtime == nullptr) {
        return;
    }
    try {
        const auto now = Clock::now();
        if (now >= g_next_scan) {
            g_next_scan = now + kScanInterval;
            rescan();
        }
        for (const auto &script : g_scripts) {
            run_timers(*script, now);
        }
        run_completions();
    }
    catch (const std::exception &e) {
        log_error(std::format("tick failed: {}", e.what()));
    }
}

}

#include "bca/net/network.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "bca/core/log.h"
#include "bca/game/abi.h"
#include "bca/hook/hook.h"
#include "bca/hook/signature.h"
#include "bca/script/runtime.h"


namespace {

namespace game = bca::game;
namespace script = bca::script;
using bca::Direction;
using bca::Side;

constexpr std::size_t kMaxBody = 1U << 20U;
constexpr std::size_t kMaxQueued = 1024;
constexpr std::size_t kMaxPlayers = 256;

void *g_create_packet = nullptr;
void *g_send_internal = nullptr;
std::atomic<const void *> g_reflection{nullptr};
thread_local const void *g_reflection_here = nullptr;
const void *reading_context()
{
    return g_reflection_here != nullptr ? g_reflection_here : g_reflection.load(std::memory_order_relaxed);
}
bca::net::Status g_status;

std::mutex g_queue_mutex;
std::vector<std::string> g_to_server;
std::vector<std::pair<int, std::string>> g_to_client;
std::vector<std::pair<int, std::string>> g_to_players;
std::atomic_size_t g_queued{0};

std::mutex g_players_mutex;
std::vector<game::NetworkIdentifier> g_players;

std::mutex g_logins_mutex;
std::map<int, std::string> g_logins;

std::map<int, std::string> g_start_games;

void remember_login(const int player, const std::string_view body)
{
    if (player < -1 || body.empty()) {
        return;
    }
    const std::lock_guard lock{g_logins_mutex};
    g_logins[player].assign(body);
}

std::map<int, std::string> g_received;

void remember_received(const int id, const std::string_view body)
{
    if (body.empty()) {
        return;
    }
    const std::lock_guard lock{g_logins_mutex};
    g_received[id].assign(body);
}

void remember_start_game(const int player, const std::string_view body)
{
    if (player < -1 || body.empty()) {
        return;
    }
    const std::lock_guard lock{g_logins_mutex};
    g_start_games[player].assign(body);
}

thread_local const game::Packet *g_read_packet = nullptr;
thread_local std::string g_read_body;
thread_local bool g_delivering = false;

struct ClientLink {
    game::NetworkIdentifier id;
    game::NetEventCallback *callback;
    std::chrono::steady_clock::time_point seen;
};
thread_local std::optional<ClientLink> g_client_link;
constexpr std::chrono::milliseconds kLinkLifetime{2000};

std::atomic<long long> g_seen_client_rx{0};
std::atomic<long long> g_seen_client_tx{0};
std::atomic<long long> g_seen_server_rx{0};
std::atomic<long long> g_seen_server_tx{0};
std::atomic<long long> g_delivered_client{0};
std::atomic<long long> g_delivered_players{0};
long long now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::atomic_int g_dropped_logged{0};
void note_drop(const std::string &what)
{
    if (g_dropped_logged.fetch_add(1, std::memory_order_relaxed) < 30) {
        bca::log_error("a queued packet was not delivered: " + what);
    }
}

using SendInternal = decltype(&game::NetworkSystem::sendInternalDetour);
using PacketRead = decltype(&game::Packet::readDetour);
using HandlerHandle = decltype(&game::PacketHandler::handleDetour);


constexpr std::array kServerbound{1,  4,  8,  20, 34, 35, 36, 37,  53,  57,  68,  69, 71,
                                   77, 78, 84, 90, 92, 94, 97, 101, 102, 113, 125, 129, 144, 152, 193};
constexpr std::array kClientbound{2,  3,  5,  6,  7,  10, 11, 12, 13,  14,  15,  17,  21,  22,  25,  26,
                                   28, 29, 38, 41, 42, 43, 46, 51, 52,  58,  59,  60,  61,  63,  66,  67,
                                   70, 72, 76, 79, 80, 82, 83, 85, 86,  87,  88,  100, 103, 106, 107, 108,
                                   110, 111, 112, 114, 118, 121, 122, 124, 143, 186};
constexpr int kLoginId = 1;
constexpr int kStartGameId = 11;
constexpr int kAvailableCommandsId = 76;

bool contains(const auto &ids, const int id)
{
    return std::ranges::find(ids, id) != ids.end();
}

thread_local std::optional<Side> g_thread_side;

std::mutex g_end_mutex;
std::map<const void *, Side> g_ends;

Side side_of(const void *object, const int id, const bool sending)
{
    const auto up = contains(kServerbound, id);
    const auto down = contains(kClientbound, id);
    const std::lock_guard lock{g_end_mutex};
    if (up != down) {
        const auto side = (up == sending) ? Side::Client : Side::Server;
        g_ends[object] = side;
        g_thread_side = side;
        return side;
    }
    if (const auto known = g_ends.find(object); known != g_ends.end()) {
        return known->second;
    }
    return g_thread_side.value_or(Side::Client);
}

int player_index(const game::NetworkIdentifier &id)
{
    const std::lock_guard lock{g_players_mutex};
    for (std::size_t i = 0; i < g_players.size(); ++i) {
        if (game::same_connection(g_players[i], id)) {
            g_players[i] = id;
            return static_cast<int>(i);
        }
    }
    if (g_players.size() >= kMaxPlayers) {
        return -1;
    }
    g_players.push_back(id);
    bca::log_line("bedrock-client-api", std::format("connection {} registered (type {})", g_players.size() - 1, game::connection_type(id)), false);
    return static_cast<int>(g_players.size() - 1);
}


std::size_t header_size(const std::string_view frame)
{
    std::size_t size = 1;
    while (size < 5 && size < frame.size() && (static_cast<std::uint8_t>(frame[size - 1]) & 0x80U) != 0) {
        ++size;
    }
    return size;
}

int packet_id_of(const std::string_view frame)
{
    std::uint32_t header = 0;
    for (std::size_t i = 0; i < header_size(frame) && i < frame.size(); ++i) {
        header |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(frame[i]) & 0x7FU) << (7 * i);
    }
    return static_cast<int>(header & 0x3FFU);
}

std::string frame_of(const int id, const std::string_view body)
{
    std::string frame;
    for (auto rest = static_cast<std::uint32_t>(id);; rest >>= 7U) {
        const auto low = static_cast<char>(rest & 0x7FU);
        frame.push_back(rest >= 0x80U ? static_cast<char>(low | 0x80) : low);
        if (rest < 0x80U) {
            break;
        }
    }
    frame.append(body);
    return frame;
}

std::shared_ptr<game::Packet> make_packet(const int id)
{
    if (g_create_packet == nullptr || id < 1) {
        return nullptr;
    }
    return reinterpret_cast<decltype(&game::MinecraftPackets::createPacket)>(g_create_packet)(id);
}

game::Result read_body(game::Packet &packet, const std::string_view body, const void *reflection_ctx)
{
    auto *const original = bca::original_in_slot(game::vtable_of(&packet), game::kPacketReadSlot);
    if (original == nullptr) {
        return game::Result::success();
    }
    game::set_sender_sub_id(&packet, 0);
    game::ReadStream stream{body};
    return bca::call_original<PacketRead>(original, &packet, stream, reflection_ctx);
}

void queue_pending_update()
{
    g_queued.store(g_to_server.size() + g_to_client.size() + g_to_players.size(), std::memory_order_relaxed);
}

void deliver_queued_to_client(const game::NetworkIdentifier &id, game::NetEventCallback &callback)
{
    if (g_delivering || g_queued.load(std::memory_order_relaxed) == 0) {
        return;
    }
    std::vector<std::pair<int, std::string>> injected;
    {
        const std::lock_guard lock{g_queue_mutex};
        injected.swap(g_to_client);
        queue_pending_update();
    }
    if (injected.empty()) {
        return;
    }
    const auto *const ctx = reading_context();
    struct Delivering {
        Delivering() { g_delivering = true; }
        ~Delivering() { g_delivering = false; }
        Delivering(const Delivering &) = delete;
        Delivering &operator=(const Delivering &) = delete;
    } delivering;
    for (const auto &[injected_id, body] : injected) {
        auto created = make_packet(injected_id);
        const auto *const handler = created ? packet_handler(created.get()) : nullptr;
        if (handler == nullptr || ctx == nullptr) {
            note_drop(std::format("packet {} for this client: {}", injected_id,
                                  created ? "the game has no handler for it" : (ctx == nullptr ? "no packet has been read yet" : "the game does not know this packet")));
            continue;
        }
        const auto result = read_body(*created, body, ctx);
        if (result.ok()) {
            game::deliver(handler, id, callback, created);
            g_delivered_client.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            bca::log_error(std::format("a packet sent to the client ({}) does not read: {}", injected_id,
                                            result.message()));
        }
    }
}

void deliver_to_client_from_send(const Side side)
{
    if (side != Side::Client || !g_client_link || g_queued.load(std::memory_order_relaxed) == 0) {
        return;
    }
    auto &link = *g_client_link;
    if (std::chrono::steady_clock::now() - link.seen > kLinkLifetime) {
        return;
    }
    deliver_queued_to_client(link.id, *link.callback);
}

}


void bca::game::NetworkSystem::sendInternalDetour(const NetworkIdentifier &id, const Packet &packet,
                                                       const std::string &data)
{
    const auto pid = packet_id(&packet);
    const auto side = side_of(this, pid, true);
    const auto direction = side == Side::Client ? Direction::ToServer : Direction::ToClient;
    const auto player = side == Side::Server ? player_index(id) : -1;
    (side == Side::Client ? g_seen_client_tx : g_seen_server_tx).store(now_ms(), std::memory_order_relaxed);

    if (pid == kLoginId && side == Side::Client) {
        g_client_link.reset();
        remember_login(-1, std::string_view{data}.substr(std::min(header_size(data), data.size())));
    }
    else if (pid == kStartGameId && side == Side::Server) {
        remember_start_game(player, std::string_view{data}.substr(std::min(header_size(data), data.size())));
    }

    auto cancelled = false;
    std::optional<std::string> rewritten;
    if (script::wants(side, direction, pid)) {
        const auto header = std::min(header_size(data), data.size());
        auto verdict = script::dispatch(side, direction, pid, std::string_view{data}.substr(header), player,
                                        side == Side::Server ? connection_type(id) : -1);
        cancelled = verdict.cancel;
        if (verdict.body) {
            rewritten = data.substr(0, header) + *verdict.body;
        }
    }
    if (!cancelled) {
        bca::call_original<SendInternal>(g_send_internal, this, id, packet, rewritten ? *rewritten : data);
    }

    if (g_queued.load(std::memory_order_relaxed) == 0) {
        return;
    }
    std::vector<std::string> to_server;
    std::vector<std::pair<int, std::string>> to_players;
    {
        const std::lock_guard lock{g_queue_mutex};
        if (side == Side::Client) {
            to_server.swap(g_to_server);
        }
        else {
            to_players.swap(g_to_players);
        }
        queue_pending_update();
    }
    for (const auto &frame : to_server) {
        const auto injected = make_packet(packet_id_of(frame));
        if (injected) {
            bca::call_original<SendInternal>(g_send_internal, this, id, *injected, frame);
        }
    }
    for (const auto &[target, frame] : to_players) {
        const auto injected = make_packet(packet_id_of(frame));
        if (!injected) {
            note_drop(std::format("packet {} for player {}: the game does not know this packet", packet_id_of(frame), target));
            continue;
        }
        std::vector<NetworkIdentifier> targets;
        {
            const std::lock_guard lock{g_players_mutex};
            if (target < 0) {
                targets = g_players;
            }
            else if (static_cast<std::size_t>(target) < g_players.size()) {
                targets.push_back(g_players[static_cast<std::size_t>(target)]);
            }
        }
        if (targets.empty()) {
            note_drop(std::format("packet {} for player {}: that connection is not known", packet_id_of(frame), target));
        }
        for (const auto &connection : targets) {
            bca::call_original<SendInternal>(g_send_internal, this, connection, *injected, frame);
            g_delivered_players.fetch_add(1, std::memory_order_relaxed);
        }
    }
    deliver_to_client_from_send(side);
}


bca::game::Result bca::game::Packet::readDetour(ReadStream &stream, const void *reflection_ctx)
{
    g_reflection.store(reflection_ctx, std::memory_order_relaxed);
    g_reflection_here = reflection_ctx;
    auto *const original = bca::original_in_slot(vtable_of(this), kPacketReadSlot);

    g_read_packet = nullptr;
    const auto pid = packet_id(this);
    if (pid == kLoginId || pid == kStartGameId || pid == kAvailableCommandsId ||
        script::wants(Side::Client, Direction::ToClient, pid) ||
        script::wants(Side::Server, Direction::ToServer, pid)) {
        const auto view = stream.view();
        const auto begin = stream.read_pointer();
        if (begin <= view.size() && view.size() <= kMaxBody) {
            g_read_packet = this;
            g_read_body.assign(view.substr(begin));
        }
    }
    return bca::call_original<PacketRead>(original, this, stream, reflection_ctx);
}

void bca::game::PacketHandler::handleDetour(const NetworkIdentifier &id, NetEventCallback &callback,
                                                 std::shared_ptr<Packet> &packet) const
{
    auto *const original = bca::original_in_slot(vtable_of(this), kHandlerHandleSlot);
    const auto pid = packet_id(packet.get());
    const auto side = side_of(&callback, pid, false);
    const auto direction = side == Side::Client ? Direction::ToClient : Direction::ToServer;

    (side == Side::Client ? g_seen_client_rx : g_seen_server_rx).store(now_ms(), std::memory_order_relaxed);
    if (side == Side::Client) {
        g_client_link.emplace(ClientLink{id, &callback, std::chrono::steady_clock::now()});
    }

    if (side == Side::Server && pid == kLoginId && g_read_packet == packet.get()) {
        remember_login(player_index(id), g_read_body);
    }

    if (side == Side::Client && pid == kStartGameId && g_read_packet == packet.get()) {
        remember_start_game(-1, g_read_body);
    }
    if (side == Side::Client && pid == kAvailableCommandsId && g_read_packet == packet.get()) {
        remember_received(pid, g_read_body);
    }

    auto cancelled = false;
    if (g_read_packet == packet.get() && script::wants(side, direction, pid)) {
        g_read_packet = nullptr;
        const auto verdict = script::dispatch(side, direction, pid, g_read_body,
                                              side == Side::Server ? player_index(id) : -1,
                                              side == Side::Server ? connection_type(id) : -1);
        cancelled = verdict.cancel;
        const auto *const ctx = reading_context();
        if (verdict.body && !cancelled && ctx != nullptr) {
            const auto result = read_body(*packet, *verdict.body, ctx);
            if (!result.ok()) {
                bca::log_error(std::format("{}: the replaced body does not read as a packet: {}",
                                                packet_name(packet.get()), result.message()));
            }
        }
    }
    if (!cancelled) {
        bca::call_original<HandlerHandle>(original, this, id, callback, packet);
    }

    if (side == Side::Client) {
        deliver_queued_to_client(id, callback);
    }
}


namespace bca::net {
namespace {

bool stream_layout_matches()
{
    const game::ReadStream probe{"abc"};
    const auto *const bytes = reinterpret_cast<const unsigned char *>(&probe);
    std::string_view view;
    std::size_t position = 1;
    std::memcpy(&view, bytes + game::kStreamViewOffset, sizeof(view));
    std::memcpy(&position, bytes + game::kStreamReadPointerOffset, sizeof(position));
    return sizeof(game::ReadStream) == game::kStreamSize && view == "abc" && position == 0;
}

bool plausible_name(const std::string_view name)
{
    return !name.empty() && name.size() <= 96 &&
           std::ranges::all_of(name, [](const char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; });
}

void self_check()
{
    if (!stream_layout_matches()) {
        throw std::runtime_error{"the stream layout in game/abi.h does not match what the code builds"};
    }
    std::size_t found = 0;
    for (std::size_t id = 1; id < kPacketIdLimit; ++id) {
        const auto packet = make_packet(static_cast<int>(id));
        if (!packet) {
            continue;
        }
        ++found;
        if (game::packet_id(packet.get()) != static_cast<int>(id)) {
            throw std::runtime_error{std::format(
                "packet {} reports id {}: createPacket or the getId slot do not match this client", id,
                game::packet_id(packet.get()))};
        }
        if (!plausible_name(game::packet_name(packet.get()))) {
            throw std::runtime_error{std::format("packet {} has no sensible name: the getName slot does not match this client", id)};
        }
    }
    if (found < 50) {
        throw std::runtime_error{std::format("only {} packet classes were found, a client has far more", found)};
    }
}

void hook_packet_classes()
{
    std::unordered_set<void **> seen;
    for (std::size_t id = 1; id < kPacketIdLimit; ++id) {
        const auto packet = make_packet(static_cast<int>(id));
        if (!packet) {
            continue;
        }
        auto **vtable = game::vtable_of(packet.get());
        if (seen.insert(vtable).second &&
            swap_vtable_slot("Packet::read", vtable, game::kPacketReadSlot, address_of(&game::Packet::readDetour))) {
            ++g_status.packet_classes;
        }
    }

    seen.clear();
    for (std::size_t id = 1; id < kPacketIdLimit; ++id) {
        const auto packet = make_packet(static_cast<int>(id));
        const auto *const handler = packet ? game::packet_handler(packet.get()) : nullptr;
        if (handler == nullptr) {
            continue;
        }
        auto **vtable = game::vtable_of(handler);
        if (seen.insert(vtable).second &&
            swap_vtable_slot("PacketHandler::handle", vtable, game::kHandlerHandleSlot,
                             address_of(&game::PacketHandler::handleDetour))) {
            ++g_status.handlers;
        }
    }
    if (g_status.handlers == 0) {
        log_error("no packet handler could be hooked: received packets cannot be seen and nothing can be sent to the client");
    }
}

void *follow_send_internal(void *send, const std::string_view call_pattern)
{
    const auto length = static_cast<std::size_t>(std::ranges::count(call_pattern, ' ') + 1);
    const auto *const call = static_cast<const std::uint8_t *>(scan_within(send, 0x400, call_pattern));
    std::int32_t relative = 0;
    std::memcpy(&relative, call + length, sizeof(relative));
    return const_cast<std::uint8_t *>(call + length + sizeof(relative)) + relative;
}

}

void install()
{
    verify_client();
    const auto &signature = signatures();

    try {
        g_create_packet = scan(signature.create_packet);
    }
    catch (const std::exception &e) {
        throw std::runtime_error{std::format("MinecraftPackets::createPacket: {}", e.what())};
    }
    try {
        self_check();
    }
    catch (...) {
        g_create_packet = nullptr;
        throw;
    }
    g_status.create_packet = true;
    hook_packet_classes();

    if (signature.send.empty()) {
        log_error("this client build has no NetworkSystem::send pattern: outgoing packets cannot be seen or sent, "
                  "incoming ones still work");
        return;
    }
    try {
        auto *const send = scan(signature.send);
        auto *const target = follow_send_internal(send, signature.send_internal_call);
        install_inline_hook("NetworkSystem::_sendInternal", target,
                            address_of(&game::NetworkSystem::sendInternalDetour), &g_send_internal);
        g_status.send_internal = true;
    }
    catch (const std::exception &e) {
        log_error(std::format("NetworkSystem::_sendInternal: {}; outgoing packets cannot be seen or sent", e.what()));
    }
}

const Status &status()
{
    return g_status;
}

const std::vector<std::string> &packet_names()
{
    static std::vector<std::string> names;
    static std::once_flag once;
    std::call_once(once, [] {
        if (g_create_packet == nullptr) {
            return;
        }
        names.resize(kPacketIdLimit);
        std::size_t highest = 0;
        for (std::size_t id = 1; id < names.size(); ++id) {
            if (const auto packet = make_packet(static_cast<int>(id))) {
                names[id] = std::string{game::packet_name(packet.get())};
                highest = id;
            }
        }
        names.resize(highest + 1);
    });
    return names;
}

std::optional<std::string> login_of(const int player)
{
    const std::lock_guard lock{g_logins_mutex};
    if (const auto found = g_logins.find(player); found != g_logins.end()) {
        return found->second;
    }
    return std::nullopt;
}

std::optional<std::string> start_game_of(const int player)
{
    const std::lock_guard lock{g_logins_mutex};
    if (const auto found = g_start_games.find(player); found != g_start_games.end()) {
        return found->second;
    }
    return std::nullopt;
}

std::optional<std::string> last_received(const int id)
{
    const std::lock_guard lock{g_logins_mutex};
    if (const auto found = g_received.find(id); found != g_received.end()) {
        return found->second;
    }
    return std::nullopt;
}

std::vector<int> known_logins()
{
    const std::lock_guard lock{g_logins_mutex};
    std::vector<int> players;
    for (const auto &entry : g_logins) {
        if (entry.first >= 0) {
            players.push_back(entry.first);
        }
    }
    return players;
}

bool send(const Side side, const Direction direction, const int id, const std::string_view body, const int player)
{
    if (side == Side::Server && direction != Direction::ToClient) {
        return false;
    }
    const auto usable = direction == Direction::ToClient && side == Side::Client ? g_status.handlers != 0
                                                                                  : g_status.send_internal;
    if (!usable || id < 1 || id >= static_cast<int>(kPacketIdLimit) || body.size() > kMaxBody || !make_packet(id)) {
        return false;
    }
    if (side == Side::Server) {
        const std::lock_guard lock{g_players_mutex};
        if (player < 0 ? g_players.empty() : static_cast<std::size_t>(player) >= g_players.size()) {
            return false;
        }
    }
    const std::lock_guard lock{g_queue_mutex};
    if (g_to_server.size() + g_to_client.size() + g_to_players.size() >= kMaxQueued) {
        const auto of_this_kind = side == Side::Server                   ? g_to_players.size()
                                  : direction == Direction::ToServer ? g_to_server.size()
                                                                     : g_to_client.size();
        if (of_this_kind == 0) {
            return false;
        }
        if (side == Side::Server) {
            g_to_players.erase(g_to_players.begin());
        }
        else if (direction == Direction::ToServer) {
            g_to_server.erase(g_to_server.begin());
        }
        else {
            g_to_client.erase(g_to_client.begin());
        }
    }
    if (side == Side::Server) {
        g_to_players.emplace_back(player, frame_of(id, body));
    }
    else if (direction == Direction::ToServer) {
        g_to_server.push_back(frame_of(id, body));
    }
    else {
        g_to_client.emplace_back(id, std::string{body});
    }
    queue_pending_update();
    return true;
}

}

namespace bca::net {

void report_stuck()
{
    static long long since = 0;
    static std::size_t last_total = 0;
    static long long last_report = 0;
    const auto now = now_ms();
    std::size_t to_server = 0;
    std::size_t to_client = 0;
    std::size_t to_players = 0;
    {
        const std::lock_guard lock{g_queue_mutex};
        to_server = g_to_server.size();
        to_client = g_to_client.size();
        to_players = g_to_players.size();
    }
    const auto total = to_server + to_client + to_players;
    if (total == 0 || total != last_total) {
        since = now;
        last_total = total;
        return;
    }
    if (now - since < 3000 || now - last_report < 15000) {
        return;
    }
    last_report = now;
    std::size_t players = 0;
    {
        const std::lock_guard lock{g_players_mutex};
        players = g_players.size();
    }
    std::size_t as_client = 0;
    std::size_t as_server = 0;
    {
        const std::lock_guard lock{g_end_mutex};
        for (const auto &[object, side] : g_ends) {
            (side == Side::Client ? as_client : as_server) += 1;
        }
    }
    const auto ago = [now](const std::atomic<long long> &stamp) {
        const auto at = stamp.load(std::memory_order_relaxed);
        return at == 0 ? std::string{"never"} : std::format("{}ms ago", now - at);
    };
    bca::log_error(std::format(
        "packets are waiting and not leaving: toServer={} toClient={} toPlayers={}; players known={}; "
        "last received: client {} / server {}; last sent: client {} / server {}; "
        "delivered so far: to client {} / to players {}; objects seen as client={} server={}",
        to_server, to_client, to_players, players, ago(g_seen_client_rx), ago(g_seen_server_rx), ago(g_seen_client_tx),
        ago(g_seen_server_tx), g_delivered_client.load(std::memory_order_relaxed),
        g_delivered_players.load(std::memory_order_relaxed), as_client, as_server));
}

}

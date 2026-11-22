#include "bca/install.h"

#include <Windows.h>

#include <exception>
#include <format>
#include <string>
#include <string_view>

#include "bca/core/log.h"
#include "bca/core/paths.h"
#include "bca/net/network.h"
#include "bca/script/runtime.h"

namespace bca {
namespace {

bool first_copy()
{
    const auto guard = CreateMutexW(nullptr, FALSE, L"bedrock-client-api-instance");
    if (guard != nullptr && GetLastError() == ERROR_ALREADY_EXISTS) {
        OutputDebugStringW(L"bedrock-client-api: another copy is already installed, this one stays idle\n");
        return false;
    }
    return true;
}

void run_ticker()
{
    CloseHandle(CreateThread(
        nullptr, 0,
        [](LPVOID) -> DWORD {
            for (;;) {
                try {
                    script::tick();
                    net::report_stuck();
                }
                catch (...) {
                }
                Sleep(10);
            }
        },
        nullptr, 0, nullptr));
}

}

void install()
{
    if (!first_copy()) {
        return;
    }
    open_console();
    log_line("bedrock-client-api", std::format("bedrock-client-api {} for Minecraft {}", BCA_VERSION, MINECRAFT_CLIENT), false);
    log_line("bedrock-client-api", std::format("loaded from {}", utf8(dll_directory())), false);

    try {
        net::install();
    }
    catch (const std::exception &e) {
        log_error(std::format("packet hooks: {}", e.what()));
    }

    script::start(net::packet_names(), [](const Side side, const Direction direction, const int id,
                                          const std::string_view body, const int player) {
        return net::send(side, direction, id, body, player);
    });
    run_ticker();

    const auto &status = net::status();
    log_line("bedrock-client-api",
             std::format("hooks: createPacket={} sendInternal={} packetClasses={} handlers={}", status.create_packet,
                         status.send_internal, status.packet_classes, status.handlers),
             false);
    if (status.create_packet) {
        log_line("bedrock-client-api", "ready: scripts are the *.js files in the scripts folder next to the DLL", false);
    }
    else {
        log_error("not ready: the game's packet code was not found, scripts will load but see nothing");
    }
}

}

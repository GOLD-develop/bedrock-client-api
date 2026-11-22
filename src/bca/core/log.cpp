#include "bca/core/log.h"

#include <Windows.h>

#include <chrono>
#include <ctime>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <string>

#include "bca/core/paths.h"

namespace bca {
namespace {

std::mutex g_mutex;
std::ofstream g_file;
bool g_file_tried = false;
HANDLE g_console = INVALID_HANDLE_VALUE;
thread_local bool g_inside = false;

std::wstring widen(const std::string_view text)
{
    if (text.empty()) {
        return {};
    }
    const auto length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), length);
    return wide;
}

std::string stamp()
{
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
    std::tm local{};
    localtime_s(&local, &time);
    return std::format("{:02}:{:02}:{:02}.{:03}", local.tm_hour, local.tm_min, local.tm_sec, millis);
}

}

void log_line(const std::string_view source, const std::string_view text, const bool error) noexcept
{
    if (g_inside) {
        return;
    }
    g_inside = true;
    try {
        auto line = std::format("[{}] {}{}{}", stamp(), error ? "ERROR " : "", source.empty() ? "" : std::format("<{}> ", source),
                                text);
        const std::lock_guard lock{g_mutex};
        if (!g_file_tried) {
            g_file_tried = true;
            g_file.open(data_directory() / "bedrock-client-api.log", std::ios::binary | std::ios::trunc);
        }
        if (g_file.is_open()) {
            g_file << line << '\n';
            g_file.flush();
        }
        if (g_console != INVALID_HANDLE_VALUE) {
            std::string console_text;
            console_text.reserve(line.size() + 8);
            for (const auto c : line) {
                if (c == '\n') {
                    console_text.push_back('\r');
                }
                console_text.push_back(c);
            }
            console_text += "\r\n";
            if (error) {
                SetConsoleTextAttribute(g_console, FOREGROUND_RED | FOREGROUND_INTENSITY);
            }
            const auto wide = widen(console_text);
            DWORD written = 0;
            WriteConsoleW(g_console, wide.data(), static_cast<DWORD>(wide.size()), &written, nullptr);
            if (error) {
                SetConsoleTextAttribute(g_console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
        }
    }
    catch (...) {
    }
    g_inside = false;
}

void open_console() noexcept
{
    try {
        std::error_code ec;
        if (std::filesystem::exists(data_directory() / "no-console", ec) ||
            std::filesystem::exists(dll_directory() / "no-console", ec)) {
            return;
        }
        if (!AllocConsole() && GetLastError() != ERROR_ACCESS_DENIED) {
            return;
        }
        const auto handle = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                        OPEN_EXISTING, 0, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            return;
        }
        SetConsoleTitleW(L"bedrock-client-api");
        if (const auto window = GetConsoleWindow(); window != nullptr) {
            if (const auto menu = GetSystemMenu(window, FALSE); menu != nullptr) {
                DeleteMenu(menu, SC_CLOSE, MF_BYCOMMAND);
            }
        }
        SetConsoleCtrlHandler([](const DWORD type) -> BOOL { return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT; }, TRUE);
        const std::lock_guard lock{g_mutex};
        g_console = handle;
    }
    catch (...) {
    }
}

}

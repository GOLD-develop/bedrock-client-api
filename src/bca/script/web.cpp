#include "bca/script/web.h"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <format>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace bca::script::web {
namespace {

std::wstring widen(const std::string_view text)
{
    if (text.empty()) {
        return {};
    }
    const auto length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<std::size_t>(std::max(length, 0)), L'\0');
    if (length > 0) {
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), length);
    }
    return wide;
}

std::string narrow(const std::wstring_view text)
{
    if (text.empty()) {
        return {};
    }
    const auto length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(std::max(length, 0)), '\0');
    if (length > 0) {
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length, nullptr, nullptr);
    }
    return out;
}

std::string describe(const DWORD code)
{
    wchar_t buffer[256]{};
    const auto length = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                       GetModuleHandleW(L"winhttp.dll"), code, 0, buffer, 255, nullptr);
    auto text = narrow(std::wstring_view{buffer, length});
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ' || text.back() == '.')) {
        text.pop_back();
    }
    return text.empty() ? std::format("error {}", code) : std::format("{} (error {})", text, code);
}

class Handle {
public:
    Handle() = default;
    explicit Handle(HINTERNET handle) : handle_(handle) {}
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&other) noexcept : handle_(other.release()) {}
    Handle &operator=(Handle &&other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    ~Handle() { reset(); }
    void reset(HINTERNET handle = nullptr)
    {
        if (handle_ != nullptr) {
            WinHttpCloseHandle(handle_);
        }
        handle_ = handle;
    }
    [[nodiscard]] HINTERNET get() const { return handle_; }
    [[nodiscard]] explicit operator bool() const { return handle_ != nullptr; }
    HINTERNET release() { return std::exchange(handle_, nullptr); }

private:
    HINTERNET handle_{nullptr};
};

struct Target {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port{0};
    bool secure{false};
};

std::string as_http_url(std::string url)
{
    if (url.starts_with("ws://")) {
        return "http://" + url.substr(5);
    }
    if (url.starts_with("wss://")) {
        return "https://" + url.substr(6);
    }
    return url;
}

Target crack(const std::string &url)
{
    if (!url.starts_with("http://") && !url.starts_with("https://")) {
        throw std::runtime_error{"only http:// and https:// addresses work"};
    }
    const auto wide = widen(url);
    URL_COMPONENTSW parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (WinHttpCrackUrl(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &parts) == FALSE) {
        throw std::runtime_error{std::format("not a valid address: {}", describe(GetLastError()))};
    }
    Target target;
    target.host.assign(parts.lpszHostName, parts.dwHostNameLength);
    target.path.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (parts.lpszExtraInfo != nullptr) {
        target.path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    }
    if (target.path.empty()) {
        target.path = L"/";
    }
    target.port = parts.nPort;
    target.secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
    return target;
}

std::wstring header_block(const Headers &headers)
{
    std::wstring block;
    for (const auto &[name, value] : headers) {
        if (name.find_first_of("\r\n:") != std::string::npos || value.find_first_of("\r\n") != std::string::npos) {
            throw std::runtime_error{std::format("the header \"{}\" has a forbidden character", name)};
        }
        block += widen(name) + L": " + widen(value) + L"\r\n";
    }
    return block;
}

[[noreturn]] void fail_last(const char *what)
{
    throw std::runtime_error{std::format("{}: {}", what, describe(GetLastError()))};
}

struct Connection {
    Handle session;
    Handle connect;
    Handle request;
};

Connection open_request(const Target &target, const wchar_t *method, const Headers &headers, const int timeout_ms)
{
    Connection c;
    c.session.reset(WinHttpOpen(L"bedrock-client-api", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                                WINHTTP_NO_PROXY_BYPASS, 0));
    if (!c.session) {
        fail_last("WinHttpOpen");
    }
    WinHttpSetTimeouts(c.session.get(), timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    c.connect.reset(WinHttpConnect(c.session.get(), target.host.c_str(), target.port, 0));
    if (!c.connect) {
        fail_last("connect");
    }
    c.request.reset(WinHttpOpenRequest(c.connect.get(), method, target.path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, target.secure ? WINHTTP_FLAG_SECURE : 0));
    if (!c.request) {
        fail_last("open request");
    }
    if (const auto block = header_block(headers); !block.empty()) {
        if (WinHttpAddRequestHeaders(c.request.get(), block.c_str(), static_cast<DWORD>(block.size()),
                                     WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) == FALSE) {
            fail_last("headers");
        }
    }
    return c;
}

Headers parse_raw_headers(const std::string &raw)
{
    Headers headers;
    std::size_t pos = raw.find("\r\n");
    while (pos != std::string::npos && pos + 2 < raw.size()) {
        const auto start = pos + 2;
        const auto end = raw.find("\r\n", start);
        const auto line = std::string_view{raw}.substr(start, end == std::string::npos ? std::string::npos : end - start);
        pos = end;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) {
            continue;
        }
        auto value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ') {
            value.remove_prefix(1);
        }
        headers.emplace_back(std::string{line.substr(0, colon)}, std::string{value});
    }
    return headers;
}

}


HttpResponse perform(const HttpRequest &request)
{
    HttpResponse response;
    try {
        const auto target = crack(request.url);
        auto connection = open_request(target, widen(request.method).c_str(), request.headers, request.timeout_ms);
        const auto size = static_cast<DWORD>(request.body.size());
        if (request.body.size() > kMaxBody ||
            WinHttpSendRequest(connection.request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               size == 0 ? WINHTTP_NO_REQUEST_DATA : const_cast<char *>(request.body.data()), size, size, 0) == FALSE) {
            fail_last("send");
        }
        if (WinHttpReceiveResponse(connection.request.get(), nullptr) == FALSE) {
            fail_last("receive");
        }
        DWORD status = 0;
        DWORD status_size = sizeof(status);
        WinHttpQueryHeaders(connection.request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX);
        response.status = static_cast<int>(status);

        DWORD raw_size = 0;
        WinHttpQueryHeaders(connection.request.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER,
                            &raw_size, WINHTTP_NO_HEADER_INDEX);
        if (raw_size > 0) {
            std::wstring raw(raw_size / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(connection.request.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, raw.data(), &raw_size,
                                    WINHTTP_NO_HEADER_INDEX) != FALSE) {
                raw.resize(raw_size / sizeof(wchar_t));
                response.headers = parse_raw_headers(narrow(raw));
            }
        }

        for (;;) {
            DWORD available = 0;
            if (WinHttpQueryDataAvailable(connection.request.get(), &available) == FALSE) {
                fail_last("read");
            }
            if (available == 0) {
                break;
            }
            if (response.body.size() + available > kMaxBody) {
                throw std::runtime_error{"the answer is larger than 16 MB"};
            }
            const auto old = response.body.size();
            response.body.resize(old + available);
            DWORD read = 0;
            if (WinHttpReadData(connection.request.get(), response.body.data() + old, available, &read) == FALSE) {
                fail_last("read");
            }
            response.body.resize(old + read);
            if (read == 0) {
                break;
            }
        }
    }
    catch (const std::exception &e) {
        response.error = e.what();
    }
    catch (...) {
        response.error = "unknown error";
    }
    return response;
}


struct Socket::State {
    Listener listener;
    std::mutex mutex;
    std::mutex send_mutex;
    Handle session;
    Handle connect;
    Handle web_socket;
    std::atomic<bool> aborted{false};
    std::atomic<bool> finished{false};
    std::atomic<bool> closing{false};
    int our_close_code{1000};
    std::string our_close_reason;

    void report(SocketEvent event)
    {
        if (!aborted.load()) {
            listener(std::move(event));
        }
    }
};

namespace {

void run_socket(const std::shared_ptr<Socket::State> &state, std::string url, Headers headers)
{
    int close_code = 1006;
    std::string close_reason;
    try {
        const auto target = crack(as_http_url(std::move(url)));
        Connection connection = open_request(target, L"GET", headers, 30000);
        if (WinHttpSetOption(connection.request.get(), WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) == FALSE) {
            fail_last("upgrade");
        }
        if (WinHttpSendRequest(connection.request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE) {
            fail_last("send");
        }
        if (WinHttpReceiveResponse(connection.request.get(), nullptr) == FALSE) {
            fail_last("receive");
        }
        HINTERNET upgraded = WinHttpWebSocketCompleteUpgrade(connection.request.get(), 0);
        if (upgraded == nullptr) {
            fail_last("the server did not accept the WebSocket");
        }
        connection.request.reset();
        {
            const std::lock_guard lock{state->mutex};
            state->session.reset(connection.session.release());
            state->connect.reset(connection.connect.release());
            state->web_socket.reset(upgraded);
        }
        state->report(SocketEvent{SocketEvent::Kind::Open});

        std::string message;
        std::vector<char> buffer(16384);
        for (;;) {
            DWORD read = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
            const auto error = WinHttpWebSocketReceive(upgraded, buffer.data(), static_cast<DWORD>(buffer.size()), &read, &type);
            if (error != NO_ERROR) {
                if (!state->closing.load() && !state->aborted.load()) {
                    throw std::runtime_error{describe(error)};
                }
                close_code = state->our_close_code;
                close_reason = state->our_close_reason;
                break;
            }
            if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
                USHORT status = 0;
                char reason[123]{};
                DWORD reason_length = 0;
                if (WinHttpWebSocketQueryCloseStatus(upgraded, &status, reason, sizeof(reason), &reason_length) == NO_ERROR) {
                    close_code = status;
                    close_reason.assign(reason, reason_length);
                }
                else {
                    close_code = 1005;
                }
                if (state->closing.load()) {
                    close_code = state->our_close_code;
                    close_reason = state->our_close_reason;
                }
                break;
            }
            message.append(buffer.data(), read);
            if (message.size() > kMaxBody) {
                throw std::runtime_error{"a message is larger than 16 MB"};
            }
            if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
                SocketEvent event{SocketEvent::Kind::Message};
                event.binary = type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
                event.data = std::move(message);
                message.clear();
                state->report(std::move(event));
            }
        }
    }
    catch (const std::exception &e) {
        SocketEvent event{SocketEvent::Kind::Error};
        event.data = e.what();
        state->report(std::move(event));
        close_code = 1006;
        close_reason.clear();
    }
    {
        const std::lock_guard lock{state->mutex};
        state->web_socket.reset();
        state->connect.reset();
        state->session.reset();
    }
    state->finished.store(true);
    SocketEvent event{SocketEvent::Kind::Close};
    event.code = close_code;
    event.data = std::move(close_reason);
    state->report(std::move(event));
}

}

Socket::Socket(std::shared_ptr<State> state) : state_(std::move(state)) {}

std::shared_ptr<Socket> Socket::open(std::string url, Headers headers, Listener listener)
{
    if (!url.starts_with("ws://") && !url.starts_with("wss://")) {
        throw std::runtime_error{"WebSocket addresses start with ws:// or wss://"};
    }
    auto state = std::make_shared<State>();
    state->listener = std::move(listener);
    std::thread{[state, url = std::move(url), headers = std::move(headers)]() mutable {
        run_socket(state, std::move(url), std::move(headers));
    }}.detach();
    return std::shared_ptr<Socket>{new Socket{std::move(state)}};
}

Socket::~Socket()
{
    abort();
}

void Socket::send(const std::string_view data, const bool binary)
{
    if (data.size() > kMaxBody) {
        throw std::runtime_error{"a message may not be larger than 16 MB"};
    }
    const std::lock_guard send_lock{state_->send_mutex};
    HINTERNET handle = nullptr;
    {
        const std::lock_guard lock{state_->mutex};
        handle = state_->web_socket.get();
    }
    if (handle == nullptr || state_->closing.load() || state_->finished.load()) {
        throw std::runtime_error{"the WebSocket is not open"};
    }
    const auto error = WinHttpWebSocketSend(handle, binary ? WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE : WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                            const_cast<char *>(data.data()), static_cast<DWORD>(data.size()));
    if (error != NO_ERROR) {
        throw std::runtime_error{std::format("send failed: {}", describe(error))};
    }
}

void Socket::close(const int code, const std::string_view reason)
{
    if (state_->closing.exchange(true) || state_->finished.load()) {
        return;
    }
    state_->our_close_code = code;
    state_->our_close_reason = std::string{reason.substr(0, 123)};
    HINTERNET handle = nullptr;
    {
        const std::lock_guard lock{state_->mutex};
        handle = state_->web_socket.get();
    }
    if (handle != nullptr) {
        WinHttpWebSocketClose(handle, static_cast<USHORT>(code), const_cast<char *>(state_->our_close_reason.data()),
                              static_cast<DWORD>(state_->our_close_reason.size()));
    }
    std::thread{[state = state_] {
        for (int i = 0; i < 50 && !state->finished.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        if (!state->finished.load()) {
            const std::lock_guard lock{state->mutex};
            state->web_socket.reset();
        }
    }}.detach();
}

void Socket::abort()
{
    state_->aborted.store(true);
    const std::lock_guard lock{state_->mutex};
    state_->web_socket.reset();
}

}

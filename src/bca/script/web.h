#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bca::script::web {

using Headers = std::vector<std::pair<std::string, std::string>>;

inline constexpr std::size_t kMaxBody = 16U << 20U;

struct HttpRequest {
    std::string method{"GET"};
    std::string url;
    Headers headers;
    std::string body;
    int timeout_ms{15000};
};

struct HttpResponse {
    int status{0};
    Headers headers;
    std::string body;
    std::string error;
};

[[nodiscard]] HttpResponse perform(const HttpRequest &request);

struct SocketEvent {
    enum class Kind { Open, Message, Close, Error };
    explicit SocketEvent(Kind what = Kind::Open) : kind(what) {}
    Kind kind{Kind::Open};
    bool binary{false};
    std::string data;
    int code{0};
};

class Socket {
public:
    using Listener = std::function<void(SocketEvent)>;

    [[nodiscard]] static std::shared_ptr<Socket> open(std::string url, Headers headers, Listener listener);

    ~Socket();
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

    void send(std::string_view data, bool binary);
    void close(int code, std::string_view reason);
    void abort();

    struct State;

private:
    explicit Socket(std::shared_ptr<State> state);
    std::shared_ptr<State> state_;
};

}

#include <iostream>

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>


#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>
#include <chrono>
#include <algorithm>
#include <vector>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>


std::tuple<std::string_view, std::string_view, std::string_view> getStreamAndData(std::string_view msg);
std::string_view getTickerSequenceNumber(std::string_view data);

//------------------------------------------------------------------------------

struct TickerEvent {

    static constexpr size_t SYMBOL_SIZE = 10;
    static constexpr size_t ID_SIZE = 15;

    TickerEvent() = default;

    TickerEvent(
            std::string_view symbol,
            std::string_view id,
            decltype(std::chrono::steady_clock::now()) monotonicTime,
            decltype(std::chrono::system_clock::now()) systemTime) {

        auto symbolCount = std::min(symbol.length(), SYMBOL_SIZE-1);
        std::strncpy(this->Symbol, symbol.begin(), symbolCount);
        Symbol[symbolCount] = 0;

        auto idCount = std::min(id.length(), ID_SIZE-1);
        std::strncpy(this->Id, id.begin(), idCount);
        Id[idCount] = 0;

        MonotonicTime = monotonicTime;
        SystemTime = systemTime;
    }

    char Symbol[SYMBOL_SIZE];
    char Id[ID_SIZE];
    decltype(std::chrono::steady_clock::now()) MonotonicTime;
    decltype(std::chrono::system_clock::now()) SystemTime;
};

std::ostream& operator<<(std::ostream& os, const TickerEvent& dt)
{
    os << dt.Symbol << ','
       << dt.Id << ','
       << dt.MonotonicTime.time_since_epoch().count() << ','
       << dt.SystemTime.time_since_epoch().count();
    return os;
}

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

// Sends a WebSocket message and prints the response
class session
{
    tcp::resolver resolver_;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws_;
    beast::flat_buffer buffer_;
    std::string host_;
    std::string target_;
    std::vector<TickerEvent> events_;

    static constexpr size_t EVENT_COUNT = 10000;

public:
    // Resolver and socket require an io_context
    explicit
    session(net::io_context& ioc, ssl::context& ctx)
            : resolver_(net::make_strand(ioc))
            , ws_(net::make_strand(ioc), ctx)
            , events_()
    {
        events_.reserve(EVENT_COUNT);
    }

    // Start the asynchronous operation
    void run(char const* host, char const* port, char const* target)
    {
        // Save these for later
        host_ = host;
        target_ = target;

        // Look up the domain name
        resolver_.async_resolve(
                host,
                port,
                [&](auto ec, auto result) {
                    on_resolve(ec, result);
                });
    }

    void on_resolve(beast::error_code ec, tcp::resolver::results_type results)
    {
        if(ec)
            return fail(ec, "resolve");

        // Set a timeout on the operation
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(ws_).async_connect(
                results,
                [&](auto ec, auto result) {
                    on_connect(ec, result);
                });
    }

    void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type ep)
    {
        if(ec)
            return fail(ec, "connect");

        // Set a timeout on the operation
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if(!SSL_set_tlsext_host_name(
                ws_.next_layer().native_handle(),
                host_.c_str()))
        {
            ec = beast::error_code(static_cast<int>(::ERR_get_error()),
                                   net::error::get_ssl_category());
            return fail(ec, "connect");
        }

        // Update the host_ string. This will provide the value of the
        // Host HTTP header during the WebSocket handshake.
        // See https://tools.ietf.org/html/rfc7230#section-5.4
        host_ += ':' + std::to_string(ep.port());

        // Perform the SSL handshake
        ws_.next_layer().async_handshake(
                ssl::stream_base::client,
                [&](auto ec) {
                    on_ssl_handshake(ec);
                });
    }

    void on_ssl_handshake(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "ssl_handshake");

        // Turn off the timeout on the tcp_stream, because
        // the websocket stream has its own timeout system.
        beast::get_lowest_layer(ws_).expires_never();

        // Set suggested timeout settings for the websocket
        ws_.set_option(
                websocket::stream_base::timeout::suggested(
                        beast::role_type::client));

        // Set a decorator to change the User-Agent of the handshake
        ws_.set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req)
                {
                    req.set(http::field::user_agent,
                            std::string(BOOST_BEAST_VERSION_STRING) +
                            " websocket-client-async-ssl");
                }));

        std::cout << host_ << target_ << std::endl;
        // Perform the websocket handshake
        ws_.async_handshake(host_, target_,
                            [&](auto ec) {
                                on_handshake(ec);
                            });
    }

    void on_handshake(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "handshake");

        // start reading
        ws_.async_read(
                buffer_,
                [&](auto ec, auto result) {
                    on_read(ec, result);
                });
    }

//    void on_write(beast::error_code ec, std::size_t bytes_transferred)
//    {
//        boost::ignore_unused(bytes_transferred);
//
//        if(ec)
//            return fail(ec, "write");
//
//        // Read a message into our buffer
//        ws_.async_read(
//                buffer_,
//                beast::bind_front_handler(
//                        &session::on_read,
//                        shared_from_this()));
//    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "read");

        auto bufferData = buffer_cast<const char*>(buffer_.cdata());
        std::string_view message(bufferData, bufferData + bytes_transferred);

        auto [symbol, stream, messageData] = getStreamAndData(message);

        if (stream == "bookTicker") {
            auto id = getTickerSequenceNumber(messageData);

            events_.emplace_back(symbol, id, std::chrono::steady_clock::now(), std::chrono::system_clock::now());

            if (events_.size() == EVENT_COUNT)
            {
                ws_.async_close(
                        websocket::close_code::normal,
                        [&](auto ec) {
                            on_close(ec);
                        });

                return;
            }
        }

        buffer_.clear();

        // keep reading
        ws_.async_read(
            buffer_,
            [&](auto ec, auto result) {
                on_read(ec, result);
            });
    }

    void on_close(beast::error_code ec)
    {
        std::cout << "symbol,id,monotonic_time,system_time" << std::endl;
        for (auto& event : events_) {
            std::cout << event << std::endl;
        }
    }
};


std::tuple<std::string_view, std::string_view, std::string_view> getStreamAndData(std::string_view msg) {
    auto streamStartIndex = msg.find(':') + 2;
    auto streamSepIndex = msg.find('@', streamStartIndex);
    auto streamEndIndex = msg.find('"', streamSepIndex);
    auto dataStart =  msg.find('{', streamEndIndex);

    return {
            msg.substr(streamStartIndex, streamSepIndex - streamStartIndex),
            msg.substr(streamSepIndex + 1, streamEndIndex - (streamSepIndex + 1)),
            msg.substr(dataStart, msg.length() - 1 - dataStart)
    };
}

std::string_view getTickerSequenceNumber(std::string_view data) {
    auto startIndex = data.find(':') + 1;
    auto endIndex = data.find(',', startIndex);
    return data.substr(startIndex, endIndex - startIndex);
}

int main(int argc, char** argv) {


    // Check command line arguments.
    if(argc != 4)
    {
        std::cerr <<
                  "Usage: web-socket-test <host> <port> <target>\n" <<
                  "Example:\n" <<
                  "    web-socket-test 54.178.200.199 9443 /stream?streams=bnbbtc@depth/bnbbtc@bookTicker\n";
        return EXIT_FAILURE;
    }
    auto const host = argv[1];
    auto const port = argv[2];
    auto const text = argv[3];

    net::io_context ioc;

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12_client};
    ctx.set_verify_mode(ssl::verify_none);


    // wss://stream.binance.com:9443.
    // Launch the asynchronous operation
    // "/stream?streams=bnbbtc@depth/bnbbtc@bookTicker"
    // "/ws/bnbbtc@depth"
    session s(ioc, ctx);
    //stream.binance.com
    s.run("54.178.200.199", "9443", "/stream?streams=bnbbtc@depth/bnbbtc@bookTicker");

    // Run the I/O service. The call will return when
    // the socket is closed.
    ioc.run();


//    std::string tickerMsg  = R"({"stream":"bnbbtc@bookTicker","data":{"u":2892084878,"s":"BNBBTC","b":"0.01631500","B":"3.23900000","a":"0.01631600","A":"28.17900000"}})";
//    std::string depthMsg  = R"({"stream":"bnbbtc@depth","data":{"e":"depthUpdate","E":1668645077001,"s":"BNBBTC","U":2892084874,"u":2892084879,"b":[["0.01630200","1.20000000"],["0.01628500","16.44500000"]],"a":[["0.01631600","28.17900000"]]}})";
//
//
//
//
//    auto [symbol, stream, data] = getStreamAndData(tickerMsg);
//
//    std::cout << symbol << std::endl;
//    std::cout << stream << std::endl;
//    std::cout << data << std::endl;

    return 0;
}

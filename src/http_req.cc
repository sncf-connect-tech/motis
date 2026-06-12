#include "motis/http_req.h"

#include "boost/asio/awaitable.hpp"
#include "boost/asio/cancel_after.hpp"
#include "boost/asio/co_spawn.hpp"
#include "boost/asio/io_context.hpp"
#include "boost/asio/ssl.hpp"
#include "boost/asio/use_awaitable.hpp"
#include "boost/beast/core.hpp"
#include "boost/beast/http.hpp"
#include "boost/beast/http/dynamic_body.hpp"
#include "boost/beast/ssl/ssl_stream.hpp"
#include "boost/beast/version.hpp"
#include "boost/iostreams/copy.hpp"
#include "boost/iostreams/filter/gzip.hpp"
#include "boost/iostreams/filtering_stream.hpp"
#include "boost/iostreams/filtering_streambuf.hpp"
#include "boost/url/url.hpp"

#include "net/base64.h"

#include "utl/verify.h"

namespace motis {

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = asio::ssl;

template <typename Stream>
asio::awaitable<http_response> req(
    Stream&&,
    boost::urls::url const&,
    std::map<std::string, std::string> const&,
    std::optional<std::string> const& body = std::nullopt,
    bool use_absolute_url = false);

asio::awaitable<http_response> req_no_tls(
    boost::urls::url const& url,
    std::map<std::string, std::string> const& headers,
    std::optional<std::string> const& body,
    std::chrono::seconds const timeout,
    std::optional<proxy> const& proxy) {
  auto executor = co_await asio::this_coro::executor;
  auto resolver = asio::ip::tcp::resolver{executor};
  auto stream = beast::tcp_stream{executor};

  auto const host = proxy ? proxy->host_ : url.host();
  auto const port =
      proxy ? proxy->port_ : std::string{url.has_port() ? url.port() : "80"};
  auto const results = co_await resolver.async_resolve(
      host, port, asio::cancel_after(timeout, asio::use_awaitable));

  stream.expires_after(timeout);

  co_await stream.async_connect(results);

  auto proxy_headers = headers;
  if (proxy && !proxy->user_.empty()) {
    proxy_headers.emplace(
        "Proxy-Authorization",
        fmt::format("Basic {}", net::encode_base64(fmt::format(
                                    "{}:{}", proxy->user_, proxy->password_))));
  }
  // HTTP proxies require absolute-form request target (RFC 7230 §5.3.2).
  co_return co_await req(std::move(stream), url, proxy_headers, body,
                         proxy.has_value());
}

asio::awaitable<http_response> req_tls(
    boost::urls::url const& url,
    std::map<std::string, std::string> const& headers,
    std::optional<std::string> const& body,
    std::chrono::seconds const timeout,
    std::optional<proxy> const& proxy) {
  auto ssl_ctx = ssl::context{ssl::context::tls_client};
  ssl_ctx.set_default_verify_paths();
  ssl_ctx.set_verify_mode(ssl::verify_none);
  ssl_ctx.set_options(ssl::context::default_workarounds |
                      ssl::context::single_dh_use);

  auto executor = co_await asio::this_coro::executor;
  auto resolver = asio::ip::tcp::resolver{executor};

  auto const target_host = std::string{url.host()};
  auto const target_port =
      std::string{url.has_port() ? url.port() : "443"};
  auto const connect_host = proxy ? proxy->host_ : target_host;
  auto const connect_port = proxy ? proxy->port_ : target_port;

  auto const results = co_await resolver.async_resolve(
      connect_host, connect_port,
      asio::cancel_after(timeout, asio::use_awaitable));

  auto tcp_stream = beast::tcp_stream{executor};
  tcp_stream.expires_after(timeout);
  co_await tcp_stream.async_connect(results);

  if (proxy) {
    // HTTP CONNECT tunnel through proxy.
    auto connect_req = http::request<http::empty_body>{
        http::verb::connect,
        fmt::format("{}:{}", target_host, target_port), 11};
    connect_req.set(http::field::host,
                    fmt::format("{}:{}", target_host, target_port));
    if (!proxy->user_.empty()) {
      connect_req.set(
          http::field::proxy_authorization,
          fmt::format("Basic {}",
                      net::encode_base64(fmt::format("{}:{}", proxy->user_,
                                                     proxy->password_))));
    }
    co_await http::async_write(tcp_stream, connect_req);

    auto buffer = beast::flat_buffer{};
    auto parser = http::response_parser<http::empty_body>{};
    parser.skip(true);
    co_await http::async_read(tcp_stream, buffer, parser);
    auto const connect_res = parser.release();
    if (connect_res.result_int() != 200) {
      throw utl::fail("proxy CONNECT failed with status {}",
                      connect_res.result_int());
    }
  }

  // Upgrade TCP stream to TLS. SNI must use the target host, not the proxy.
  auto stream = ssl::stream<beast::tcp_stream>{std::move(tcp_stream), ssl_ctx};
  if (!SSL_set_tlsext_host_name(stream.native_handle(),
                                const_cast<char*>(target_host.c_str()))) {
    throw boost::system::system_error{
        {static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category()}};
  }
  co_await stream.async_handshake(ssl::stream_base::client);
  co_return co_await req(std::move(stream), url, headers, body);
}

template <typename Stream>
asio::awaitable<http_response> req(
    Stream&& stream,
    boost::urls::url const& url,
    std::map<std::string, std::string> const& headers,
    std::optional<std::string> const& body,
    bool const use_absolute_url) {
  auto const target =
      use_absolute_url ? std::string{url.c_str()} : std::string{url.encoded_target()};
  auto req = http::request<http::string_body>{
      body ? http::verb::post : http::verb::get, target, 11};
  req.set(http::field::host, url.host());
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.set(http::field::accept_encoding, "gzip");
  for (auto const& [k, v] : headers) {
    req.set(k, v);
  }

  if (body) {
    req.body() = *body;
    req.prepare_payload();
  }

  co_await http::async_write(stream, req);

  auto p = http::response_parser<http::dynamic_body>{};
  p.eager(true);
  p.body_limit(kBodySizeLimit);

  auto buffer = beast::flat_buffer{};
  co_await http::async_read(stream, buffer, p);

  auto ec = beast::error_code{};
  beast::get_lowest_layer(stream).socket().shutdown(
      asio::ip::tcp::socket::shutdown_both, ec);
  co_return p.release();
}

asio::awaitable<http::response<http::dynamic_body>> http_GET(
    boost::urls::url url,
    std::map<std::string, std::string> const& headers,
    std::chrono::seconds const timeout,
    std::optional<proxy> const& proxy) {
  auto n_redirects = 0U;
  auto next_url = url;
  while (n_redirects < 3U) {
    auto const use_tls =
        next_url.scheme_id() == boost::urls::scheme::https;
    auto const res = co_await (
        use_tls ? req_tls(next_url, headers, std::nullopt, timeout, proxy)
                : req_no_tls(next_url, headers, std::nullopt, timeout, proxy));
    auto const code = res.base().result_int();
    if (code >= 300 && code < 400) {
      next_url = boost::urls::url{res.base()["Location"]};
      ++n_redirects;
      continue;
    } else {
      co_return res;
    }
  }
  throw utl::fail(R"(too many redirects: "{}", latest="{}")",
                  fmt::streamed(url), fmt::streamed(next_url));
}

asio::awaitable<http::response<http::dynamic_body>> http_POST(
    boost::urls::url url,
    std::map<std::string, std::string> const& headers,
    std::string const& body,
    std::chrono::seconds timeout,
    std::optional<proxy> const& proxy) {
  auto n_redirects = 0U;
  auto next_url = url;
  while (n_redirects < 3U) {
    auto const use_tls =
        next_url.scheme_id() == boost::urls::scheme::https;
    auto const res = co_await (
        use_tls ? req_tls(next_url, headers, body, timeout, proxy)
                : req_no_tls(next_url, headers, body, timeout, proxy));
    auto const code = res.base().result_int();
    if (code >= 300 && code < 400) {
      next_url = boost::urls::url{res.base()["Location"]};
      ++n_redirects;
      continue;
    } else {
      co_return res;
    }
  }
  throw utl::fail(R"(too many redirects: "{}", latest="{}")",
                  fmt::streamed(url), fmt::streamed(next_url));
}

std::string get_http_body(http_response const& res) {
  auto body = beast::buffers_to_string(res.body().data());
  if (res[http::field::content_encoding] == "gzip") {
    auto const src = boost::iostreams::array_source{body.data(), body.size()};
    auto is = boost::iostreams::filtering_istream{};
    auto os = std::stringstream{};
    is.push(boost::iostreams::gzip_decompressor{});
    is.push(src);
    boost::iostreams::copy(is, os);
    body = os.str();
  }
  return body;
}

}  // namespace motis

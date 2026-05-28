#include "motis/http_req.h"

#include "boost/asio/awaitable.hpp"
#include "boost/asio/co_spawn.hpp"
#include "boost/asio/io_context.hpp"
#include "boost/asio/ssl.hpp"
#include "boost/beast/core.hpp"
#include "boost/beast/core/detail/base64.hpp"
#include "boost/beast/http.hpp"
#include "boost/beast/http/dynamic_body.hpp"
#include "boost/beast/ssl/ssl_stream.hpp"
#include "boost/beast/version.hpp"
#include "boost/iostreams/copy.hpp"
#include "boost/iostreams/filter/gzip.hpp"
#include "boost/iostreams/filtering_stream.hpp"
#include "boost/iostreams/filtering_streambuf.hpp"
#include "boost/url/url.hpp"

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
    std::optional<proxy> const& proxy = std::nullopt,
    std::optional<std::string> const& body = std::nullopt);

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
  auto const results = co_await resolver.async_resolve(host, port);

  stream.expires_after(timeout);

  co_await stream.async_connect(results);

  // For proxied requests, send the absolute URI form required by HTTP proxies.
  if (proxy) {
    auto abs_url = boost::urls::url{url};
    auto proxy_req = http::request<http::string_body>{
        body ? http::verb::post : http::verb::get,
        abs_url.c_str(),  // absolute URI: scheme://host/path
        11};
    proxy_req.set(http::field::host, url.host());
    proxy_req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    proxy_req.set(http::field::accept_encoding, "gzip");
    if (proxy->credentials_) {
      auto const& creds = *proxy->credentials_;
      auto encoded = std::string(
          beast::detail::base64::encoded_size(creds.size()), '\0');
      auto const n =
          beast::detail::base64::encode(encoded.data(), creds.data(), creds.size());
      encoded.resize(n);
      proxy_req.set(http::field::proxy_authorization, "Basic " + encoded);
    }
    for (auto const& [k, v] : headers) {
      proxy_req.set(k, v);
    }
    if (body) {
      proxy_req.body() = *body;
      proxy_req.prepare_payload();
    }
    co_await http::async_write(stream, proxy_req);

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

  co_return co_await req(std::move(stream), url, headers, proxy, body);
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

  if (proxy) {
    // CONNECT tunneling: connect to proxy via plain TCP, then tunnel TLS.
    auto tcp_stream = beast::tcp_stream{executor};
    auto const proxy_results =
        co_await resolver.async_resolve(proxy->host_, proxy->port_);
    tcp_stream.expires_after(timeout);
    co_await tcp_stream.async_connect(proxy_results);

    // Send CONNECT request.
    auto connect_req = http::request<http::empty_body>{
        http::verb::connect, target_host + ":" + target_port, 11};
    connect_req.set(http::field::host, target_host + ":" + target_port);
    connect_req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    if (proxy->credentials_) {
      auto const& creds = *proxy->credentials_;
      auto encoded = std::string(
          beast::detail::base64::encoded_size(creds.size()), '\0');
      auto const n = beast::detail::base64::encode(
          encoded.data(), creds.data(), creds.size());
      encoded.resize(n);
      connect_req.set(http::field::proxy_authorization, "Basic " + encoded);
    }
    co_await http::async_write(tcp_stream, connect_req);

    // Read CONNECT response (expect 200).
    auto connect_res = http::response<http::empty_body>{};
    auto connect_parser = http::response_parser<http::empty_body>{connect_res};
    connect_parser.skip(true);
    auto buffer = beast::flat_buffer{};
    co_await http::async_read(tcp_stream, buffer, connect_parser);
    if (connect_parser.get().result_int() != 200) {
      throw std::runtime_error{
          fmt::format("proxy CONNECT failed: {}",
                      connect_parser.get().result_int())};
    }

    // Upgrade the established tunnel to TLS.
    auto stream = ssl::stream<beast::tcp_stream>{std::move(tcp_stream), ssl_ctx};
    if (!SSL_set_tlsext_host_name(stream.native_handle(),
                                  const_cast<char*>(target_host.c_str()))) {
      throw boost::system::system_error{{static_cast<int>(::ERR_get_error()),
                                         asio::error::get_ssl_category()}};
    }
    co_await stream.async_handshake(ssl::stream_base::client);
    co_return co_await req(std::move(stream), url, headers, std::nullopt, body);
  }

  auto stream = ssl::stream<beast::tcp_stream>{executor, ssl_ctx};

  if (!SSL_set_tlsext_host_name(stream.native_handle(),
                                const_cast<char*>(target_host.c_str()))) {
    throw boost::system::system_error{
        {static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category()}};
  }

  auto const results = co_await resolver.async_resolve(target_host, target_port);

  stream.next_layer().expires_after(timeout);

  co_await beast::get_lowest_layer(stream).async_connect(results);
  co_await stream.async_handshake(ssl::stream_base::client);
  co_return co_await req(std::move(stream), url, headers, proxy, body);
}

template <typename Stream>
asio::awaitable<http_response> req(
    Stream&& stream,
    boost::urls::url const& url,
    std::map<std::string, std::string> const& headers,
    std::optional<proxy> const& proxy,
    std::optional<std::string> const& body) {
  auto req = http::request<http::string_body>{
      body ? http::verb::post : http::verb::get, url.encoded_target(), 11};
  req.set(http::field::host, url.host());
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.set(http::field::accept_encoding, "gzip");
  if (proxy && proxy->credentials_) {
    auto const& creds = *proxy->credentials_;
    auto encoded = std::string(beast::detail::base64::encoded_size(creds.size()), '\0');
    auto const n = beast::detail::base64::encode(encoded.data(), creds.data(), creds.size());
    encoded.resize(n);
    req.set(http::field::proxy_authorization, "Basic " + encoded);
  }
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

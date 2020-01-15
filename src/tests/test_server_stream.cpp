/*
* TLS ASIO Stream Client-Server Interaction Test
* (C) 2018-2020 Jack Lloyd
*     2018-2020 Hannes Rantzsch
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <botan/asio_stream.h>
#include <botan/auto_rng.h>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/bind.hpp>

#include "../cli/tls_helpers.h"  // for Basic_Credentials_Manager

namespace {

namespace beast = boost::beast;
namespace asio = boost::asio;
namespace _ = boost::asio::placeholders;

using tcp = asio::ip::tcp;
using error_code = boost::system::error_code;
using ssl_stream = Botan::TLS::Stream<beast::tcp_stream>;

constexpr auto k_timeout = std::chrono::seconds(3);

static std::string server_cert() { return Botan_Tests::Test::data_dir() + "/x509/certstor/cert1.crt"; }
static std::string server_key() { return Botan_Tests::Test::data_dir() + "/x509/certstor/key01.pem"; }

class server : public std::enable_shared_from_this<server>
   {
   public:
      server(asio::io_context& io_context, Botan_Tests::Test::Result& result)
         : m_ioc(io_context),
           m_acceptor(io_context),
           m_accept_timer(io_context),
           m_credentials_manager(m_rng, server_cert(), server_key()),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()),
           m_result(result) {}

      void listen(const tcp::endpoint& endpoint)
         {
         error_code ec;

         m_acceptor.open(endpoint.protocol(), ec);
         m_acceptor.set_option(asio::socket_base::reuse_address(true), ec);
         m_acceptor.bind(endpoint, ec);
         m_acceptor.listen(asio::socket_base::max_listen_connections, ec);

         check_rc("listen", ec);

         m_accept_timer.expires_after(k_timeout);
         m_accept_timer.async_wait(boost::bind(&tcp::acceptor::close, &m_acceptor));
         m_acceptor.async_accept(m_ioc, beast::bind_front_handler(&server::handle_accept, shared_from_this()));
         }

   private:
      void handle_accept(const error_code& ec, tcp::socket socket)
         {
         // Note: If this fails with 'Operation canceled', it likely means m_accept_timer expired and the port is taken.
         check_rc("accept", ec);

         // Note: If this was a real server, we should create a new session (with its own stream) for each accepted
         // connection. In this test we only have one connection.
         m_stream = std::unique_ptr<ssl_stream>(new ssl_stream(std::move(socket), m_ctx));

         beast::get_lowest_layer(*m_stream).expires_after(std::chrono::seconds(k_timeout));
         m_stream->async_handshake(Botan::TLS::Connection_Side::SERVER,
                                   beast::bind_front_handler(&server::handle_handshake, shared_from_this()));
         }

      void handle_handshake(const error_code& ec)
         {
         check_rc("handshake", ec);

         beast::get_lowest_layer(*m_stream).expires_after(std::chrono::seconds(k_timeout));
         asio::async_read(*m_stream,
                          asio::buffer(data_, max_length),
                          beast::bind_front_handler(&server::handle_read, shared_from_this()));
         }

      void handle_read(const error_code& ec, size_t bytes_transferred)
         {
         check_rc("read", ec);

         beast::get_lowest_layer(*m_stream).expires_after(std::chrono::seconds(k_timeout));
         asio::async_write(*m_stream,
                           asio::buffer(data_, bytes_transferred),
                           boost::bind(&server::handle_write, shared_from_this(), _::error));
         }

      void handle_write(const error_code& ec)
         {
         check_rc("write", ec);
         }

   private:
      void check_rc(const std::string& msg, const error_code& ec)
         {
         if(ec)
            { m_result.test_failure(msg, ec.message()); }
         else
            { m_result.test_success(msg); }
         }

   private:
      asio::io_context& m_ioc;
      tcp::acceptor m_acceptor;
      asio::system_timer m_accept_timer;

      Botan::AutoSeeded_RNG m_rng;
      Basic_Credentials_Manager m_credentials_manager;
      Botan::TLS::Session_Manager_Noop m_session_mgr;
      Botan::TLS::Policy m_policy;
      Botan::TLS::Context m_ctx;

      // Note: m_result is not mutexed. We assume to be handling one client message at a time in a ping-pong fashion.
      Botan_Tests::Test::Result& m_result;

      std::unique_ptr<ssl_stream> m_stream;
      enum { max_length = 1024 };
      char data_[max_length];
   };

class client : public std::enable_shared_from_this<client>
   {
      static void accept_all(
         const std::vector<Botan::X509_Certificate>&,
         const std::vector<std::shared_ptr<const Botan::OCSP::Response>>&,
         const std::vector<Botan::Certificate_Store*>&, Botan::Usage_Type,
         const std::string&, const Botan::TLS::Policy&) {}

   public:
      client(asio::io_context& io_context, Botan_Tests::Test::Result& result)
         : m_credentials_manager(true, ""),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()),
           m_stream(io_context, m_ctx),
           m_result(result)
         {
         m_ctx.set_verify_callback(accept_all);
         }

      void connect(const std::vector<tcp::endpoint>& endpoints)
         {
         beast::get_lowest_layer(m_stream).expires_after(std::chrono::seconds(k_timeout));
         asio::async_connect(beast::get_lowest_layer(m_stream).socket(), endpoints,
                             boost::bind(&client::handshake, shared_from_this(), _::error));
         }

   private:
      void handshake(const error_code& ec)
         {
         check_rc("connect", ec);

         beast::get_lowest_layer(m_stream).expires_after(std::chrono::seconds(k_timeout));
         m_stream.async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                  beast::bind_front_handler(&client::send_message, shared_from_this()));
         }

      void send_message(const error_code& ec)
         {
         check_rc("handshake", ec);

         beast::get_lowest_layer(m_stream).expires_after(std::chrono::seconds(k_timeout));
         asio::async_write(m_stream, asio::buffer(m_message, max_length),
                           beast::bind_front_handler(&client::recv_response, shared_from_this()));
         }

      void recv_response(const error_code& ec, size_t)
         {
         check_rc("write", ec);

         beast::get_lowest_layer(m_stream).expires_after(std::chrono::seconds(k_timeout));
         asio::async_read(m_stream, asio::buffer(data_, max_length),
                          beast::bind_front_handler(&client::check_response, shared_from_this()));
         }

      void check_response(const error_code& ec, size_t)
         {
         check_rc("read", ec);

         m_result.test_eq("correct message", std::string(data_), std::string(m_message));
         }

   private:
      void check_rc(const std::string& msg, const error_code& ec)
         {
         if(ec)
            { m_result.test_failure(msg, ec.message()); }
         else
            { m_result.test_success(msg); }
         }

   private:
      Botan::AutoSeeded_RNG m_rng;
      Basic_Credentials_Manager m_credentials_manager;
      Botan::TLS::Session_Manager_Noop m_session_mgr;
      Botan::TLS::Policy m_policy;
      Botan::TLS::Context m_ctx;

      ssl_stream m_stream;

      enum { max_length = 1024 };
      char data_[max_length];
      const char m_message[max_length] = "Time is an illusion. Lunchtime doubly so.";

      Botan_Tests::Test::Result& m_result;
   };

}  // namespace

namespace Botan_Tests {

class Tls_Server_Stream_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         auto server_results = Test::Result("Server");
         auto client_results = Test::Result("Client");

         asio::io_context io_context;
         std::vector<tcp::endpoint> endpoints{tcp::endpoint{asio::ip::make_address("127.0.0.1"), 8082}};

         auto s = std::make_shared<server>(io_context, server_results);
         s->listen(endpoints.back());

         auto c = std::make_shared<client>(io_context, client_results);
         c->connect(endpoints);

         io_context.run();

         return {server_results, client_results};
         }
   };

BOTAN_REGISTER_TEST("tls_server_stream", Tls_Server_Stream_Tests);

}  // namespace Botan_Tests

#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO

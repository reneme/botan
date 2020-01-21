/*
* TLS ASIO Stream Client-Server Interaction Test
* (C) 2018-2020 Jack Lloyd
*     2018-2020 Hannes Rantzsch
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

// first version to be compatible with Networking TS (N4656) and boost::beast
#include <boost/version.hpp>
#if BOOST_VERSION >= 106600

#include <functional>

#include <botan/asio_stream.h>
#include <botan/auto_rng.h>

#include <boost/asio.hpp>
#include <boost/asio/yield.hpp>

#include "../cli/tls_helpers.h"  // for Basic_Credentials_Manager

namespace {

namespace net = boost::asio;

using tcp = net::ip::tcp;
using error_code = boost::system::error_code;
using ssl_stream = Botan::TLS::Stream<net::ip::tcp::socket>;
using namespace std::placeholders;

constexpr auto k_timeout = std::chrono::seconds(3);

static std::string server_cert() { return Botan_Tests::Test::data_dir() + "/x509/certstor/cert1.crt"; }
static std::string server_key() { return Botan_Tests::Test::data_dir() + "/x509/certstor/key01.pem"; }

class timeout_exception : public std::runtime_error
   {
      using std::runtime_error::runtime_error;
   };

class participant : public net::coroutine
   {
   protected:
      participant(net::io_context& io_context, Botan_Tests::Test::Result& result)
         : m_credentials_manager(true, ""),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()),
           m_timer(io_context),
           m_result(result) {}

      participant(net::io_context& io_context, const std::string& server_cert, const std::string& server_key,
                  Botan_Tests::Test::Result& result)
         : m_credentials_manager(m_rng, server_cert, server_key),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()),
           m_timer(io_context),
           m_result(result) {}

      void set_timer(const std::string& msg)
         {
         m_timer.expires_after(k_timeout);
         m_timer.async_wait([this, msg](const error_code &ec)
            {
            if(ec != net::error::operation_aborted)  // timer cancelled
               {
               m_result.test_failure(m_result.who() + ": timeout in " + msg);
               throw timeout_exception(m_result.who());
               }
            });
         }

      void stop_timer()
         {
         m_timer.cancel();
         }

      void check_ec(const std::string& msg, const error_code& ec)
         {
         if(ec)
            { m_result.test_failure(msg, ec.message()); }
         else
            { m_result.test_success(msg); }
         }

      Botan_Tests::Test::Result& result() { return m_result; }

   protected:
      Botan::AutoSeeded_RNG m_rng;
      Basic_Credentials_Manager m_credentials_manager;
      Botan::TLS::Session_Manager_Noop m_session_mgr;
      Botan::TLS::Policy m_policy;
      Botan::TLS::Context m_ctx;
      std::unique_ptr<ssl_stream> m_stream;

      enum { max_length = 512 };
      char m_data[max_length];

   private:
      net::system_timer m_timer;
      // Note: m_result is not mutexed. We assume to be handling one message at a time in a ping-pong fashion.
      Botan_Tests::Test::Result& m_result;
   };

class server : public participant, public std::enable_shared_from_this<server>
   {
   public:
      server(net::io_context& io_context, Botan_Tests::Test::Result& result)
         : participant(io_context, server_cert(), server_key(), result),
           m_acceptor(io_context) {}

      void listen(net::io_context& io_context, const tcp::endpoint& endpoint)
         {
         error_code ec;

         m_acceptor.open(endpoint.protocol(), ec);
         m_acceptor.set_option(net::socket_base::reuse_address(true), ec);
         m_acceptor.bind(endpoint, ec);
         m_acceptor.listen(net::socket_base::max_listen_connections, ec);

         check_ec("listen", ec);

         set_timer("accept");
         m_acceptor.async_accept(io_context, std::bind(&server::start_session, shared_from_this(), _1, _2));
         }

   private:
      void start_session(const error_code& ec, tcp::socket socket)
         {
         // Note: If this fails with 'Operation canceled', it likely means the timer expired and the port is taken.
         check_ec("accept", ec);

         // Note: If this was a real server, we should create a new session (with its own stream) for each accepted
         // connection. In this test we only have one connection.
         m_stream = std::unique_ptr<ssl_stream>(new ssl_stream(std::move(socket), m_ctx));

         set_timer("handshake");
         m_stream->async_handshake(Botan::TLS::Connection_Side::SERVER,
                                   std::bind(&server::handshake, shared_from_this(), _1));
         }

      void handshake(const error_code& ec)
         {
         check_ec("handshake", ec);
         loop(error_code{});
         }

      void loop(const error_code& ec, size_t bytes_transferred=0)
         {
         reenter(*this)
            {
            set_timer("read_message");
            yield net::async_read(*m_stream,
                                  net::buffer(m_data, max_length),
                                  std::bind(&server::loop, shared_from_this(), _1, _2));
            check_ec("read_message", ec);

            set_timer("send_response");
            yield net::async_write(*m_stream,
                                   net::buffer(m_data, bytes_transferred),
                                   std::bind(&server::loop, shared_from_this(), _1, _2));
            check_ec("send_response", ec);
            }
         }

   private:
      tcp::acceptor m_acceptor;
   };

class client : public participant, public std::enable_shared_from_this<client>
   {
      static void accept_all(
         const std::vector<Botan::X509_Certificate>&,
         const std::vector<std::shared_ptr<const Botan::OCSP::Response>>&,
         const std::vector<Botan::Certificate_Store*>&, Botan::Usage_Type,
         const std::string&, const Botan::TLS::Policy&) {}

   public:
      client(net::io_context& io_context, Botan_Tests::Test::Result& result)
         : participant(io_context, result)
         {
         m_ctx.set_verify_callback(accept_all);
         m_stream = std::unique_ptr<ssl_stream>(new ssl_stream(io_context, m_ctx));
         }

      void test_conversation(const std::vector<tcp::endpoint>& endpoints)
         {
         set_timer("connect");
         net::async_connect(m_stream->lowest_layer(),
                            endpoints,
                            std::bind(&client::conversation, shared_from_this(), _1));
         }

      void test_eager_close(const std::vector<tcp::endpoint>& endpoints)
         {
         set_timer("connect");
         net::async_connect(m_stream->lowest_layer(),
                            endpoints,
                            std::bind(&client::eager_close, shared_from_this(), _1));
         }

   private:
      // test a complete conversation with the echo server, including correct shutdown on both sides
      void conversation(const error_code& ec)
         {
         static auto test_case = &client::conversation;
         reenter(*this)
            {
            check_ec("connect", ec);

            set_timer("handshake");
            yield m_stream->async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                            std::bind(test_case, shared_from_this(), _1));
            check_ec("handshake", ec);

            set_timer("send_message");
            yield net::async_write(*m_stream,
                                   net::buffer(m_message, max_length),
                                   std::bind(test_case, shared_from_this(), _1));
            check_ec("send_message", ec);

            set_timer("receive_response");
            yield net::async_read(*m_stream,
                                  net::buffer(m_data, max_length),
                                  std::bind(test_case, shared_from_this(), _1));
            check_ec("receive_response", ec);
            result().test_eq("correct message", std::string(m_data), std::string(m_message));

            set_timer("shutdown");
            yield m_stream->async_shutdown(std::bind(test_case, shared_from_this(), _1));
            check_ec("shutdown", ec);

            stop_timer();
            }
         }

      // the client shuts down the session, but closes the socket without waiting for a response
      void eager_close(const error_code& ec)
         {
         static auto test_case = &client::eager_close;
         reenter(*this)
            {
            check_ec("connect", ec);

            set_timer("handshake");
            yield m_stream->async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                            std::bind(test_case, shared_from_this(), _1));
            check_ec("handshake", ec);

            set_timer("shutdown");
            yield m_stream->async_shutdown(std::bind(test_case, shared_from_this(), _1));
            check_ec("shutdown", ec);

            set_timer("receive_response");
            auto self = shared_from_this();
            /* no yield! */ net::async_read(*m_stream, net::buffer(m_data, max_length),
                                            [this, self](const error_code &ec, size_t)
               {
               // check that "waiting" for the server's shutdown turns out to be aborted
               result().confirm("async_read is aborted", ec == net::error::operation_aborted);
               });

            m_stream->lowest_layer().close();

            stop_timer();
            }
         }

   private:
      const char m_message[max_length] = "Time is an illusion. Lunchtime doubly so.";
   };

#include <boost/asio/unyield.hpp>

}  // namespace

namespace Botan_Tests {

class Tls_Server_Stream_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         auto server_results = Test::Result("Server");
         auto client_results = Test::Result("Client");

         net::io_context io_context;
         std::vector<tcp::endpoint> endpoints{tcp::endpoint{net::ip::make_address("127.0.0.1"), 8082}};

         auto s = std::make_shared<server>(io_context, server_results);
         s->listen(io_context, endpoints.back());

         auto c = std::make_shared<client>(io_context, client_results);
         // TODO: multiple test cases
         c->test_conversation(endpoints);
         // c->test_eager_close(endpoints);

         try
            {
            io_context.run();
            }
         catch(timeout_exception&) { /* the test result will already contain a failure */ }

         return {server_results, client_results};
         }
   };

BOTAN_REGISTER_TEST("tls_server_stream", Tls_Server_Stream_Tests);

}  // namespace Botan_Tests

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO

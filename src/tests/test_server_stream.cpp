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

class participant
   {
   protected:
      participant(net::io_context& io_context, Botan_Tests::Test::Result& result) : m_timer(io_context),
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

      void check_rc(const std::string& msg, const error_code& ec)
         {
         if(ec)
            { m_result.test_failure(msg, ec.message()); }
         else
            { m_result.test_success(msg); }
         }

      Botan_Tests::Test::Result& result() { return m_result; }

   private:
      net::system_timer m_timer;
      // Note: m_result is not mutexed. We assume to be handling one message at a time in a ping-pong fashion.
      Botan_Tests::Test::Result& m_result;

   };

class server : public participant, public std::enable_shared_from_this<server>
   {
   public:
      server(net::io_context& io_context, Botan_Tests::Test::Result& result)
         : participant(io_context, result),
           m_ioc(io_context),
           m_acceptor(io_context),
           m_credentials_manager(m_rng, server_cert(), server_key()),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()) {}

      void listen(const tcp::endpoint& endpoint)
         {
         error_code ec;

         m_acceptor.open(endpoint.protocol(), ec);
         m_acceptor.set_option(net::socket_base::reuse_address(true), ec);
         m_acceptor.bind(endpoint, ec);
         m_acceptor.listen(net::socket_base::max_listen_connections, ec);

         check_rc("listen", ec);

         set_timer("accept");
         m_acceptor.async_accept(m_ioc, std::bind(&server::handle_accept, shared_from_this(), _1, _2));
         }

   private:
      void handle_accept(const error_code& ec, tcp::socket socket)
         {
         // Note: If this fails with 'Operation canceled', it likely means m_accept_timer expired and the port is taken.
         check_rc("accept", ec);

         // Note: If this was a real server, we should create a new session (with its own stream) for each accepted
         // connection. In this test we only have one connection.
         m_stream = std::unique_ptr<ssl_stream>(new ssl_stream(std::move(socket), m_ctx));

         set_timer("handshake");
         m_stream->async_handshake(Botan::TLS::Connection_Side::SERVER,
                                   std::bind(&server::read_message, shared_from_this(), _1));
         }

      void read_message(const error_code& ec)
         {
         check_rc("handshake", ec);

         set_timer("read_message");
         net::async_read(*m_stream,
                         net::buffer(data_, max_length),
                         std::bind(&server::send_response, shared_from_this(), _1, _2));
         }

      void send_response(const error_code& ec, size_t bytes_transferred)
         {
         check_rc("read_message", ec);

         set_timer("send_response");
         net::async_write(*m_stream,
                          net::buffer(data_, bytes_transferred),
                          std::bind(&server::handle_write, shared_from_this(), _1));
         }

      void handle_write(const error_code& ec)
         {
         stop_timer();
         check_rc("send_response", ec);
         }

   private:
      net::io_context& m_ioc;
      tcp::acceptor m_acceptor;

      Botan::AutoSeeded_RNG m_rng;
      Basic_Credentials_Manager m_credentials_manager;
      Botan::TLS::Session_Manager_Noop m_session_mgr;
      Botan::TLS::Policy m_policy;
      Botan::TLS::Context m_ctx;

      std::unique_ptr<ssl_stream> m_stream;
      enum { max_length = 1024 };
      char data_[max_length];
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
         : participant(io_context, result),
           m_credentials_manager(true, ""),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()),
           m_stream(io_context, m_ctx)
         {
         m_ctx.set_verify_callback(accept_all);
         }

      void connect(const std::vector<tcp::endpoint>& endpoints)
         {
         set_timer("connect");
         net::async_connect(m_stream.lowest_layer(), endpoints, std::bind(&client::handshake, shared_from_this(), _1));
         }

   private:
      void handshake(const error_code& ec)
         {
         check_rc("connect", ec);

         set_timer("handshake");
         m_stream.async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                  std::bind(&client::send_message, shared_from_this(), _1));
         }

      void send_message(const error_code& ec)
         {
         check_rc("handshake", ec);

         set_timer("send_message");
         net::async_write(m_stream,
                          net::buffer(m_message, max_length),
                          std::bind(&client::receive_response, shared_from_this(), _1, _2));
         }

      void receive_response(const error_code& ec, size_t)
         {
         check_rc("send_message", ec);

         set_timer("receive_response");
         net::async_read(m_stream,
                         net::buffer(data_, max_length),
                         std::bind(&client::check_response, shared_from_this(), _1, _2));
         }

      void check_response(const error_code& ec, size_t)
         {
         stop_timer();

         check_rc("receive_response", ec);

         result().test_eq("correct message", std::string(data_), std::string(m_message));
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

         net::io_context io_context;
         std::vector<tcp::endpoint> endpoints{tcp::endpoint{net::ip::make_address("127.0.0.1"), 8082}};

         auto s = std::make_shared<server>(io_context, server_results);
         s->listen(endpoints.back());

         auto c = std::make_shared<client>(io_context, client_results);
         c->connect(endpoints);

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

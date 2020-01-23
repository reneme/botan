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
using Result = Botan_Tests::Test::Result;

static const auto k_timeout = std::chrono::seconds(3);
static const auto k_endpoints = std::vector<tcp::endpoint> {tcp::endpoint{net::ip::make_address("127.0.0.1"), 8082}};

enum { max_msg_length = 512 };

static std::string server_cert() { return Botan_Tests::Test::data_dir() + "/x509/certstor/cert1.crt"; }
static std::string server_key() { return Botan_Tests::Test::data_dir() + "/x509/certstor/key01.pem"; }

class Timeout_Exception : public std::runtime_error
   {
      using std::runtime_error::runtime_error;
   };

struct Side
   {
      Side()
         : m_credentials_manager(true, ""),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()) {}

      Side(const std::string& server_cert, const std::string& server_key)
         : m_credentials_manager(m_rng, server_cert, server_key),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()) {}

      virtual ~Side() {}

      net::mutable_buffer buffer() { return net::buffer(m_data, max_msg_length); }
      net::mutable_buffer buffer(size_t size) { return net::buffer(m_data, size); }

      std::string message() const { return std::string(m_data); }

   protected:
      Botan::AutoSeeded_RNG m_rng;
      Basic_Credentials_Manager m_credentials_manager;
      Botan::TLS::Session_Manager_Noop m_session_mgr;
      Botan::TLS::Policy m_policy;
      Botan::TLS::Context m_ctx;
      std::unique_ptr<ssl_stream> m_stream;

      char m_data[max_msg_length];
   };

struct Result_Wrapper
   {
      Result_Wrapper(net::io_context& ioc, const std::string& name) : m_timer(ioc), m_result(name) {}

      Result& result() { return m_result; }

      void set_timer(const std::string& msg)
         {
         m_timer.expires_after(k_timeout);
         m_timer.async_wait([this, msg](const error_code &ec)
            {
            if(ec != net::error::operation_aborted)  // timer cancelled
               {
               m_result.test_failure(m_result.who() + ": timeout in " + msg);
               throw Timeout_Exception(m_result.who());
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

      void confirm(const std::string& msg, bool condition)
         {
         m_result.confirm(msg, condition);
         }

   private:
      net::system_timer m_timer;
      Result m_result;
   };

class Server : public Side, public std::enable_shared_from_this<Server>
   {
   public:
      Server(net::io_context& ioc)
         : Side(server_cert(), server_key()),
           m_acceptor(ioc),
           m_result(ioc, "Server"),
           m_short_read_expected(false) {}

      void listen()
         {
         error_code ec;
         const auto endpoint = k_endpoints.back();

         m_acceptor.open(endpoint.protocol(), ec);
         m_acceptor.set_option(net::socket_base::reuse_address(true), ec);
         m_acceptor.bind(endpoint, ec);
         m_acceptor.listen(net::socket_base::max_listen_connections, ec);

         m_result.check_ec("listen", ec);

         m_result.set_timer("accept");
         m_acceptor.async_accept(std::bind(&Server::start_session, shared_from_this(), _1, _2));
         }

      void expect_short_read()
         {
         m_short_read_expected = true;
         }

      void shutdown()
         {
         m_result.set_timer("shutdown");
         m_stream->async_shutdown(std::bind(&Server::on_shutdown, shared_from_this(), _1));
         }

      Result result() { return m_result.result(); }

   private:
      void start_session(const error_code& ec, tcp::socket socket)
         {
         // Note: If this fails with 'Operation canceled', it likely means the timer expired and the port is taken.
         m_result.check_ec("accept", ec);

         // Note: If this was a real server, we should create a new session (with its own stream) for each accepted
         // connection. In this test we only have one connection.
         m_stream = std::unique_ptr<ssl_stream>(new ssl_stream(std::move(socket), m_ctx));

         m_result.set_timer("handshake");
         m_stream->async_handshake(Botan::TLS::Connection_Side::SERVER,
                                   std::bind(&Server::handshake, shared_from_this(), _1));
         }

      void handshake(const error_code& ec)
         {
         m_result.check_ec("handshake", ec);
         handle_write(error_code{});
         }

      void handle_write(const error_code& ec)
         {
         m_result.check_ec("send_response", ec);
         m_result.set_timer("read_message");
         net::async_read(*m_stream, buffer(),
                         std::bind(&Server::handle_read, shared_from_this(), _1, _2));
         }

      void handle_read(const error_code& ec, size_t bytes_transferred=0)
         {
         if(m_short_read_expected)
            {
            m_result.confirm("received stream truncated error", ec == Botan::TLS::StreamTruncated);
            }

         if(ec == net::error::eof || (m_short_read_expected && ec == Botan::TLS::StreamTruncated))
            {
            // TODO: Is this needed? At this point the channel should have written the close_notify to the buffer
            // already
            shutdown();
            }
         else
            {
            m_result.check_ec("read_message", ec);
            m_result.set_timer("send_response");
            net::async_write(*m_stream, buffer(bytes_transferred),
                             std::bind(&Server::handle_write, shared_from_this(), _1));
            }
         }

      void on_shutdown(const error_code& ec)
         {
         m_result.stop_timer();
         m_result.check_ec("shutdown", ec);
         }

   private:
      tcp::acceptor m_acceptor;
      Result_Wrapper m_result;
      bool m_short_read_expected;
   };

class Client : public Side
   {
      static void accept_all(
         const std::vector<Botan::X509_Certificate>&,
         const std::vector<std::shared_ptr<const Botan::OCSP::Response>>&,
         const std::vector<Botan::Certificate_Store*>&, Botan::Usage_Type,
         const std::string&, const Botan::TLS::Policy&) {}

   public:
      Client(net::io_context& ioc)
         : Side()
         {
         m_ctx.set_verify_callback(accept_all);
         m_stream = std::unique_ptr<ssl_stream>(new ssl_stream(ioc, m_ctx));
         }

      ssl_stream& stream() {return *m_stream; }
   };

#include <boost/asio/yield.hpp>

/* In this test case both parties perform the handshake, exchange a message, and do a full shutdown.
 *
 * The client expects the server to echo the same message it sent. The client then initiates the shutdown. The server is
 * expected to receive a close_notify and complete its shutdown with an error_code Success, the client is expected to
 * receive a close_notify and complete its shutdown with an error_code EOF.
 */
class Test_Conversation : public net::coroutine, public std::enable_shared_from_this<Test_Conversation>
   {
   public:
      Test_Conversation(net::io_context& ioc, std::shared_ptr<Server> /* unused */)
         : m_client(ioc),
           m_result(ioc, "Test Conversation") {}

      void run(const error_code& ec)
         {
         static auto test_case = &Test_Conversation::run;
         const char message[max_msg_length] = "Time is an illusion. Lunchtime doubly so.";

         reenter(*this)
            {
            m_result.set_timer("connect");
            yield net::async_connect(m_client.stream().lowest_layer(), k_endpoints,
                                     std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("connect", ec);

            m_result.set_timer("handshake");
            yield m_client.stream().async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                                    std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("handshake", ec);

            m_result.set_timer("send_message");
            yield net::async_write(m_client.stream(),
                                   net::buffer(message, max_msg_length),
                                   std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("send_message", ec);

            m_result.set_timer("receive_response");
            yield net::async_read(m_client.stream(),
                                  m_client.buffer(),
                                  std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("receive_response", ec);
            m_result.confirm("correct message", m_client.message() == std::string(message));

            m_result.set_timer("shutdown");
            yield m_client.stream().async_shutdown(std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("shutdown", ec);

            m_result.set_timer("await close_notify");
            yield net::async_read(m_client.stream(), m_client.buffer(),
                                  std::bind(test_case, shared_from_this(), _1));
            m_result.confirm("received close_notify", m_client.stream().shutdown_received());
            m_result.confirm("closed with EOF", ec == net::error::eof);

            m_result.stop_timer();
            }
         }

      Result result() { return m_result.result(); }

   private:
      Client m_client;
      Result_Wrapper m_result;
   };

/* In this test case the client shuts down the SSL connection, but does not wait for the server's response before
 * closing the socket. Accordingly, it will not receive the server's close_notify alert. Instead, the async_read
 * operation will be aborted. The server should be able to successfully shutdown nonetheless.
 */
class Test_Eager_Close : public net::coroutine, public std::enable_shared_from_this<Test_Eager_Close>
   {
   public:
      Test_Eager_Close(net::io_context& ioc, std::shared_ptr<Server> /* unused */)
         : m_client(ioc),
           m_result(ioc, "Test Eager Close") {}

      void run(const error_code& ec)
         {
         static auto test_case = &Test_Eager_Close::run;
         reenter(*this)
            {
            m_result.set_timer("connect");
            yield net::async_connect(m_client.stream().lowest_layer(), k_endpoints,
                                     std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("connect", ec);

            m_result.set_timer("handshake");
            yield m_client.stream().async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                                    std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("handshake", ec);

            m_result.set_timer("shutdown");
            yield m_client.stream().async_shutdown(std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("shutdown", ec);

            m_result.set_timer("receive_response");
            // Start the async_read but do not yield for it to complete. Instead, close the socket and expect the read
            // to be aborted.
            auto self = shared_from_this();
            /* no yield! */ net::async_read(m_client.stream(), m_client.buffer(),
                                            [this, self](const error_code &ec, size_t)
               {
               // check that "waiting" for the server's shutdown turns out to be aborted
               m_result.confirm("async_read is aborted", ec == net::error::operation_aborted);
               });

            m_result.confirm("did not receive close_notify", !m_client.stream().shutdown_received());
            m_client.stream().lowest_layer().close();

            m_result.stop_timer();
            }
         }

      Result result() { return m_result.result(); }

   private:
      Client m_client;
      Result_Wrapper m_result;
   };

/* In this test case the client closes the socket without properly shutting down the connection.
 * The server should see a short-read error.
 */
class Test_Close_Without_Shutdown
   : public net::coroutine,
     public std::enable_shared_from_this<Test_Close_Without_Shutdown>
   {
   public:
      Test_Close_Without_Shutdown(net::io_context& ioc, std::shared_ptr<Server> server)
         : m_client(ioc),
           m_result(ioc, "Test Close Without Shutdown"),
           m_server(server) {}

      void run(const error_code& ec)
         {
         static auto test_case = &Test_Close_Without_Shutdown::run;
         reenter(*this)
            {
            m_result.set_timer("connect");
            yield net::async_connect(m_client.stream().lowest_layer(), k_endpoints,
                                     std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("connect", ec);

            m_result.set_timer("handshake");
            yield m_client.stream().async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                                    std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("handshake", ec);

            m_server->expect_short_read();

            m_result.set_timer("receive_response");
            // Start the async_read but do not yield for it to complete. Instead, close the socket and expect the read
            // to be aborted.
            auto self = shared_from_this();
            /* no yield! */ net::async_read(m_client.stream(), m_client.buffer(),
                                            [this, self](const error_code &ec, size_t)
               {
               m_result.stop_timer();
               // check that "waiting" for the server's shutdown turns out to be aborted
               m_result.confirm("async_read is aborted", ec == net::error::operation_aborted);
               });

            m_result.confirm("received close_notify", !m_client.stream().shutdown_received());
            m_client.stream().lowest_layer().close();
            }
         }

      Result result() { return m_result.result(); }

   private:
      Client m_client;
      Result_Wrapper m_result;
      std::shared_ptr<Server> m_server;
   };

/* In this test case the server shuts down the connection but the client doesn't send the corresponding close_notify
 * response. Instead, it closes the socket immediately.
 * The server should see a short-read error.
 */
class Test_No_Shutdown_Response : public net::coroutine, public std::enable_shared_from_this<Test_No_Shutdown_Response>
   {
   public:
      Test_No_Shutdown_Response(net::io_context& ioc, std::shared_ptr<Server> server)
         : m_client(ioc),
           m_result(ioc, "Test No Shutdown Response"),
           m_server(server) {}

      void run(const error_code& ec)
         {
         static auto test_case = &Test_No_Shutdown_Response::run;
         reenter(*this)
            {
            m_result.set_timer("connect");
            yield net::async_connect(m_client.stream().lowest_layer(), k_endpoints,
                                     std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("connect", ec);

            m_result.set_timer("handshake");
            yield m_client.stream().async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                                    std::bind(test_case, shared_from_this(), _1));
            m_result.check_ec("handshake", ec);

            m_server->shutdown();

            m_result.set_timer("read close_notify");
            yield net::async_read(m_client.stream(), m_client.buffer(),
                                  std::bind(test_case, shared_from_this(), _1));
            m_result.confirm("read gives EOF", ec == net::error::eof);
            m_result.confirm("received close_notify", m_client.stream().shutdown_received());

            m_result.stop_timer();

            // close the socket rather than shutting down
            m_server->expect_short_read();
            m_client.stream().lowest_layer().close();
            }
         }

      Result result() { return m_result.result(); }

   private:
      Client m_client;
      Result_Wrapper m_result;
      std::shared_ptr<Server> m_server;
   };

#include <boost/asio/unyield.hpp>

template<typename TestT>
std::vector<Result> run_test_case()
   {
   net::io_context ioc;

   auto s = std::make_shared<Server>(ioc);
   s->listen();

   auto t = std::make_shared<TestT>(ioc, s);
   t->run(error_code{});

   try
      {
      ioc.run();
      }
   catch(Timeout_Exception&) { /* the test result will already contain a failure */ }

   return {s->result(), t->result()};
   }

}  // namespace

namespace Botan_Tests {

class Tls_Server_Stream_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         auto r1 = run_test_case<Test_Eager_Close>();
         results.insert(results.end(), r1.cbegin(), r1.cend());

         auto r2 = run_test_case<Test_Conversation>();
         results.insert(results.end(), r2.cbegin(), r2.cend());

         auto r3 = run_test_case<Test_Close_Without_Shutdown>();
         results.insert(results.end(), r3.cbegin(), r3.cend());

         auto r4 = run_test_case<Test_No_Shutdown_Response>();
         results.insert(results.end(), r4.cbegin(), r4.cend());

         return results;
         }
   };

BOTAN_REGISTER_TEST("tls_server_stream", Tls_Server_Stream_Tests);

}  // namespace Botan_Tests

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO

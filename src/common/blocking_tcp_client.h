#include <boost/asio/connect.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio/write.hpp>
#include <cstdlib>
#include <iostream>
#include <string>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>

using boost::asio::deadline_timer;
using boost::asio::ip::tcp;

//----------------------------------------------------------------------

//
// This class manages socket timeouts by applying the concept of a deadline.
// Each asynchronous operation is given a deadline by which it must complete.
// Deadlines are enforced by an "actor" that persists for the lifetime of the
// client object:
//
//  +----------------+
//  |                |
//  | check_deadline |<---+
//  |                |    |
//  +----------------+    | async_wait()
//              |         |
//              +---------+
//

class client
{
public:
    client();

    void connect(const std::string &host, const std::string &service, boost::posix_time::time_duration timeout);

    std::string read_until(char until, boost::posix_time::time_duration timeout);

    void write_line(const std::string &line, boost::posix_time::time_duration timeout);

private:
    void check_deadline();

    boost::asio::io_service io_service_;
    tcp::socket socket_;
    deadline_timer deadline_;
    boost::asio::streambuf input_buffer_;
};
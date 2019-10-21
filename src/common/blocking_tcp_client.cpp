#include "blocking_tcp_client.h"


using boost::lambda::_1;
using boost::lambda::bind;
using boost::lambda::var;

client::client()
    : socket_(io_service_),
      deadline_(io_service_)
{
  deadline_.expires_at(boost::posix_time::pos_infin);
  check_deadline();
}

void client::connect(const std::string &host, const std::string &service, boost::posix_time::time_duration timeout)
{
  tcp::resolver::query query(host, service);
  tcp::resolver::iterator iter = tcp::resolver(io_service_).resolve(query);
  deadline_.expires_from_now(timeout);

  boost::system::error_code ec = boost::asio::error::would_block;
  boost::asio::async_connect(socket_, iter, var(ec) = _1);

  // Block until the asynchronous operation has completed.
  do
    io_service_.run_one();
  while (ec == boost::asio::error::would_block);

  if (ec || !socket_.is_open())
    throw boost::system::system_error(
        ec ? ec : boost::asio::error::operation_aborted);
}

std::string client::read_until(char until, boost::posix_time::time_duration timeout)
{
  deadline_.expires_from_now(timeout);

  boost::system::error_code ec = boost::asio::error::would_block;
  boost::asio::async_read_until(socket_, input_buffer_, until, var(ec) = _1);
  
  // Block until the asynchronous operation has completed.
  do
    io_service_.run_one();
  while (ec == boost::asio::error::would_block);

  if (ec)
    throw boost::system::system_error(ec);

  std::string line;
  std::istream is(&input_buffer_);
  std::getline(is, line, until);
  return line;
}

void client::write_line(const std::string &line, boost::posix_time::time_duration timeout)
{
  std::string data = line + "\n";
  deadline_.expires_from_now(timeout);

  boost::system::error_code ec = boost::asio::error::would_block;
  boost::asio::async_write(socket_, boost::asio::buffer(data), var(ec) = _1);

  // Block until the asynchronous operation has completed.
  do
    io_service_.run_one();
  while (ec == boost::asio::error::would_block);

  if (ec)
    throw boost::system::system_error(ec);
}

void client::check_deadline()
{
  // Check whether the deadline has passed. We compare the deadline against
  // the current time since a new asynchronous operation may have moved the
  // deadline before this actor had a chance to run.
  if (deadline_.expires_at() <= deadline_timer::traits_type::now())
  {
    // The deadline has passed. The socket is closed so that any outstanding
    // asynchronous operations are cancelled. This allows the blocked
    // connect(), read_line() or write_line() functions to return.
    boost::system::error_code ignored_ec;
    socket_.close(ignored_ec);

    // There is no longer an active deadline. The expiry is set to positive
    // infinity so that the actor takes no action until a new deadline is set.
    deadline_.expires_at(boost::posix_time::pos_infin);
  }

  // Put the actor back to sleep.
  deadline_.async_wait(bind(&client::check_deadline, this));
}
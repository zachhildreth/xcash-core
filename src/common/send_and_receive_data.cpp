#include "common/send_and_receive_data.h"

std::string send_and_receive_data(std::string IP_address,std::string data2)
{
  // Variables
  boost::asio::io_service http_service;
  boost::asio::streambuf message;
  std::string string;

  try
  {
    // add the end string to the data
    data2 += SOCKET_END_STRING;

    // send the data to the server
    tcp::resolver resolver(http_service);
    tcp::resolver::query query(IP_address, SEND_DATA_PORT);
    tcp::resolver::iterator data = resolver.resolve(query);
    tcp::socket socket(http_service);
  
    std::future<tcp::resolver::iterator> conn_result = boost::asio::async_connect(socket,data,boost::asio::use_future);
    auto status = conn_result.wait_for(std::chrono::milliseconds(SOCKET_CONNECTION_TIMEOUT_SETTINGS));
   
    std::ostream http_request(&message);
    http_request << data2;
 
    // send the message and read the response
    boost::asio::write(socket, message);
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "}");
    std::istream response_stream(&response);  
    std::getline(response_stream, string, '}');
  }
  catch (...)
  {
    return "";
  }
  return string;
}
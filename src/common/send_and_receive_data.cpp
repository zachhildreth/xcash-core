#include "common/send_and_receive_data.h"
#include "common/blocking_tcp_client.h"

std::string send_and_receive_data(std::string IP_address,std::string data2)
{
  // Variables
  std::string string;
  auto connection_timeout = boost::posix_time::milliseconds(CONNECTION_TIMEOUT_SETTINGS);
  auto send_and_receive_data_timeout = boost::posix_time::milliseconds(SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS);

  try
  {
    // add the end string to the data
    data2 += SOCKET_END_STRING;

    client c;
    c.connect(IP_address, SEND_DATA_PORT, connection_timeout);
    
    // send the message and read the response
    c.write_line(data2, send_and_receive_data_timeout);
    string = c.read_until('}', send_and_receive_data_timeout);
  }
  catch (std::exception &ex)
  {
    return "";
  }
  return string;
}
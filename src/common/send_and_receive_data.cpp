#include "common/send_and_receive_data.h"
#include "common/blocking_tcp_client.h"

std::string send_and_receive_data(std::string IP_address,std::string data2)
{
  // Variables
  std::string string;
  auto timeout = boost::posix_time::milliseconds(SOCKET_CONNECTION_TIMEOUT_SETTINGS);

  try
  {
    // add the end string to the data
    data2 += SOCKET_END_STRING;

    client c;
    c.connect(IP_address, SEND_DATA_PORT, timeout);
    
    // send the message and read the response
    c.write_line(data2, timeout);
    string = c.read_until('}', timeout);
    //std::cout << string << std::endl << std::endl;
  }
  catch (std::exception &ex)
  {
    //std::cout << ex.what() << std::endl;
    return "";
  }
  return string;
}
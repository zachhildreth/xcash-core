// Copyright (c) 2018 X-CASH Project, Derived from 2014-2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <thread>
#include <future>
#include "include_base_utils.h"
#include "string_tools.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "common/boost_serialization_helper.h"
#include "common/base58.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "daemon/rpc_command_executor.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/hardfork.h"
#include <boost/format.hpp>
#include <boost/asio.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/ip/address.hpp>
#include <ctime>
#include <string>
#include "serialization/binary_utils.h"
#include "serialization/container.h"
#include "../../external/VRF_functions/VRF_functions.h"

using boost::asio::ip::tcp;

#undef XCASH_DEFAULT_LOG_CATEGORY
#define XCASH_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

namespace {
  void print_peer(std::string const & prefix, cryptonote::peer const & peer)
  {
    time_t now;
    time(&now);
    time_t last_seen = static_cast<time_t>(peer.last_seen);

    std::string id_str;
    std::string port_str;
    std::string elapsed = epee::misc_utils::get_time_interval_string(now - last_seen);
    std::string ip_str = epee::string_tools::get_ip_string_from_int32(peer.ip);
    std::stringstream peer_id_str;
    peer_id_str << std::hex << std::setw(16) << peer.id;
    peer_id_str >> id_str;
    epee::string_tools::xtype_to_string(peer.port, port_str);
    std::string addr_str = ip_str + ":" + port_str;
    tools::msg_writer() << boost::format("%-10s %-25s %-25s %s") % prefix % id_str % addr_str % elapsed;
  }

  void print_block_header(cryptonote::block_header_response const & header)
  {
    tools::success_msg_writer()
      << "timestamp: " << boost::lexical_cast<std::string>(header.timestamp) << std::endl
      << "previous hash: " << header.prev_hash << std::endl
      << "nonce: " << boost::lexical_cast<std::string>(header.nonce) << std::endl
      << "is orphan: " << header.orphan_status << std::endl
      << "height: " << boost::lexical_cast<std::string>(header.height) << std::endl
      << "depth: " << boost::lexical_cast<std::string>(header.depth) << std::endl
      << "hash: " << header.hash << std::endl
      << "difficulty: " << boost::lexical_cast<std::string>(header.difficulty) << std::endl
      << "POW hash: " << header.pow_hash << std::endl
      << "block size: " << header.block_size << std::endl
      << "block weight: " << header.block_weight << std::endl
      << "num txes: " << header.num_txes << std::endl
      << "reward: " << cryptonote::print_money(header.reward);
  }

  std::string get_human_time_ago(time_t t, time_t now)
  {
    if (t == now)
      return "now";
    time_t dt = t > now ? t - now : now - t;
    std::string s;
    if (dt < 90)
      s = boost::lexical_cast<std::string>(dt) + " seconds";
    else if (dt < 90 * 60)
      s = boost::lexical_cast<std::string>(dt/60) + " minutes";
    else if (dt < 36 * 3600)
      s = boost::lexical_cast<std::string>(dt/3600) + " hours";
    else
      s = boost::lexical_cast<std::string>(dt/(3600*24)) + " days";
    return s + " " + (t > now ? "in the future" : "ago");
  }

  std::string get_time_hms(time_t t)
  {
    unsigned int hours, minutes, seconds;
    char buffer[24];
    hours = t / 3600;
    t %= 3600;
    minutes = t / 60;
    t %= 60;
    seconds = t;
    snprintf(buffer, sizeof(buffer), "%02u:%02u:%02u", hours, minutes, seconds);
    return std::string(buffer);
  }

  std::string make_error(const std::string &base, const std::string &status)
  {
    if (status == CORE_RPC_STATUS_OK)
      return base;
    return base + " -- " + status;
  }
}

t_rpc_command_executor::t_rpc_command_executor(
    uint32_t ip
  , uint16_t port
  , const boost::optional<tools::login>& login
  , bool is_rpc
  , cryptonote::core_rpc_server* rpc_server
  )
  : m_rpc_client(NULL), m_rpc_server(rpc_server)
{
  if (is_rpc)
  {
    boost::optional<epee::net_utils::http::login> http_login{};
    if (login)
      http_login.emplace(login->username, login->password.password());
    m_rpc_client = new tools::t_rpc_client(ip, port, std::move(http_login));
  }
  else
  {
    if (rpc_server == NULL)
    {
      throw std::runtime_error("If not calling commands via RPC, rpc_server pointer must be non-null");
    }
  }

  m_is_rpc = is_rpc;
}

t_rpc_command_executor::~t_rpc_command_executor()
{
  if (m_rpc_client != NULL)
  {
    delete m_rpc_client;
  }
}

bool t_rpc_command_executor::print_peer_list() {
  cryptonote::COMMAND_RPC_GET_PEER_LIST::request req;
  cryptonote::COMMAND_RPC_GET_PEER_LIST::response res;

  std::string failure_message = "Couldn't retrieve peer list";
  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/get_peer_list", failure_message.c_str()))
    {
      return false;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_peer_list(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << failure_message;
      return false;
    }
  }

  for (auto & peer : res.white_list)
  {
    print_peer("white", peer);
  }

  for (auto & peer : res.gray_list)
  {
    print_peer("gray", peer);
  }

  return true;
}

bool t_rpc_command_executor::print_peer_list_stats() {
  cryptonote::COMMAND_RPC_GET_PEER_LIST::request req;
  cryptonote::COMMAND_RPC_GET_PEER_LIST::response res;

  std::string failure_message = "Couldn't retrieve peer list";
  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/get_peer_list", failure_message.c_str()))
    {
      return false;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_peer_list(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << failure_message;
      return false;
    }
  }

  tools::msg_writer()
    << "White list size: " << res.white_list.size() << "/" << P2P_LOCAL_WHITE_PEERLIST_LIMIT << " (" << res.white_list.size() *  100.0 / P2P_LOCAL_WHITE_PEERLIST_LIMIT << "%)" << std::endl
    << "Gray list size: " << res.gray_list.size() << "/" << P2P_LOCAL_GRAY_PEERLIST_LIMIT << " (" << res.gray_list.size() *  100.0 / P2P_LOCAL_GRAY_PEERLIST_LIMIT << "%)";

  return true;
}

bool t_rpc_command_executor::save_blockchain() {
  cryptonote::COMMAND_RPC_SAVE_BC::request req;
  cryptonote::COMMAND_RPC_SAVE_BC::response res;

  std::string fail_message = "Couldn't save blockchain";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/save_bc", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_save_bc(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::success_msg_writer() << "Blockchain saved";

  return true;
}

bool t_rpc_command_executor::show_hash_rate() {
  cryptonote::COMMAND_RPC_SET_LOG_HASH_RATE::request req;
  cryptonote::COMMAND_RPC_SET_LOG_HASH_RATE::response res;
  req.visible = true;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/set_log_hash_rate", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_set_log_hash_rate(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
    }
  }

  tools::success_msg_writer() << "Hash rate logging is on";

  return true;
}

bool t_rpc_command_executor::hide_hash_rate() {
  cryptonote::COMMAND_RPC_SET_LOG_HASH_RATE::request req;
  cryptonote::COMMAND_RPC_SET_LOG_HASH_RATE::response res;
  req.visible = false;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/set_log_hash_rate", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_set_log_hash_rate(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::success_msg_writer() << "Hash rate logging is off";

  return true;
}

bool t_rpc_command_executor::show_difficulty() {
  cryptonote::COMMAND_RPC_GET_INFO::request req;
  cryptonote::COMMAND_RPC_GET_INFO::response res;

  std::string fail_message = "Problem fetching info";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/getinfo", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_info(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message.c_str(), res.status);
      return true;
    }
  }

  tools::success_msg_writer() <<   "BH: " << res.height
                              << ", TH: " << res.top_block_hash
                              << ", DIFF: " << res.difficulty
                              << ", HR: " << res.difficulty / res.target << " H/s";

  return true;
}

static std::string get_mining_speed(uint64_t hr)
{
  if (hr>1e9) return (boost::format("%.2f GH/s") % (hr/1e9)).str();
  if (hr>1e6) return (boost::format("%.2f MH/s") % (hr/1e6)).str();
  if (hr>1e3) return (boost::format("%.2f kH/s") % (hr/1e3)).str();
  return (boost::format("%.0f H/s") % hr).str();
}

static std::string get_fork_extra_info(uint64_t t, uint64_t now, uint64_t block_time)
{
  uint64_t blocks_per_day = 86400 / block_time;

  if (t == now)
    return " (forking now)";

  if (t > now)
  {
    uint64_t dblocks = t - now;
    if (dblocks <= 30)
      return (boost::format(" (next fork in %u blocks)") % (unsigned)dblocks).str();
    if (dblocks <= blocks_per_day / 2)
      return (boost::format(" (next fork in %.1f hours)") % (dblocks / (float)(blocks_per_day / 24))).str();
    if (dblocks <= blocks_per_day * 30)
      return (boost::format(" (next fork in %.1f days)") % (dblocks / (float)blocks_per_day)).str();
    return "";
  }
  return "";
}

static float get_sync_percentage(uint64_t height, uint64_t target_height)
{
  target_height = target_height ? target_height < height ? height : target_height : height;
  float pc = 100.0f * height / target_height;
  if (height < target_height && pc > 99.9f)
    return 99.9f; // to avoid 100% when not fully synced
  return pc;
}
static float get_sync_percentage(const cryptonote::COMMAND_RPC_GET_INFO::response &ires)
{
  return get_sync_percentage(ires.height, ires.target_height);
}

bool t_rpc_command_executor::show_status() {
  cryptonote::COMMAND_RPC_GET_INFO::request ireq;
  cryptonote::COMMAND_RPC_GET_INFO::response ires;
  cryptonote::COMMAND_RPC_HARD_FORK_INFO::request hfreq;
  cryptonote::COMMAND_RPC_HARD_FORK_INFO::response hfres;
  cryptonote::COMMAND_RPC_MINING_STATUS::request mreq;
  cryptonote::COMMAND_RPC_MINING_STATUS::response mres;
  epee::json_rpc::error error_resp;
  bool has_mining_info = true;

  std::string fail_message = "Problem fetching info";

  hfreq.version = 0;
  bool mining_busy = false;
  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(ireq, ires, "/getinfo", fail_message.c_str()))
    {
      return true;
    }
    if (!m_rpc_client->json_rpc_request(hfreq, hfres, "hard_fork_info", fail_message.c_str()))
    {
      return true;
    }
    // mining info is only available non unrestricted RPC mode
    has_mining_info = m_rpc_client->rpc_request(mreq, mres, "/mining_status", fail_message.c_str());
  }
  else
  {
    if (!m_rpc_server->on_get_info(ireq, ires) || ires.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, ires.status);
      return true;
    }
    if (!m_rpc_server->on_hard_fork_info(hfreq, hfres, error_resp) || hfres.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, hfres.status);
      return true;
    }
    if (!m_rpc_server->on_mining_status(mreq, mres))
    {
      tools::fail_msg_writer() << fail_message.c_str();
      return true;
    }

    if (mres.status == CORE_RPC_STATUS_BUSY)
    {
      mining_busy = true;
    }
    else if (mres.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, mres.status);
      return true;
    }
  }

  std::time_t uptime = std::time(nullptr) - ires.start_time;
  uint64_t net_height = ires.target_height > ires.height ? ires.target_height : ires.height;
  std::string bootstrap_msg;
  if (ires.was_bootstrap_ever_used)
  {
    bootstrap_msg = ", bootstrapping from " + ires.bootstrap_daemon_address;
    if (ires.untrusted)
    {
      bootstrap_msg += (boost::format(", local height: %llu (%.1f%%)") % ires.height_without_bootstrap % get_sync_percentage(ires.height_without_bootstrap, net_height)).str();
    }
    else
    {
      bootstrap_msg += " was used before";
    }
  }

  std::stringstream str;
  str << boost::format("Height: %llu/%llu (%.1f%%) on %s%s, %s, net hash %s, v%u%s, %s, %u(out)+%u(in) connections")
    % (unsigned long long)ires.height
    % (unsigned long long)net_height
    % get_sync_percentage(ires)
    % (ires.testnet ? "testnet" : ires.stagenet ? "stagenet" : "mainnet")
    % bootstrap_msg
    % (!has_mining_info ? "mining info unavailable" : mining_busy ? "syncing" : mres.active ? ( ( mres.is_background_mining_enabled ? "smart " : "" ) + std::string("mining at ") + get_mining_speed(mres.speed) ) : "not mining")
    % get_mining_speed(ires.difficulty / ires.target)
    % (unsigned)hfres.version
    % get_fork_extra_info(hfres.earliest_height, net_height, ires.target)
    % (hfres.state == cryptonote::HardFork::Ready ? "up to date" : hfres.state == cryptonote::HardFork::UpdateNeeded ? "update needed" : "out of date, likely forked")
    % (unsigned)ires.outgoing_connections_count
    % (unsigned)ires.incoming_connections_count
  ;

  // restricted RPC does not disclose start time
  if (ires.start_time)
  {
    str << boost::format(", uptime %ud %uh %um %us")
      % (unsigned int)floor(uptime / 60.0 / 60.0 / 24.0)
      % (unsigned int)floor(fmod((uptime / 60.0 / 60.0), 24.0))
      % (unsigned int)floor(fmod((uptime / 60.0), 60.0))
      % (unsigned int)fmod(uptime, 60.0)
    ;
  }

  tools::success_msg_writer() << str.str();

  return true;
}

bool t_rpc_command_executor::print_connections() {
  cryptonote::COMMAND_RPC_GET_CONNECTIONS::request req;
  cryptonote::COMMAND_RPC_GET_CONNECTIONS::response res;
  epee::json_rpc::error error_resp;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->json_rpc_request(req, res, "get_connections", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_connections(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::msg_writer() << std::setw(30) << std::left << "Remote Host"
      << std::setw(20) << "Peer id"
      << std::setw(20) << "Support Flags"      
      << std::setw(30) << "Recv/Sent (inactive,sec)"
      << std::setw(25) << "State"
      << std::setw(20) << "Livetime(sec)"
      << std::setw(12) << "Down (kB/s)"
      << std::setw(14) << "Down(now)"
      << std::setw(10) << "Up (kB/s)" 
      << std::setw(13) << "Up(now)"
      << std::endl;

  for (auto & info : res.connections)
  {
    std::string address = info.incoming ? "INC " : "OUT ";
    address += info.ip + ":" + info.port;
    //std::string in_out = info.incoming ? "INC " : "OUT ";
    tools::msg_writer() 
     //<< std::setw(30) << std::left << in_out
     << std::setw(30) << std::left << address
     << std::setw(20) << epee::string_tools::pad_string(info.peer_id, 16, '0', true)
     << std::setw(20) << info.support_flags
     << std::setw(30) << std::to_string(info.recv_count) + "("  + std::to_string(info.recv_idle_time) + ")/" + std::to_string(info.send_count) + "(" + std::to_string(info.send_idle_time) + ")"
     << std::setw(25) << info.state
     << std::setw(20) << info.live_time
     << std::setw(12) << info.avg_download
     << std::setw(14) << info.current_download
     << std::setw(10) << info.avg_upload
     << std::setw(13) << info.current_upload
     
     << std::left << (info.localhost ? "[LOCALHOST]" : "")
     << std::left << (info.local_ip ? "[LAN]" : "");
    //tools::msg_writer() << boost::format("%-25s peer_id: %-25s %s") % address % info.peer_id % in_out;
    
  }

  return true;
}

bool t_rpc_command_executor::print_blockchain_info(uint64_t start_block_index, uint64_t end_block_index) {
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request req;
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response res;
  epee::json_rpc::error error_resp;

  req.start_height = start_block_index;
  req.end_height = end_block_index;
  req.fill_pow_hash = false;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->json_rpc_request(req, res, "getblockheadersrange", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_block_headers_range(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  bool first = true;
  for (auto & header : res.headers)
  {
    if (!first)
      std::cout << std::endl;
    std::cout
      << "height: " << header.height << ", timestamp: " << header.timestamp
      << ", size: " << header.block_size << ", weight: " << header.block_weight << ", transactions: " << header.num_txes << std::endl
      << "major version: " << (unsigned)header.major_version << ", minor version: " << (unsigned)header.minor_version << std::endl
      << "block id: " << header.hash << ", previous block id: " << header.prev_hash << std::endl
      << "difficulty: " << header.difficulty << ", nonce " << header.nonce << ", reward " << cryptonote::print_money(header.reward) << std::endl;
    first = false;
  }

  return true;
}

bool t_rpc_command_executor::set_log_level(int8_t level) {
  cryptonote::COMMAND_RPC_SET_LOG_LEVEL::request req;
  cryptonote::COMMAND_RPC_SET_LOG_LEVEL::response res;
  req.level = level;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/set_log_level", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_set_log_level(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::success_msg_writer() << "Log level is now " << std::to_string(level);

  return true;
}

bool t_rpc_command_executor::set_log_categories(const std::string &categories) {
  cryptonote::COMMAND_RPC_SET_LOG_CATEGORIES::request req;
  cryptonote::COMMAND_RPC_SET_LOG_CATEGORIES::response res;
  req.categories = categories;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/set_log_categories", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_set_log_categories(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::success_msg_writer() << "Log categories are now " << res.categories;

  return true;
}

bool t_rpc_command_executor::print_height() {
  cryptonote::COMMAND_RPC_GET_HEIGHT::request req;
  cryptonote::COMMAND_RPC_GET_HEIGHT::response res;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/getheight", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_height(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::success_msg_writer() << boost::lexical_cast<std::string>(res.height);

  return true;
}

bool t_rpc_command_executor::print_block_by_hash(crypto::hash block_hash) {
  cryptonote::COMMAND_RPC_GET_BLOCK::request req;
  cryptonote::COMMAND_RPC_GET_BLOCK::response res;
  epee::json_rpc::error error_resp;

  req.hash = epee::string_tools::pod_to_hex(block_hash);
  req.fill_pow_hash = true;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->json_rpc_request(req, res, "getblock", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_block(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  print_block_header(res.block_header);
  tools::success_msg_writer() << res.json << ENDL;

  return true;
}

bool t_rpc_command_executor::print_block_by_height(uint64_t height) {
  cryptonote::COMMAND_RPC_GET_BLOCK::request req;
  cryptonote::COMMAND_RPC_GET_BLOCK::response res;
  epee::json_rpc::error error_resp;

  req.height = height;
  req.fill_pow_hash = true;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->json_rpc_request(req, res, "getblock", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_block(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  print_block_header(res.block_header);
  tools::success_msg_writer() << res.json << ENDL;

  return true;
}

bool t_rpc_command_executor::print_transaction(crypto::hash transaction_hash,
  bool include_hex,
  bool include_json) {
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req;
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res;

  std::string fail_message = "Problem fetching transaction";

  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(transaction_hash));
  req.decode_as_json = false;
  req.prune = false;
  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/gettransactions", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_transactions(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  if (1 == res.txs.size() || 1 == res.txs_as_hex.size())
  {
    if (1 == res.txs.size())
    {
      // only available for new style answers
      if (res.txs.front().in_pool)
        tools::success_msg_writer() << "Found in pool";
      else
        tools::success_msg_writer() << "Found in blockchain at height " << res.txs.front().block_height;
    }

    const std::string &as_hex = (1 == res.txs.size()) ? res.txs.front().as_hex : res.txs_as_hex.front();
    // Print raw hex if requested
    if (include_hex)
      tools::success_msg_writer() << as_hex << std::endl;

    // Print json if requested
    if (include_json)
    {
      crypto::hash tx_hash, tx_prefix_hash;
      cryptonote::transaction tx;
      cryptonote::blobdata blob;
      if (!string_tools::parse_hexstr_to_binbuff(as_hex, blob))
      {
        tools::fail_msg_writer() << "Failed to parse tx to get json format";
      }
      else if (!cryptonote::parse_and_validate_tx_from_blob(blob, tx, tx_hash, tx_prefix_hash))
      {
        tools::fail_msg_writer() << "Failed to parse tx blob to get json format";
      }
      else
      {
        tools::success_msg_writer() << cryptonote::obj_to_json_str(tx) << std::endl;
      }
    }
  }
  else
  {
    tools::fail_msg_writer() << "Transaction wasn't found: " << transaction_hash << std::endl;
  }

  return true;
}

bool t_rpc_command_executor::is_key_image_spent(const crypto::key_image &ki) {
  cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::request req;
  cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::response res;

  std::string fail_message = "Problem checking key image";

  req.key_images.push_back(epee::string_tools::pod_to_hex(ki));
  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/is_key_image_spent", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_is_key_image_spent(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  if (1 == res.spent_status.size())
  {
    // first as hex
    tools::success_msg_writer() << ki << ": " << (res.spent_status.front() ? "spent" : "unspent") << (res.spent_status.front() == cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_POOL ? " (in pool)" : "");
  }
  else
  {
    tools::fail_msg_writer() << "key image status could not be determined" << std::endl;
  }

  return true;
}

bool t_rpc_command_executor::print_transaction_pool_long() {
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL::request req;
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL::response res;

  std::string fail_message = "Problem fetching transaction pool";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/get_transaction_pool", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_transaction_pool(req, res, false) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  if (res.transactions.empty() && res.spent_key_images.empty())
  {
    tools::msg_writer() << "Pool is empty" << std::endl;
  }
  if (! res.transactions.empty())
  {
    const time_t now = time(NULL);
    tools::msg_writer() << "Transactions: ";
    for (auto & tx_info : res.transactions)
    {
      tools::msg_writer() << "id: " << tx_info.id_hash << std::endl
                          << tx_info.tx_json << std::endl
                          << "blob_size: " << tx_info.blob_size << std::endl
                          << "weight: " << tx_info.weight << std::endl
                          << "fee: " << cryptonote::print_money(tx_info.fee) << std::endl
                          << "fee/byte: " << cryptonote::print_money(tx_info.fee / (double)tx_info.weight) << std::endl
                          << "receive_time: " << tx_info.receive_time << " (" << get_human_time_ago(tx_info.receive_time, now) << ")" << std::endl
                          << "relayed: " << [&](const cryptonote::tx_info &tx_info)->std::string { if (!tx_info.relayed) return "no"; return boost::lexical_cast<std::string>(tx_info.last_relayed_time) + " (" + get_human_time_ago(tx_info.last_relayed_time, now) + ")"; } (tx_info) << std::endl
                          << "do_not_relay: " << (tx_info.do_not_relay ? 'T' : 'F')  << std::endl
                          << "kept_by_block: " << (tx_info.kept_by_block ? 'T' : 'F') << std::endl
                          << "double_spend_seen: " << (tx_info.double_spend_seen ? 'T' : 'F')  << std::endl
                          << "max_used_block_height: " << tx_info.max_used_block_height << std::endl
                          << "max_used_block_id: " << tx_info.max_used_block_id_hash << std::endl
                          << "last_failed_height: " << tx_info.last_failed_height << std::endl
                          << "last_failed_id: " << tx_info.last_failed_id_hash << std::endl;
    }
    if (res.spent_key_images.empty())
    {
      tools::msg_writer() << "WARNING: Inconsistent pool state - no spent key images";
    }
  }
  if (! res.spent_key_images.empty())
  {
    tools::msg_writer() << ""; // one newline
    tools::msg_writer() << "Spent key images: ";
    for (const cryptonote::spent_key_image_info& kinfo : res.spent_key_images)
    {
      tools::msg_writer() << "key image: " << kinfo.id_hash;
      if (kinfo.txs_hashes.size() == 1)
      {
        tools::msg_writer() << "  tx: " << kinfo.txs_hashes[0];
      }
      else if (kinfo.txs_hashes.size() == 0)
      {
        tools::msg_writer() << "  WARNING: spent key image has no txs associated";
      }
      else
      {
        tools::msg_writer() << "  NOTE: key image for multiple txs: " << kinfo.txs_hashes.size();
        for (const std::string& tx_id : kinfo.txs_hashes)
        {
          tools::msg_writer() << "  tx: " << tx_id;
        }
      }
    }
    if (res.transactions.empty())
    {
      tools::msg_writer() << "WARNING: Inconsistent pool state - no transactions";
    }
  }

  return true;
}

bool t_rpc_command_executor::print_transaction_pool_short() {
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL::request req;
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL::response res;

  std::string fail_message = "Problem fetching transaction pool";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/get_transaction_pool", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_transaction_pool(req, res, false) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  if (res.transactions.empty())
  {
    tools::msg_writer() << "Pool is empty" << std::endl;
  }
  else
  {
    const time_t now = time(NULL);
    for (auto & tx_info : res.transactions)
    {
      tools::msg_writer() << "id: " << tx_info.id_hash << std::endl
                          << "blob_size: " << tx_info.blob_size << std::endl
                          << "weight: " << tx_info.weight << std::endl
                          << "fee: " << cryptonote::print_money(tx_info.fee) << std::endl
                          << "fee/byte: " << cryptonote::print_money(tx_info.fee / (double)tx_info.weight) << std::endl
                          << "receive_time: " << tx_info.receive_time << " (" << get_human_time_ago(tx_info.receive_time, now) << ")" << std::endl
                          << "relayed: " << [&](const cryptonote::tx_info &tx_info)->std::string { if (!tx_info.relayed) return "no"; return boost::lexical_cast<std::string>(tx_info.last_relayed_time) + " (" + get_human_time_ago(tx_info.last_relayed_time, now) + ")"; } (tx_info) << std::endl
                          << "do_not_relay: " << (tx_info.do_not_relay ? 'T' : 'F')  << std::endl
                          << "kept_by_block: " << (tx_info.kept_by_block ? 'T' : 'F') << std::endl
                          << "double_spend_seen: " << (tx_info.double_spend_seen ? 'T' : 'F') << std::endl
                          << "max_used_block_height: " << tx_info.max_used_block_height << std::endl
                          << "max_used_block_id: " << tx_info.max_used_block_id_hash << std::endl
                          << "last_failed_height: " << tx_info.last_failed_height << std::endl
                          << "last_failed_id: " << tx_info.last_failed_id_hash << std::endl;
    }
  }

  return true;
}

bool t_rpc_command_executor::print_transaction_pool_stats() {
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_STATS::request req;
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_STATS::response res;
  cryptonote::COMMAND_RPC_GET_INFO::request ireq;
  cryptonote::COMMAND_RPC_GET_INFO::response ires;

  std::string fail_message = "Problem fetching transaction pool stats";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/get_transaction_pool_stats", fail_message.c_str()))
    {
      return true;
    }
    if (!m_rpc_client->rpc_request(ireq, ires, "/getinfo", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    res.pool_stats = {};
    if (!m_rpc_server->on_get_transaction_pool_stats(req, res, false) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
    if (!m_rpc_server->on_get_info(ireq, ires) || ires.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, ires.status);
      return true;
    }
  }

  size_t n_transactions = res.pool_stats.txs_total;
  const uint64_t now = time(NULL);
  size_t avg_bytes = n_transactions ? res.pool_stats.bytes_total / n_transactions : 0;

  std::string backlog_message;
  const uint64_t full_reward_zone = ires.block_weight_limit / 2;
  if (res.pool_stats.bytes_total <= full_reward_zone)
  {
    backlog_message = "no backlog";
  }
  else
  {
    uint64_t backlog = (res.pool_stats.bytes_total + full_reward_zone - 1) / full_reward_zone;
    backlog_message = ires.height >= HF_BLOCK_HEIGHT_PROOF_OF_STAKE ? (boost::format("estimated %u block (%u minutes) backlog") % backlog % (backlog * DIFFICULTY_TARGET_V13 / 60)).str() : ires.height >= HF_BLOCK_HEIGHT_TWO_MINUTE_BLOCK_TIME ? (boost::format("estimated %u block (%u minutes) backlog") % backlog % (backlog * DIFFICULTY_TARGET_V12 / 60)).str() : (boost::format("estimated %u block (%u minutes) backlog") % backlog % (backlog * DIFFICULTY_TARGET_V2 / 60)).str();
  }

  tools::msg_writer() << n_transactions << " tx(es), " << res.pool_stats.bytes_total << " bytes total (min " << res.pool_stats.bytes_min << ", max " << res.pool_stats.bytes_max << ", avg " << avg_bytes << ", median " << res.pool_stats.bytes_med << ")" << std::endl
      << "fees " << cryptonote::print_money(res.pool_stats.fee_total) << " (avg " << cryptonote::print_money(n_transactions ? res.pool_stats.fee_total / n_transactions : 0) << " per tx" << ", " << cryptonote::print_money(res.pool_stats.bytes_total ? res.pool_stats.fee_total / res.pool_stats.bytes_total : 0) << " per byte)" << std::endl
      << res.pool_stats.num_double_spends << " double spends, " << res.pool_stats.num_not_relayed << " not relayed, " << res.pool_stats.num_failing << " failing, " << res.pool_stats.num_10m << " older than 10 minutes (oldest " << (res.pool_stats.oldest == 0 ? "-" : get_human_time_ago(res.pool_stats.oldest, now)) << "), " << backlog_message;

  if (n_transactions > 1 && res.pool_stats.histo.size())
  {
    std::vector<uint64_t> times;
    uint64_t numer;
    size_t i, n = res.pool_stats.histo.size(), denom;
    times.resize(n);
    if (res.pool_stats.histo_98pc)
    {
      numer = res.pool_stats.histo_98pc;
      denom = n-1;
      for (i=0; i<denom; i++)
        times[i] = i * numer / denom;
      times[i] = now - res.pool_stats.oldest;
    } else
    {
      numer = now - res.pool_stats.oldest;
      denom = n;
      for (i=0; i<denom; i++)
        times[i] = i * numer / denom;
    }
    tools::msg_writer() << "   Age      Txes       Bytes";
    for (i=0; i<n; i++)
    {
      tools::msg_writer() << get_time_hms(times[i]) << std::setw(8) << res.pool_stats.histo[i].txs << std::setw(12) << res.pool_stats.histo[i].bytes;
    }
  }
  tools::msg_writer();

  return true;
}

bool t_rpc_command_executor::start_mining(cryptonote::account_public_address address, uint64_t num_threads, cryptonote::network_type nettype, bool do_background_mining, bool ignore_battery) {
  cryptonote::COMMAND_RPC_START_MINING::request req;
  cryptonote::COMMAND_RPC_START_MINING::response res;
  req.miner_address = cryptonote::get_account_address_as_str(nettype, false, address);
  req.threads_count = num_threads;
  req.do_background_mining = do_background_mining;
  req.ignore_battery = ignore_battery;
  
  std::string fail_message = "Mining did not start";

  if (m_is_rpc)
  {
    if (m_rpc_client->rpc_request(req, res, "/start_mining", fail_message.c_str()))
    {
      tools::success_msg_writer() << "Mining started";
    }
  }
  else
  {
    if (!m_rpc_server->on_start_mining(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  return true;
}

bool t_rpc_command_executor::stop_mining() {
  cryptonote::COMMAND_RPC_STOP_MINING::request req;
  cryptonote::COMMAND_RPC_STOP_MINING::response res;

  std::string fail_message = "Mining did not stop";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/stop_mining", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_stop_mining(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::success_msg_writer() << "Mining stopped";
  return true;
}

bool t_rpc_command_executor::stop_daemon()
{
  cryptonote::COMMAND_RPC_STOP_DAEMON::request req;
  cryptonote::COMMAND_RPC_STOP_DAEMON::response res;

//# ifdef WIN32
//    // Stop via service API
//    // TODO - this is only temporary!  Get rid of hard-coded constants!
//    bool ok = windows::stop_service("BitX-CASH Daemon");
//    ok = windows::uninstall_service("BitX-CASH Daemon");
//    //bool ok = windows::stop_service(SERVICE_NAME);
//    //ok = windows::uninstall_service(SERVICE_NAME);
//    if (ok)
//    {
//      return true;
//    }
//# endif

  // Stop via RPC
  std::string fail_message = "Daemon did not stop";

  if (m_is_rpc)
  {
    if(!m_rpc_client->rpc_request(req, res, "/stop_daemon", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_stop_daemon(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::success_msg_writer() << "Stop signal sent";

  return true;
}

bool t_rpc_command_executor::print_status()
{
  if (!m_is_rpc)
  {
    tools::success_msg_writer() << "print_status makes no sense in interactive mode";
    return true;
  }

  bool daemon_is_alive = m_rpc_client->check_connection();

  if(daemon_is_alive) {
    tools::success_msg_writer() << "xcashd is running";
  }
  else {
    tools::fail_msg_writer() << "xcashd is NOT running";
  }

  return true;
}

bool t_rpc_command_executor::get_limit()
{
  cryptonote::COMMAND_RPC_GET_LIMIT::request req;
  cryptonote::COMMAND_RPC_GET_LIMIT::response res;

  std::string failure_message = "Couldn't get limit";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/get_limit", failure_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_limit(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(failure_message, res.status);
      return true;
    }
  }

  tools::msg_writer() << "limit-down is " << res.limit_down << " kB/s";
  tools::msg_writer() << "limit-up is " << res.limit_up << " kB/s";
  return true;
}

bool t_rpc_command_executor::set_limit(int64_t limit_down, int64_t limit_up)
{
  cryptonote::COMMAND_RPC_SET_LIMIT::request req;
  cryptonote::COMMAND_RPC_SET_LIMIT::response res;

  req.limit_down = limit_down;
  req.limit_up = limit_up;

  std::string failure_message = "Couldn't set limit";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/set_limit", failure_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_set_limit(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(failure_message, res.status);
      return true;
    }
  }

  tools::msg_writer() << "Set limit-down to " << res.limit_down << " kB/s";
  tools::msg_writer() << "Set limit-up to " << res.limit_up << " kB/s";
  return true;
}

bool t_rpc_command_executor::get_limit_up()
{
  cryptonote::COMMAND_RPC_GET_LIMIT::request req;
  cryptonote::COMMAND_RPC_GET_LIMIT::response res;

  std::string failure_message = "Couldn't get limit";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/get_limit", failure_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_limit(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(failure_message, res.status);
      return true;
    }
  }

  tools::msg_writer() << "limit-up is " << res.limit_up << " kB/s";
  return true;
}

bool t_rpc_command_executor::get_limit_down()
{
  cryptonote::COMMAND_RPC_GET_LIMIT::request req;
  cryptonote::COMMAND_RPC_GET_LIMIT::response res;

  std::string failure_message = "Couldn't get limit";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/get_limit", failure_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_limit(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(failure_message, res.status);
      return true;
    }
  }

  tools::msg_writer() << "limit-down is " << res.limit_down << " kB/s";
  return true;
}

bool t_rpc_command_executor::out_peers(uint64_t limit)
{
	cryptonote::COMMAND_RPC_OUT_PEERS::request req;
	cryptonote::COMMAND_RPC_OUT_PEERS::response res;
	
	epee::json_rpc::error error_resp;

	req.out_peers = limit;
	
	std::string fail_message = "Unsuccessful";

	if (m_is_rpc)
	{
		if (!m_rpc_client->rpc_request(req, res, "/out_peers", fail_message.c_str()))
		{
			return true;
		}
	}
	else
	{
		if (!m_rpc_server->on_out_peers(req, res) || res.status != CORE_RPC_STATUS_OK)
		{
			tools::fail_msg_writer() << make_error(fail_message, res.status);
			return true;
		}
	}

	std::cout << "Max number of out peers set to " << limit << std::endl;

	return true;
}

bool t_rpc_command_executor::in_peers(uint64_t limit)
{
	cryptonote::COMMAND_RPC_IN_PEERS::request req;
	cryptonote::COMMAND_RPC_IN_PEERS::response res;

	epee::json_rpc::error error_resp;

	req.in_peers = limit;

	std::string fail_message = "Unsuccessful";

	if (m_is_rpc)
	{
		if (!m_rpc_client->rpc_request(req, res, "/in_peers", fail_message.c_str()))
		{
			return true;
		}
	}
	else
	{
		if (!m_rpc_server->on_in_peers(req, res) || res.status != CORE_RPC_STATUS_OK)
		{
			tools::fail_msg_writer() << make_error(fail_message, res.status);
			return true;
		}
	}

	std::cout << "Max number of in peers set to " << limit << std::endl;

	return true;
}

bool t_rpc_command_executor::start_save_graph()
{
	cryptonote::COMMAND_RPC_START_SAVE_GRAPH::request req;
	cryptonote::COMMAND_RPC_START_SAVE_GRAPH::response res;
	std::string fail_message = "Unsuccessful";
	
	if (m_is_rpc)
	{
		if (!m_rpc_client->rpc_request(req, res, "/start_save_graph", fail_message.c_str()))
		{
			return true;
		}
	}
	
	else
    {
		if (!m_rpc_server->on_start_save_graph(req, res) || res.status != CORE_RPC_STATUS_OK)
		{
			tools::fail_msg_writer() << make_error(fail_message, res.status);
			return true;
		}
	}
	
	tools::success_msg_writer() << "Saving graph is now on";
	return true;
}

bool t_rpc_command_executor::stop_save_graph()
{
	cryptonote::COMMAND_RPC_STOP_SAVE_GRAPH::request req;
	cryptonote::COMMAND_RPC_STOP_SAVE_GRAPH::response res;
	std::string fail_message = "Unsuccessful";
	
	if (m_is_rpc)
	{
		if (!m_rpc_client->rpc_request(req, res, "/stop_save_graph", fail_message.c_str()))
		{
			return true;
		}
	}
	
	else
    {
		if (!m_rpc_server->on_stop_save_graph(req, res) || res.status != CORE_RPC_STATUS_OK)
		{
			tools::fail_msg_writer() << make_error(fail_message, res.status);
			return true;
		}
	}
	tools::success_msg_writer() << "Saving graph is now off";
	return true;
}

bool t_rpc_command_executor::hard_fork_info(uint8_t version)
{
    cryptonote::COMMAND_RPC_HARD_FORK_INFO::request req;
    cryptonote::COMMAND_RPC_HARD_FORK_INFO::response res;
    std::string fail_message = "Unsuccessful";
    epee::json_rpc::error error_resp;

    req.version = version;

    if (m_is_rpc)
    {
        if (!m_rpc_client->json_rpc_request(req, res, "hard_fork_info", fail_message.c_str()))
        {
            return true;
        }
    }
    else
    {
        if (!m_rpc_server->on_hard_fork_info(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
        {
            tools::fail_msg_writer() << make_error(fail_message, res.status);
            return true;
        }
    }

    version = version > 0 ? version : res.voting;
    tools::msg_writer() << "version " << (uint32_t)version << " " << (res.enabled ? "enabled" : "not enabled") <<
        ", " << res.votes << "/" << res.window << " votes, threshold " << res.threshold;
    tools::msg_writer() << "current version " << (uint32_t)res.version << ", voting for version " << (uint32_t)res.voting;

    return true;
}

bool t_rpc_command_executor::print_bans()
{
    cryptonote::COMMAND_RPC_GETBANS::request req;
    cryptonote::COMMAND_RPC_GETBANS::response res;
    std::string fail_message = "Unsuccessful";
    epee::json_rpc::error error_resp;

    if (m_is_rpc)
    {
        if (!m_rpc_client->json_rpc_request(req, res, "get_bans", fail_message.c_str()))
        {
            return true;
        }
    }
    else
    {
        if (!m_rpc_server->on_get_bans(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
        {
            tools::fail_msg_writer() << make_error(fail_message, res.status);
            return true;
        }
    }

    for (auto i = res.bans.begin(); i != res.bans.end(); ++i)
    {
        tools::msg_writer() << epee::string_tools::get_ip_string_from_int32(i->ip) << " banned for " << i->seconds << " seconds";
    }

    return true;
}


bool t_rpc_command_executor::ban(const std::string &ip, time_t seconds)
{
    cryptonote::COMMAND_RPC_SETBANS::request req;
    cryptonote::COMMAND_RPC_SETBANS::response res;
    std::string fail_message = "Unsuccessful";
    epee::json_rpc::error error_resp;

    cryptonote::COMMAND_RPC_SETBANS::ban ban;
    if (!epee::string_tools::get_ip_int32_from_string(ban.ip, ip))
    {
        tools::fail_msg_writer() << "Invalid IP";
        return true;
    }
    ban.ban = true;
    ban.seconds = seconds;
    req.bans.push_back(ban);

    if (m_is_rpc)
    {
        if (!m_rpc_client->json_rpc_request(req, res, "set_bans", fail_message.c_str()))
        {
            return true;
        }
    }
    else
    {
        if (!m_rpc_server->on_set_bans(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
        {
            tools::fail_msg_writer() << make_error(fail_message, res.status);
            return true;
        }
    }

    return true;
}

bool t_rpc_command_executor::unban(const std::string &ip)
{
    cryptonote::COMMAND_RPC_SETBANS::request req;
    cryptonote::COMMAND_RPC_SETBANS::response res;
    std::string fail_message = "Unsuccessful";
    epee::json_rpc::error error_resp;

    cryptonote::COMMAND_RPC_SETBANS::ban ban;
    if (!epee::string_tools::get_ip_int32_from_string(ban.ip, ip))
    {
        tools::fail_msg_writer() << "Invalid IP";
        return true;
    }
    ban.ban = false;
    ban.seconds = 0;
    req.bans.push_back(ban);

    if (m_is_rpc)
    {
        if (!m_rpc_client->json_rpc_request(req, res, "set_bans", fail_message.c_str()))
        {
            return true;
        }
    }
    else
    {
        if (!m_rpc_server->on_set_bans(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
        {
            tools::fail_msg_writer() << make_error(fail_message, res.status);
            return true;
        }
    }

    return true;
}

bool t_rpc_command_executor::flush_txpool(const std::string &txid)
{
    cryptonote::COMMAND_RPC_FLUSH_TRANSACTION_POOL::request req;
    cryptonote::COMMAND_RPC_FLUSH_TRANSACTION_POOL::response res;
    std::string fail_message = "Unsuccessful";
    epee::json_rpc::error error_resp;

    if (!txid.empty())
      req.txids.push_back(txid);

    if (m_is_rpc)
    {
        if (!m_rpc_client->json_rpc_request(req, res, "flush_txpool", fail_message.c_str()))
        {
            return true;
        }
    }
    else
    {
        if (!m_rpc_server->on_flush_txpool(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
        {
            tools::fail_msg_writer() << make_error(fail_message, res.status);
            return true;
        }
    }

    tools::success_msg_writer() << "Pool successfully flushed";
    return true;
}

bool t_rpc_command_executor::output_histogram(const std::vector<uint64_t> &amounts, uint64_t min_count, uint64_t max_count)
{
    cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request req;
    cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response res;
    std::string fail_message = "Unsuccessful";
    epee::json_rpc::error error_resp;

    req.amounts = amounts;
    req.min_count = min_count;
    req.max_count = max_count;
    req.unlocked = false;
    req.recent_cutoff = 0;

    if (m_is_rpc)
    {
        if (!m_rpc_client->json_rpc_request(req, res, "get_output_histogram", fail_message.c_str()))
        {
            return true;
        }
    }
    else
    {
        if (!m_rpc_server->on_get_output_histogram(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
        {
            tools::fail_msg_writer() << make_error(fail_message, res.status);
            return true;
        }
    }

    std::sort(res.histogram.begin(), res.histogram.end(),
        [](const cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::entry &e1, const cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::entry &e2)->bool { return e1.total_instances < e2.total_instances; });
    for (const auto &e: res.histogram)
    {
        tools::msg_writer() << e.total_instances << "  " << cryptonote::print_money(e.amount);
    }

    return true;
}

bool t_rpc_command_executor::print_coinbase_tx_sum(uint64_t height, uint64_t count)
{
  cryptonote::COMMAND_RPC_GET_COINBASE_TX_SUM::request req;
  cryptonote::COMMAND_RPC_GET_COINBASE_TX_SUM::response res;
  epee::json_rpc::error error_resp;

  req.height = height;
  req.count = count;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->json_rpc_request(req, res, "get_coinbase_tx_sum", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_coinbase_tx_sum(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  tools::msg_writer() << "Sum of coinbase transactions between block heights ["
    << height << ", " << (height + count) << ") is "
    << cryptonote::print_money(res.emission_amount + res.fee_amount) << " "
    << "consisting of " << cryptonote::print_money(res.emission_amount) 
    << " in emissions, and " << cryptonote::print_money(res.fee_amount) << " in fees";
  return true;
}

bool t_rpc_command_executor::alt_chain_info(const std::string &tip)
{
  cryptonote::COMMAND_RPC_GET_INFO::request ireq;
  cryptonote::COMMAND_RPC_GET_INFO::response ires;
  cryptonote::COMMAND_RPC_GET_ALTERNATE_CHAINS::request req;
  cryptonote::COMMAND_RPC_GET_ALTERNATE_CHAINS::response res;
  epee::json_rpc::error error_resp;

  std::string fail_message = "Unsuccessful";

  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(ireq, ires, "/getinfo", fail_message.c_str()))
    {
      return true;
    }
    if (!m_rpc_client->json_rpc_request(req, res, "get_alternate_chains", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_info(ireq, ires) || ires.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, ires.status);
      return true;
    }
    if (!m_rpc_server->on_get_alternate_chains(req, res, error_resp))
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  if (tip.empty())
  {
    tools::msg_writer() << boost::lexical_cast<std::string>(res.chains.size()) << " alternate chains found:";
    for (const auto &chain: res.chains)
    {
      uint64_t start_height = (chain.height - chain.length + 1);
      tools::msg_writer() << chain.length << " blocks long, from height " << start_height << " (" << (ires.height - start_height - 1)
          << " deep), diff " << chain.difficulty << ": " << chain.block_hash;
    }
  }
  else
  {
    const auto i = std::find_if(res.chains.begin(), res.chains.end(), [&tip](cryptonote::COMMAND_RPC_GET_ALTERNATE_CHAINS::chain_info &info){ return info.block_hash == tip; });
    if (i != res.chains.end())
    {
      const auto &chain = *i;
      tools::success_msg_writer() << "Found alternate chain with tip " << tip;
      uint64_t start_height = (chain.height - chain.length + 1);
      tools::msg_writer() << chain.length << " blocks long, from height " << start_height << " (" << (ires.height - start_height - 1)
          << " deep), diff " << chain.difficulty << ":";
      for (const std::string &block_id: chain.block_hashes)
        tools::msg_writer() << "  " << block_id;
      tools::msg_writer() << "Chain parent on main chain: " << chain.main_chain_parent_block;
    }
    else
      tools::fail_msg_writer() << "Block hash " << tip << " is not the tip of any known alternate chain";
  }
  return true;
}

bool t_rpc_command_executor::print_blockchain_dynamic_stats(uint64_t nblocks)
{
  cryptonote::COMMAND_RPC_GET_INFO::request ireq;
  cryptonote::COMMAND_RPC_GET_INFO::response ires;
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request bhreq;
  cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response bhres;
  cryptonote::COMMAND_RPC_GET_BASE_FEE_ESTIMATE::request fereq;
  cryptonote::COMMAND_RPC_GET_BASE_FEE_ESTIMATE::response feres;
  epee::json_rpc::error error_resp;

  std::string fail_message = "Problem fetching info";

  fereq.grace_blocks = 0;
  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(ireq, ires, "/getinfo", fail_message.c_str()))
    {
      return true;
    }
    if (!m_rpc_client->json_rpc_request(fereq, feres, "get_fee_estimate", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_info(ireq, ires) || ires.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, ires.status);
      return true;
    }
    if (!m_rpc_server->on_get_base_fee_estimate(fereq, feres, error_resp) || feres.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, feres.status);
      return true;
    }
  }

  tools::msg_writer() << "Height: " << ires.height << ", diff " << ires.difficulty << ", cum. diff " << ires.cumulative_difficulty
      << ", target " << ires.target << " sec" << ", dyn fee " << cryptonote::print_money(feres.fee) << "/kB";

  if (nblocks > 0)
  {
    if (nblocks > ires.height)
      nblocks = ires.height;

    bhreq.start_height = ires.height - nblocks;
    bhreq.end_height = ires.height - 1;
    bhreq.fill_pow_hash = false;
    if (m_is_rpc)
    {
      if (!m_rpc_client->json_rpc_request(bhreq, bhres, "getblockheadersrange", fail_message.c_str()))
      {
        return true;
      }
    }
    else
    {
      if (!m_rpc_server->on_get_block_headers_range(bhreq, bhres, error_resp) || bhres.status != CORE_RPC_STATUS_OK)
      {
        tools::fail_msg_writer() << make_error(fail_message, bhres.status);
        return true;
      }
    }

    double avgdiff = 0;
    double avgnumtxes = 0;
    double avgreward = 0;
    std::vector<uint64_t> weights;
    weights.reserve(nblocks);
    uint64_t earliest = std::numeric_limits<uint64_t>::max(), latest = 0;
    std::vector<unsigned> major_versions(256, 0), minor_versions(256, 0);
    for (const auto &bhr: bhres.headers)
    {
      avgdiff += bhr.difficulty;
      avgnumtxes += bhr.num_txes;
      avgreward += bhr.reward;
      weights.push_back(bhr.block_weight);
      static_assert(sizeof(bhr.major_version) == 1, "major_version expected to be uint8_t");
      static_assert(sizeof(bhr.minor_version) == 1, "major_version expected to be uint8_t");
      major_versions[(unsigned)bhr.major_version]++;
      minor_versions[(unsigned)bhr.minor_version]++;
      earliest = std::min(earliest, bhr.timestamp);
      latest = std::max(latest, bhr.timestamp);
    }
    avgdiff /= nblocks;
    avgnumtxes /= nblocks;
    avgreward /= nblocks;
    uint64_t median_block_weight = epee::misc_utils::median(weights);
    tools::msg_writer() << "Last " << nblocks << ": avg. diff " << (uint64_t)avgdiff << ", " << (latest - earliest) / nblocks << " avg sec/block, avg num txes " << avgnumtxes
        << ", avg. reward " << cryptonote::print_money(avgreward) << ", median block weight " << median_block_weight;

    unsigned int max_major = 256, max_minor = 256;
    while (max_major > 0 && !major_versions[--max_major]);
    while (max_minor > 0 && !minor_versions[--max_minor]);
    std::string s = "";
    for (unsigned n = 0; n <= max_major; ++n)
      if (major_versions[n])
        s += (s.empty() ? "" : ", ") + boost::lexical_cast<std::string>(major_versions[n]) + std::string(" v") + boost::lexical_cast<std::string>(n);
    tools::msg_writer() << "Block versions: " << s;
    s = "";
    for (unsigned n = 0; n <= max_minor; ++n)
      if (minor_versions[n])
        s += (s.empty() ? "" : ", ") + boost::lexical_cast<std::string>(minor_versions[n]) + std::string(" v") + boost::lexical_cast<std::string>(n);
    tools::msg_writer() << "Voting for: " << s;
  }
  return true;
}

bool t_rpc_command_executor::update(const std::string &command)
{
  cryptonote::COMMAND_RPC_UPDATE::request req;
  cryptonote::COMMAND_RPC_UPDATE::response res;
  epee::json_rpc::error error_resp;

  std::string fail_message = "Problem fetching info";

  req.command = command;
  if (m_is_rpc)
  {
    if (!m_rpc_client->rpc_request(req, res, "/update", fail_message.c_str()))
    {
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_update(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      tools::fail_msg_writer() << make_error(fail_message, res.status);
      return true;
    }
  }

  if (!res.update)
  {
    tools::msg_writer() << "No update available";
    return true;
  }

  tools::msg_writer() << "Update available: v" << res.version << ": " << res.user_uri << ", hash " << res.hash;
  if (command == "check")
    return true;

  if (!res.path.empty())
    tools::msg_writer() << "Update downloaded to: " << res.path;
  else
    tools::msg_writer() << "Update download failed: " << res.status;
  if (command == "download")
    return true;

  tools::msg_writer() << "'update' not implemented yet";

  return true;
}

bool t_rpc_command_executor::relay_tx(const std::string &txid)
{
    cryptonote::COMMAND_RPC_RELAY_TX::request req;
    cryptonote::COMMAND_RPC_RELAY_TX::response res;
    std::string fail_message = "Unsuccessful";
    epee::json_rpc::error error_resp;

    req.txids.push_back(txid);

    if (m_is_rpc)
    {
        if (!m_rpc_client->json_rpc_request(req, res, "relay_tx", fail_message.c_str()))
        {
            return true;
        }
    }
    else
    {
        if (!m_rpc_server->on_relay_tx(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
        {
            tools::fail_msg_writer() << make_error(fail_message, res.status);
            return true;
        }
    }

    tools::success_msg_writer() << "Transaction successfully relayed";
    return true;
}

bool t_rpc_command_executor::sync_info()
{
    cryptonote::COMMAND_RPC_SYNC_INFO::request req;
    cryptonote::COMMAND_RPC_SYNC_INFO::response res;
    std::string fail_message = "Unsuccessful";
    epee::json_rpc::error error_resp;

    if (m_is_rpc)
    {
        if (!m_rpc_client->json_rpc_request(req, res, "sync_info", fail_message.c_str()))
        {
            return true;
        }
    }
    else
    {
        if (!m_rpc_server->on_sync_info(req, res, error_resp) || res.status != CORE_RPC_STATUS_OK)
        {
            tools::fail_msg_writer() << make_error(fail_message, res.status);
            return true;
        }
    }

    uint64_t target = res.target_height < res.height ? res.height : res.target_height;
    tools::success_msg_writer() << "Height: " << res.height << ", target: " << target << " (" << (100.0 * res.height / target) << "%)";
    uint64_t current_download = 0;
    for (const auto &p: res.peers)
      current_download += p.info.current_download;
    tools::success_msg_writer() << "Downloading at " << current_download << " kB/s";

    tools::success_msg_writer() << std::to_string(res.peers.size()) << " peers";
    for (const auto &p: res.peers)
    {
      std::string address = epee::string_tools::pad_string(p.info.address, 24);
      uint64_t nblocks = 0, size = 0;
      for (const auto &s: res.spans)
        if (s.rate > 0.0f && s.connection_id == p.info.connection_id)
          nblocks += s.nblocks, size += s.size;
      tools::success_msg_writer() << address << "  " << epee::string_tools::pad_string(p.info.peer_id, 16, '0', true) << "  " << epee::string_tools::pad_string(p.info.state, 16) << "  " << p.info.height << "  "  << p.info.current_download << " kB/s, " << nblocks << " blocks / " << size/1e6 << " MB queued";
    }

    uint64_t total_size = 0;
    for (const auto &s: res.spans)
      total_size += s.size;
    tools::success_msg_writer() << std::to_string(res.spans.size()) << " spans, " << total_size/1e6 << " MB";
    for (const auto &s: res.spans)
    {
      std::string address = epee::string_tools::pad_string(s.remote_address, 24);
      if (s.size == 0)
      {
        tools::success_msg_writer() << address << "  " << s.nblocks << " (" << s.start_block_height << " - " << (s.start_block_height + s.nblocks - 1) << ")  -";
      }
      else
      {
        tools::success_msg_writer() << address << "  " << s.nblocks << " (" << s.start_block_height << " - " << (s.start_block_height + s.nblocks - 1) << ", " << (uint64_t)(s.size/1e3) << " kB)  " << (unsigned)(s.rate/1e3) << " kB/s (" << s.speed/100.0f << ")";
      }
    }

    return true;
}

// define macros

#define TEST_OUTLINE "-----------------------------------------------------------------------------------------------"
#define NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST "{\r\n \"message_settings\": \"NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST\",\r\n}"
#define NODES_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE "{\r\n \"message_settings\": \"NODES_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE\",\r\n}"

// Blockchain
#define UNLOCK_BLOCK_AMOUNT 60 // The default unlock block amount for a block reward transaction
#define MAXIMUM_TRANSACATIONS_PER_BLOCK 1000000 // The maximum amount of transaction per block

// network block string
#define BLOCK_PRODUCER_NETWORK_BLOCK_NONCE "00000000" // the network block nonce used when the block producer creates the block
#define CONSENSUS_NODE_NETWORK_BLOCK_NONCE "11111111" // the network block nonce used when the consensus node creates the block
#define NETWORK_VERSION "0d0d" // the network version
#define TIMESTAMP_LENGTH 10 /// The length of the timestamp
#define BLOCK_HASH_LENGTH 64 /// The length of the block hash
#define STEALTH_ADDRESS_OUTPUT_LENGTH 64 /// The length of the stealth address output
#define TRANSACTION_PUBLIC_KEY_LENGTH 66 /// The length of the transaction public key
#define TRANSACTION_LENGTH 64 /// The length of a transaction
#define BLOCK_REWARD_TRANSACTION_VERSION "02"
#define BLOCK_REWARD_INPUT "01"
#define VIN_TYPE "ff"
#define BLOCK_REWARD_OUTPUT "01"
#define STEALTH_ADDRESS_OUTPUT_TAG "02"
#define TRANSACTION_PUBLIC_KEY_TAG "01"
#define EXTRA_NONCE_TAG "02"
#define RINGCT_VERSION "00"
#define BLOCKCHAIN_RESERVED_BYTES_START "7c424c4f434b434841494e5f52455345525645445f42595445535f53544152547c"
#define BLOCKCHAIN_RESERVED_BYTES_DATA_HASH "02800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // the reserve bytes data hash
#define BLOCKCHAIN_DATA_SEGMENT_STRING "7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c"
#define BLOCKCHAIN_DATA_SEGMENT_SIGN_DATA_STRING "7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631"
#define BLOCKCHAIN_RESERVED_BYTES_END "7c424c4f434b434841494e5f52455345525645445f42595445535f454e447c"
#define BLOCKCHAIN_RESERVED_BYTES_START_DATA "424c4f434b434841494e5f52455345525645445f42595445535f5354415254"
#define BLOCKCHAIN_RESERVED_BYTES_END_DATA "424c4f434b434841494e5f52455345525645445f42595445535f454e44"
#define GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // The place holder bytes for a block verifier that does not create a VRF secret key, for the VRF secret key data
#define GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY "0000000000000000000000000000000000000000000000000000000000000000" // The place holder bytes for a block verifier that does not create a VRF secret key
#define GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA "0000000000000000000000000000000000000000000000000000000000000000" // The place holder bytes for a block verifier that does not create a VRF public key, for the VRF public key data
#define GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY "00000000000000000000000000000000" // The place holder bytes for a block verifier that does not create a VRF public key
#define GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING_DATA "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // The place holder bytes for a block verifier that does not create a random string, for the random string data
#define GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // The place holder bytes for a block verifier that does not create a random string
#define GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE_DATA "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // The place holder bytes for a block verifier that does not create a block verifier signature, for the block verifier signature data
#define GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // The place holder bytes for a block verifier that does not create a block verifier signature

// lengths
#define BUFFER_SIZE 164000
#define BUFFER_SIZE_RESERVE_PROOF 10000
#define BUFFER_SIZE_NETWORK_BLOCK_DATA 500
#define BUFFER_SIZE_NETWORK_BLOCK_TRANSACTIONS_DATA 100
#define MAXIMUM_BUFFER_SIZE 52428800 // 50 MB

#define RANDOM_STRING_LENGTH 100 // The length of the random string
#define DATA_HASH_LENGTH 128 // The length of the SHA2-512 hash
#define BITS_IN_BYTE 8 // 8 bits in 1 byte
#define BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH 100 // The maximum length of the block verifiers IP address
#define BLOCK_VERIFIERS_NAME_TOTAL_LENGTH 100 // The maximum length of the block verifiers name
#define MAXIMUM_INVALID_RESERERVE_PROOFS 50000 // The maximum invalid reserve proofs for the delegates

// VRF
#define VRF_PUBLIC_KEY_LENGTH 64
#define VRF_SECRET_KEY_LENGTH 128
#define VRF_PROOF_LENGTH 160
#define VRF_BETA_LENGTH 128
#define VRF_DATA "74727565" // true when the VRF data is verified



#define color_print(string,color) \
  if (memcmp(color,"red",3) == 0) \
  { \
    fprintf(stderr,"\033[1;31m%s\033[0m",string); \
  } \
  else if (memcmp(color,"green",5) == 0) \
  { \
    fprintf(stderr,"\033[1;32m%s\033[0m",string); \
  } \
  else if (memcmp(color,"yellow",6) == 0) \
  { \
    fprintf(stderr,"\033[1;33m%s\033[0m",string); \
  } \
  else if (memcmp(color,"blue",4) == 0) \
  { \
    fprintf(stderr,"\033[1;34m%s\033[0m",string); \
  } \
  else if (memcmp(color,"purple",6) == 0) \
  { \
    fprintf(stderr,"\033[1;35m%s\033[0m",string); \
  } \
  else if (memcmp(color,"lightblue",9) == 0) \
  { \
    fprintf(stderr,"\033[1;36m%s\033[0m",string); \
  } \
  else \
  { \
    fprintf(stderr,"%s",string); \
  }

#define append_string(data1,data2,data1_length) \
memcpy(data1+strlen(data1),data2,strnlen(data2,data1_length - strlen(data1) - 1));

#define pointer_reset(pointer) \
free(pointer); \
pointer = NULL;

// Global Structures

struct network_data_nodes_list {
    std::string network_data_nodes_public_address[NETWORK_DATA_NODES_AMOUNT]; // The network data nodes public address
    std::string network_data_nodes_IP_address[NETWORK_DATA_NODES_AMOUNT]; // The network data nodes IP address
};

struct current_block_verifiers_list {
    std::string block_verifiers_public_address[BLOCK_VERIFIERS_AMOUNT]; // The block verifiers public address
    std::string block_verifiers_IP_address[BLOCK_VERIFIERS_AMOUNT]; // The block verifiers IP address
};

struct blockchain_reserve_bytes {
    char* block_producer_delegates_name_data; // The block_producer_delegates_name
    char* block_producer_delegates_name; // The block_producer_delegates_name_data text
    size_t block_producer_delegates_name_data_length; // The amount of characters of the block_producer_delegates_name_data
    char* block_producer_public_address_data; // The block_producer_public_address
    char* block_producer_public_address; // The block_producer_public_address_data text
    size_t block_producer_public_address_data_length; // The amount of characters of the block_producer_public_address_data
    char* block_producer_node_backup_count_data; // The block_producer_node_backup_count
    char* block_producer_node_backup_count; // The block_producer_node_backup_count_data text
    size_t block_producer_node_backup_count_data_length; // The amount of characters of the block_producer_node_backup_count_data
    char* block_producer_backup_nodes_names_data; // The block_producer_backup_nodes_names
    char* block_producer_backup_nodes_names; // The block_producer_backup_nodes_names_data text
    size_t block_producer_backup_nodes_names_data_length; // The amount of characters of the block_producer_backup_nodes_names_data 
    char* vrf_secret_key_data_round_part_4; // The VRF secret key text for round part 3
    unsigned char* vrf_secret_key_round_part_4; // The VRF secret key for round part 3
    size_t vrf_secret_key_data_length_round_part_4; // The length of the VRF public key for round part 3   
    char* vrf_public_key_data_round_part_4; // The VRF public key text for round part 3
    unsigned char* vrf_public_key_round_part_4; // The VRF public key for round part 3
    size_t vrf_public_key_data_length_round_part_4; // The length of the VRF public key for round part 3
    char* vrf_alpha_string_data_round_part_4; // The VRF alpha string (input string) text for round part 3
    unsigned char* vrf_alpha_string_round_part_4; // The VRF alpha string (input string) for round part 3
    size_t vrf_alpha_string_data_length_round_part_4; // The length of the VRF alpha string (input string) for round part 3
    char* vrf_proof_data_round_part_4; // The VRF proof text for round part 3
    unsigned char* vrf_proof_round_part_4; // The VRF proof for round part 3
    size_t vrf_proof_data_length_round_part_4; // The length of the VRF proof for round part 3
    char* vrf_beta_string_data_round_part_4; // The VRF beta string (output string) text for round part 3
    unsigned char* vrf_beta_string_round_part_4; // The VRF beta string (output string) for round part 3
    size_t vrf_beta_string_data_length_round_part_4; // The length of the VRF beta string (output string) for round part 3
    char* vrf_data_round_part_4; // The VRF data for round part 3  
    char* vrf_data; // The VRF data for all of the round parts
    size_t vrf_data_length; // The length of the VRF data for all of the round parts
    char* block_verifiers_vrf_secret_key_data[BLOCK_VERIFIERS_AMOUNT]; // The VRF secret key text that all of the block verifiers create
    unsigned char* block_verifiers_vrf_secret_key[BLOCK_VERIFIERS_AMOUNT]; // The VRF secret key that all of the block verifiers create
    size_t block_verifiers_vrf_secret_key_data_length; // The amount of characters of the block_verifiers_vrf_secret_key_data
    char* block_verifiers_vrf_public_key_data[BLOCK_VERIFIERS_AMOUNT]; // The VRF public key text that all of the block verifiers create
    unsigned char* block_verifiers_vrf_public_key[BLOCK_VERIFIERS_AMOUNT]; // The VRF public key that all of the block verifiers create
    size_t block_verifiers_vrf_public_key_data_length; // The amount of characters of the block_verifiers_vrf_public_key_data
    char* block_verifiers_random_data[BLOCK_VERIFIERS_AMOUNT]; // The random data that all of the block verifiers create
    char* block_verifiers_random_data_text[BLOCK_VERIFIERS_AMOUNT]; // The random data text that all of the block verifiers create
    size_t block_verifiers_random_data_length; // The amount of characters of the block_verifiers_random_data
    char* next_block_verifiers_public_address_data[BLOCK_VERIFIERS_AMOUNT]; // The next_block_verifiers_public_address
    char* next_block_verifiers_public_address[BLOCK_VERIFIERS_AMOUNT]; // The next_block_verifiers_public_address_data text
    size_t next_block_verifiers_public_address_data_length; // The amount of characters of the next_block_verifiers_public_address_data
    char* previous_block_hash_data; // The previous_block_hash
    size_t previous_block_hash_data_length; // The amount of characters of the previous_block_hash_data
    char* block_validation_node_signature_data[BLOCK_VERIFIERS_AMOUNT]; // The block_validation_node_signature
    char* block_validation_node_signature[BLOCK_VERIFIERS_AMOUNT]; // The block_validation_node_signature_data text
    size_t block_validation_node_signature_data_length; // The amount of characters of the block_validation_node_signature_data
};

struct blockchain_data {
    char* network_version_data; // The network_version
    size_t network_version_data_length; // The amount of characters of the network_version_data
    char* timestamp_data; // The timestamp
    size_t timestamp; // Variant decoded timestamp
    size_t timestamp_data_length; // The amount of characters of the timestamp_data
    char* previous_block_hash_data; // The previous_block_hash
    size_t previous_block_hash_data_length; // The amount of characters of the previous_block_hash_data
    char* nonce_data; // The nonce
    size_t nonce_data_length; // The amount of characters of the nonce_data
    char* block_reward_transaction_version_data; // The block_reward_transaction_version
    size_t block_reward_transaction_version_data_length; // The amount of characters of the block_reward_transaction_version_data
    char* unlock_block_data; // The unlock_block
    size_t unlock_block; // Variant decoded unlock_block
    size_t unlock_block_data_length; // The amount of characters of the unlock_block_data
    char* block_reward_input_data; // The block_reward_input
    size_t block_reward_input_data_length; // The amount of characters of the block_reward_input_data
    char* vin_type_data; // The vin_type
    size_t vin_type_data_length; // The amount of characters of the vin_type_data
    char* block_height_data; // The block_height
    size_t block_height; // Variant decoded block_height
    size_t block_height_data_length; // The amount of characters of the block_height_data
    char* block_reward_output_data; // The block_reward_output
    size_t block_reward_output_data_length; // The amount of characters of the block_reward_output_data
    char* block_reward_data; // The block_reward
    size_t block_reward; // Variant decoded block_reward
    size_t block_reward_data_length; // The amount of characters of the block_reward_data
    char* stealth_address_output_tag_data; // The stealth_address_output_tag
    size_t stealth_address_output_tag_data_length; // The amount of characters of the stealth_address_output_tag_data
    char* stealth_address_output_data; // The stealth_address_output
    size_t stealth_address_output_data_length; // The amount of characters of the stealth_address_output_data
    char* extra_bytes_size_data; // The extra_bytes_size
    size_t extra_bytes_size; // Variant decoded extra_bytes_size
    size_t extra_bytes_size_data_length; // The amount of characters of the extra_bytes_size
    char* transaction_public_key_tag_data; // The transaction_public_key_tag
    size_t transaction_public_key_tag_data_length; // The amount of characters of the transaction_public_key_tag
    char* transaction_public_key_data; // The transaction_public_key
    size_t transaction_public_key_data_length; // The amount of characters of the transaction_public_key
    char* extra_nonce_tag_data; // The extra_nonce_tag
    size_t extra_nonce_tag_data_length; // The amount of characters of the extra_nonce_tag
    char* reserve_bytes_size_data; // The reserve_bytes_size
    size_t reserve_bytes_size; // Variant decoded reserve_bytes_size
    size_t reserve_bytes_size_data_length; // The amount of characters of the reserve_bytes_size
    struct blockchain_reserve_bytes blockchain_reserve_bytes; // A blockchain_reserve_bytes struct that holds all of the reserve bytes
    char* ringct_version_data; // The ringct_version
    size_t ringct_version_data_length; // The amount of characters of the ringct_version
    char* transaction_amount_data; // The transaction_amount
    size_t transaction_amount; // Variant decoded transaction_amount
    size_t transaction_amount_data_length; // The amount of characters of the transaction_amount
    char* transactions[MAXIMUM_TRANSACATIONS_PER_BLOCK]; // All of the transactions in the block.
};

// Global Variables
struct network_data_nodes_list network_data_nodes_list; // The network data nodes
struct current_block_verifiers_list current_block_verifiers_list; // The data for a new block to be added to the network.
struct blockchain_data blockchain_data; // The data for a new block to be added to the network.
std::string current_block_verifier_public_address = "";
std::string current_block_verifier_IP_address = "";



std::string send_and_receive_data(std::string IP_address,std::string data2)
{
  // Variables
  boost::asio::io_service http_service;
  boost::asio::streambuf message;
  std::string string;

  // add the end string to the data
  data2 += SOCKET_END_STRING;

  // send the data to the server
  tcp::resolver resolver(http_service);
  tcp::resolver::query query(IP_address, SEND_DATA_PORT);
  tcp::resolver::iterator data = resolver.resolve(query);
  tcp::socket socket(http_service);

  std::future<tcp::resolver::iterator> conn_result = boost::asio::async_connect(socket,data,boost::asio::use_future);
  auto status = conn_result.wait_for(std::chrono::milliseconds(SOCKET_CONNECTION_TIMEOUT_SETTINGS));
  if (status == std::future_status::timeout)
  {
    socket.cancel();
    return "socket_timeout";
  }

  std::ostream http_request(&message);
  http_request << data2;
 
  // send the message and read the response
  boost::asio::write(socket, message);
  boost::asio::streambuf response;
  boost::asio::read_until(socket, response, "}");
  std::istream response_stream(&response);  
  std::getline(response_stream, string, '}');
  return string;
}


size_t string_count(const char* DATA, const char* STRING)
{  
  // Variables
  char* datacopy1 = (char*)calloc(BUFFER_SIZE,sizeof(char)); 
  // since were going to be changing where datacopy1 is referencing, we need to create a copy to pointer_reset
  char* datacopy2 = datacopy1; 
  size_t count = 0;

  // check if the memory needed was allocated on the heap successfully
  if (datacopy1 == NULL)
  {
    color_print("Could not allocate the memory needed on the heap","red");
    exit(0);
  }

  // get the occurences of the string 
  memcpy(datacopy1,DATA,strnlen(DATA,BUFFER_SIZE));
  while((datacopy1 = strstr(datacopy1, STRING)) != NULL)
  {
    count++;
    datacopy1+= strlen(STRING);
  } 

  pointer_reset(datacopy2);
  return count;
}

int string_replace(char *data, const size_t DATA_TOTAL_LENGTH, const char* STR1, const char* STR2)
{  
  // check if the str to replace exist in the string
  if (strstr(data,STR1) != NULL)
  { 
    // Variables
    char* datacopy = (char*)calloc(BUFFER_SIZE,sizeof(char));
    char* data2 = (char*)calloc(BUFFER_SIZE,sizeof(char));
    char* string;
    size_t data_length;
    size_t str2_length;
    size_t start;
    size_t total = 0;
    size_t count = 0; 

    // define macros
    #define REPLACE_STRING "|REPLACE_STRING|" 
    #define pointer_reset_all \
    free(datacopy); \
    datacopy = NULL; \
    free(data2); \
    data2 = NULL;

    // check if the memory needed was allocated on the heap successfully
    if (datacopy == NULL || data2 == NULL)
    {
      if (datacopy != NULL)
      {
        pointer_reset(datacopy);
      }
      if (data2 != NULL)
      {
        pointer_reset(data2);
      }
      color_print("Could not allocate the memory needed on the heap","red");
      exit(0);
    } 

    // copy the string to data2
    memcpy(data2,data,strnlen(data,BUFFER_SIZE));

    // get the occurences of STR1   
    total = string_count(data2,(char*)STR1);

    // replace the string with the REPLACE_STRING
    for (count = 0; count < total; count++)
    {
      // reset the variables
      memset(datacopy,0,strlen(datacopy));
      data_length = strnlen(data2,BUFFER_SIZE);
      start = data_length - strnlen(strstr(data2,STR1),BUFFER_SIZE);
   
      // get a pointer to where the rest of the data2 string should be copied to
      string = strstr(data2,STR1)+strnlen(STR1,BUFFER_SIZE);
           
      // copy the bytes before STR1 to the new string
      memcpy(datacopy,data2,start);
      // copy STR2 to the new string
      memcpy(datacopy+strlen(datacopy),REPLACE_STRING,sizeof(REPLACE_STRING)-1);
      // copy the bytes after STR1 to the new string
      memcpy(datacopy+strlen(datacopy),string,strnlen(string,BUFFER_SIZE));
      // copy the new string to the string pointer
      memset(data2,0,data_length);
      memcpy(data2,datacopy,strlen(datacopy));
    }
    // replace the REPLACE_STRING with STR2
    for (count = 0; count < total; count++)
    {
      // reset the variables
      memset(datacopy,0,strlen(datacopy));
      data_length = strnlen(data2,BUFFER_SIZE);
      str2_length = strnlen(STR2,BUFFER_SIZE);
      start = data_length - strnlen(strstr(data2,REPLACE_STRING),BUFFER_SIZE);
   
      // get a pointer to where the rest of the data string should be copied to
      string = strstr(data2,REPLACE_STRING)+(sizeof(REPLACE_STRING)-1);
           
      // copy the bytes before REPLACE_STRING to the new string
      memcpy(datacopy,data2,start);
      // copy STR2 to the new string
      memcpy(datacopy+start,STR2,str2_length);
      // copy the bytes after REPLACE_STRING to the new string
      memcpy(datacopy+start+str2_length,string,strnlen(string,BUFFER_SIZE));
      // copy the new string to the string pointer
      memset(data2,0,data_length);
      memcpy(data2,datacopy,strlen(datacopy));
    }

    // copy data2 to the string
    memset(data,0,strlen(data));
    memcpy(data,data2,strnlen(data2,DATA_TOTAL_LENGTH));
    pointer_reset_all;
    return 1;
  }
  else
  {
    return 0;
  } 

  #undef REPLACE_STRING
  #undef pointer_reset_all
}

int varint_encode(long long int number, char *result, const size_t RESULT_TOTAL_LENGTH)
{
  // Variables
  char data[BUFFER_SIZE];
  size_t length;
  size_t count = 0;
  size_t count2 = 0;
  int binary_numbers[BITS_IN_BYTE];
  int binary_number_copy;
  long long int number_copy = (long long int)number;  

  memset(data,0,sizeof(data));
  memset(result,0,RESULT_TOTAL_LENGTH);  

  // check if it should not be encoded
  if (number <= 0xFF)
  {
    sprintf(result,"%02llx",number);
    return 1;
  }

  // convert the number to a binary string
  for (count = 0; number_copy != 0; count++)
  {
    if (number_copy % 2 == 1)
    {
      append_string(data,"1",sizeof(data));
    }
    else
    {
      append_string(data,"0",sizeof(data));
    }
    number_copy /= 2; 
  }

  // pad the string to a mulitple of 7 bits  
  for (count = strnlen(data,sizeof(data)); count % (BITS_IN_BYTE-1) != 0; count++)
  {
    append_string(result,"0",RESULT_TOTAL_LENGTH);
  }

  // reverse the string
  length = strnlen(data,sizeof(data));
  for (count = 0; count <= length; count++)
  {
    memcpy(result+strlen(result),&data[length - count],1);
  }
  memset(data,0,sizeof(data));
  append_string(data,result,sizeof(data));
  memset(result,0,RESULT_TOTAL_LENGTH);

  /*
  convert each 7 bits to one byte
  set the first bit to 1 for all groups of 7 except for the first group of 7
  */
  length = strnlen(data,sizeof(data)) + (strnlen(data,sizeof(data)) / (BITS_IN_BYTE-1));
  count = 0;
  count2 = 0;

 for (count = 0, count2 = 0; count < length; count++)
 {
   if (count % 8 == 0 && count != 0)
   {
     // reverse the binary bits
     binary_number_copy = 0;       
     if (((binary_numbers[count2] >> 7) & 1U) == 1) {binary_number_copy |= 1UL << 0;} else {binary_number_copy &= ~(1UL << 0);}
     if (((binary_numbers[count2] >> 6) & 1U) == 1) {binary_number_copy |= 1UL << 1;} else {binary_number_copy &= ~(1UL << 1);}
     if (((binary_numbers[count2] >> 5) & 1U) == 1) {binary_number_copy |= 1UL << 2;} else {binary_number_copy &= ~(1UL << 2);}
     if (((binary_numbers[count2] >> 4) & 1U) == 1) {binary_number_copy |= 1UL << 3;} else {binary_number_copy &= ~(1UL << 3);}
     if (((binary_numbers[count2] >> 3) & 1U) == 1) {binary_number_copy |= 1UL << 4;} else {binary_number_copy &= ~(1UL << 4);}
     if (((binary_numbers[count2] >> 2) & 1U) == 1) {binary_number_copy |= 1UL << 5;} else {binary_number_copy &= ~(1UL << 5);}
     if (((binary_numbers[count2] >> 1) & 1U) == 1) {binary_number_copy |= 1UL << 6;} else {binary_number_copy &= ~(1UL << 6);}
     if (((binary_numbers[count2] >> 0) & 1U) == 1) {binary_number_copy |= 1UL << 7;} else {binary_number_copy &= ~(1UL << 7);}
     binary_numbers[count2] = binary_number_copy;
     count2++;
   } 
   if (count % BITS_IN_BYTE == 0)
   {
     if (count == 0)
     {
       // clear the binary bit to 0
       binary_numbers[count2] &= ~(1 << (count % BITS_IN_BYTE));      
     }
     else
     {
       // set the binary bit to 1
       binary_numbers[count2] |= 1 << (count % BITS_IN_BYTE);
     }
   }
   else
   {
     if (memcmp(data + (count - (count2+1)),"1",1) == 0)
     {
       // set the binary bit to 1
       binary_numbers[count2] |= 1 << (count % BITS_IN_BYTE);
     }
     else
     {
       // clear the binary bit to 0
       binary_numbers[count2] &= ~(1 << (count % BITS_IN_BYTE));
     }     
   }
 }

  // reverse the last binary_number
  length = strnlen(data,sizeof(data)) / BITS_IN_BYTE;
  binary_number_copy = 0;
  if (((binary_numbers[length] >> 7) & 1U) == 1) {binary_number_copy |= 1UL << 0;} else {binary_number_copy &= ~(1UL << 0);}
  if (((binary_numbers[length] >> 6) & 1U) == 1) {binary_number_copy |= 1UL << 1;} else {binary_number_copy &= ~(1UL << 1);}
  if (((binary_numbers[length] >> 5) & 1U) == 1) {binary_number_copy |= 1UL << 2;} else {binary_number_copy &= ~(1UL << 2);}
  if (((binary_numbers[length] >> 4) & 1U) == 1) {binary_number_copy |= 1UL << 3;} else {binary_number_copy &= ~(1UL << 3);}
  if (((binary_numbers[length] >> 3) & 1U) == 1) {binary_number_copy |= 1UL << 4;} else {binary_number_copy &= ~(1UL << 4);}
  if (((binary_numbers[length] >> 2) & 1U) == 1) {binary_number_copy |= 1UL << 5;} else {binary_number_copy &= ~(1UL << 5);}
  if (((binary_numbers[length] >> 1) & 1U) == 1) {binary_number_copy |= 1UL << 6;} else {binary_number_copy &= ~(1UL << 6);}
  if (((binary_numbers[length] >> 0) & 1U) == 1) {binary_number_copy |= 1UL << 7;} else {binary_number_copy &= ~(1UL << 7);}
  binary_numbers[length] = binary_number_copy;

  // create the varint encoded string
  for (count = 0, count2 = 0; count <= length; count++, count2 += 2)
  {
    sprintf(result+count2,"%02x",binary_numbers[length-count] & 0xFF);
  }
  
  return 1;    
}

size_t varint_decode(size_t varint)
{
  // Variables
  int length = 0;
  int count = 0;
  int counter = 0;
  int bytecount = 0;
  size_t number = 1;
  int start = 0;

  // get the length
  if (varint <= 0xFF)
  {
    return varint;
  }
  else if (varint > 0xFF && varint < 0xFFFF)
  {
    length = 2;
  }
  else if (varint >= 0xFFFF && varint < 0xFFFFFF)
  {
    length = 3;
  }
  else if (varint >= 0xFFFFFF && varint < 0xFFFFFFFF)
  {
    length = 4;
  }
  else if (varint >= 0xFFFFFFFF && varint < 0xFFFFFFFFFF)
  {
    length = 5;
  }
  else if (varint >= 0xFFFFFFFFFF && varint < 0xFFFFFFFFFFFF)
  {
    length = 6;
  }
  else if (varint >= 0xFFFFFFFFFFFF && varint < 0xFFFFFFFFFFFFFF)
  {
    length = 7;
  }
  else if (varint >= 0xFFFFFFFFFFFFFF && varint < 0xFFFFFFFFFFFFFFFF)
  {
    length = 8;
  }

  // create a byte array for the varint
  char bytes[length];

  for (count = 0; count < length; count++)
  {
    // convert each byte to binary and read the bytes in reverse order
    bytes[count] = ((varint >> (BITS_IN_BYTE * count)) & 0xFF);
  }
    
  for (count = 0, counter = (BITS_IN_BYTE-1), bytecount = 0, start = 0; count < length * BITS_IN_BYTE; count++)
  {
    // loop through each bit until you find the first 1. for every bit after this:
    // if 0 then number = number * 2;
    // if 1 then number = (number * 2) + 1;
    // dont use the bit if its the first bit
    if (counter != (BITS_IN_BYTE-1))
    {
      if (bytes[bytecount] & (1 << counter)) 
      {
        if (start == 1)
        {
          number = (number * 2) + 1;
        }
      start = 1;
      }
      else
      {
        if (start == 1)
        {
          number = number * 2;
        }
      } 
    }
      
    if (counter == 0) 
    {
      counter = (BITS_IN_BYTE-1);
      bytecount++;
    }
    else
    {
      counter--;
    }
  }
 return number;    
}

int data_verify(const std::string PUBLIC_ADDRESS, const std::string DATA_SIGNATURE, const std::string DATA)
{
  // Variables
  cryptonote::address_parse_info info;
  cryptonote::blobdata public_address_data;
  uint64_t prefix;
  crypto::hash hash;
  std::string decoded;
  crypto::signature s;

  // create a cryptonote::address_parse_info for the public address 
  info.is_subaddress = false;
  info.has_payment_id = false;
   
  if (!tools::base58::decode_addr(PUBLIC_ADDRESS, prefix, public_address_data) || !::serialization::parse_binary(public_address_data, info.address) || !crypto::check_key(info.address.m_spend_public_key) || !crypto::check_key(info.address.m_view_public_key))
  {
    return 0;
  }

  if (DATA_SIGNATURE.size() < sizeof(XCASH_SIGN_DATA_PREFIX)-1 || DATA_SIGNATURE.substr(0, sizeof(XCASH_SIGN_DATA_PREFIX)-1) != XCASH_SIGN_DATA_PREFIX)
  {
    return 0;
  }  
  crypto::cn_fast_hash(DATA.data(), DATA.size(), hash);
  
  if (!tools::base58::decode(DATA_SIGNATURE.substr(5), decoded) || sizeof(s) != decoded.size())
  {
    return 0;
  }
  memcpy(&s, decoded.data(), sizeof(s));
  return crypto::check_signature(hash, info.address.m_spend_public_key, s) == true ? 1 : 0;
}

int verify_data(const std::string MESSAGE, int settings)
{

// Constants
const std::string public_address = MESSAGE.substr(MESSAGE.find("|XCA")+1,XCASH_WALLET_LENGTH);
const std::string xcash_proof_of_stake_signature = MESSAGE.substr(MESSAGE.find("|SigV1")+1,XCASH_SIGN_DATA_LENGTH);

// Variables
int count;
int count2;

if (settings == 0)
{
// check if the public address is in the network_data_nodes_list struct
for (count = 0, count2 = 0; count < NETWORK_DATA_NODES_AMOUNT; count++)
{
if (network_data_nodes_list.network_data_nodes_public_address[count] == public_address)
{
count2 = 1;
break;
}
}
}
else
{
for (count = 0, count2 = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
{
if (current_block_verifiers_list.block_verifiers_public_address[count] == public_address)
{
count2 = 1;
break;
}
}
}

if (count2 != 1)
{
return 0;
}
return data_verify(public_address,xcash_proof_of_stake_signature,MESSAGE.substr(0,MESSAGE.find("|XCA")+1));
}

int network_block_string_to_blockchain_data(const char* DATA, const char* BLOCK_HEIGHT)
{
  // Constants
  const size_t DATA_LENGTH = strnlen(DATA,BUFFER_SIZE);

  // Variables
  size_t count;
  size_t count2;
  size_t count3;
  size_t counter;
  size_t number;
  char* current_block_height = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* data2 = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* data3;
  char* message_copy1;

  // define macros
  #define pointer_reset_all \
  free(current_block_height); \
  current_block_height = NULL; \
  free(data2); \
  data2 = NULL;

  #define NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR(settings) \
  color_print(settings,"red"); \
  pointer_reset_all; \
  return 0; 

  // check if the memory needed was allocated on the heap successfully
  if (current_block_height == NULL || data2 == NULL)
  {
    if (current_block_height != NULL)
    {
      pointer_reset(current_block_height);
    }
    if (data2 != NULL)
    {
      pointer_reset(data2);
    }
    color_print("Could not allocate the memory needed on the heap","red");
    exit(0);
  }  

  // reset the blockchain_data
  memset(blockchain_data.network_version_data,0,strnlen(blockchain_data.network_version_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.timestamp_data,0,strnlen(blockchain_data.timestamp_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.previous_block_hash_data,0,strnlen(blockchain_data.previous_block_hash_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.nonce_data,0,strnlen(blockchain_data.nonce_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.block_reward_transaction_version_data,0,strnlen(blockchain_data.block_reward_transaction_version_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.unlock_block_data,0,strnlen(blockchain_data.unlock_block_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.block_reward_input_data,0,strnlen(blockchain_data.block_reward_input_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.vin_type_data,0,strnlen(blockchain_data.vin_type_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.block_height_data,0,strnlen(blockchain_data.block_height_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.block_reward_output_data,0,strnlen(blockchain_data.block_reward_output_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.block_reward_data,0,strnlen(blockchain_data.block_reward_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.stealth_address_output_tag_data,0,strnlen(blockchain_data.stealth_address_output_tag_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.stealth_address_output_data,0,strnlen(blockchain_data.stealth_address_output_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.extra_bytes_size_data,0,strnlen(blockchain_data.extra_bytes_size_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.transaction_public_key_tag_data,0,strnlen(blockchain_data.transaction_public_key_tag_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.transaction_public_key_data,0,strnlen(blockchain_data.transaction_public_key_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.extra_nonce_tag_data,0,strnlen(blockchain_data.extra_nonce_tag_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.reserve_bytes_size_data,0,strnlen(blockchain_data.reserve_bytes_size_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data,0,strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,0,strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data,0,strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,0,strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,0,strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,0,strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data,0,strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names,0,strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_round_part_4,0,strnlen((const char*)blockchain_data.blockchain_reserve_bytes.vrf_secret_key_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4,0,strnlen((const char*)blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,BUFFER_SIZE));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_round_part_4,0,strnlen((const char*)blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_round_part_4,BUFFER_SIZE));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4,0,strnlen((const char*)blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4,0,strnlen((const char*)blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,BUFFER_SIZE_NETWORK_BLOCK_DATA));    
  memset(blockchain_data.blockchain_reserve_bytes.vrf_data,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,0,strnlen(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    memset(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count],0,strnlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count],0,strnlen((const char*)blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count],0,strnlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count],0,strnlen((const char*)blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count],0,strnlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count],0,strnlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count],0,strnlen(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count],0,strnlen(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count],0,strnlen(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
    memset(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count],0,strnlen(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
  }
  memset(blockchain_data.ringct_version_data,0,strnlen(blockchain_data.ringct_version_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  memset(blockchain_data.transaction_amount_data,0,strnlen(blockchain_data.transaction_amount_data,BUFFER_SIZE_NETWORK_BLOCK_DATA));
  for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++)
  {
    memset(blockchain_data.transactions[count],0,strnlen(blockchain_data.transactions[count],BUFFER_SIZE_NETWORK_BLOCK_DATA));
  }
  count = 0;

  // network_version
  blockchain_data.network_version_data_length = sizeof(NETWORK_VERSION)-1;
  count+= blockchain_data.network_version_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid network_version");
  }
  memcpy(blockchain_data.network_version_data,DATA,blockchain_data.network_version_data_length);

  // timestamp
  blockchain_data.timestamp_data_length = TIMESTAMP_LENGTH;
  count+= blockchain_data.timestamp_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid timestamp");
  }
  memcpy(blockchain_data.timestamp_data,&DATA[count-blockchain_data.timestamp_data_length],blockchain_data.timestamp_data_length);
  blockchain_data.timestamp = varint_decode((size_t)strtol(blockchain_data.timestamp_data, NULL, 16));

  // previous_block_hash
  blockchain_data.previous_block_hash_data_length = BLOCK_HASH_LENGTH;
  count+= blockchain_data.previous_block_hash_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid previous_block_hash");
  }
  memcpy(blockchain_data.previous_block_hash_data,&DATA[count-blockchain_data.previous_block_hash_data_length],blockchain_data.previous_block_hash_data_length);

  // nonce
  blockchain_data.nonce_data_length = sizeof(BLOCK_PRODUCER_NETWORK_BLOCK_NONCE)-1;
  count+= blockchain_data.nonce_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid nonce");
  }
  memcpy(blockchain_data.nonce_data,&DATA[count-blockchain_data.nonce_data_length],blockchain_data.nonce_data_length);

  // block_reward_transaction_version
  blockchain_data.block_reward_transaction_version_data_length = sizeof(BLOCK_REWARD_TRANSACTION_VERSION)-1;
  count+= blockchain_data.block_reward_transaction_version_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid block_reward_transaction_version");
  }
  memcpy(blockchain_data.block_reward_transaction_version_data,&DATA[count-blockchain_data.block_reward_transaction_version_data_length],blockchain_data.block_reward_transaction_version_data_length);

  // unlock_block
  // get the current block height
  sscanf(BLOCK_HEIGHT, "%zu", &number);

  if ((number + UNLOCK_BLOCK_AMOUNT) > 2097091)
  {
    blockchain_data.unlock_block_data_length = 8;
  }
  else
  {
    blockchain_data.unlock_block_data_length = 6;
  }
  count+= blockchain_data.unlock_block_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid unlock_block");
  }
  memcpy(blockchain_data.unlock_block_data,&DATA[count-blockchain_data.unlock_block_data_length],blockchain_data.unlock_block_data_length);
  blockchain_data.unlock_block = varint_decode((size_t)strtol(blockchain_data.unlock_block_data, NULL, 16));

  // block_reward_input
  blockchain_data.block_reward_input_data_length = sizeof(BLOCK_REWARD_INPUT)-1;
  count+= blockchain_data.block_reward_input_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid block_reward_input");
  }
  memcpy(blockchain_data.block_reward_input_data,&DATA[count-blockchain_data.block_reward_input_data_length],blockchain_data.block_reward_input_data_length);

  // vin_type
  blockchain_data.vin_type_data_length = sizeof(VIN_TYPE)-1;
  count+= blockchain_data.vin_type_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid vin_type");
  }
  memcpy(blockchain_data.vin_type_data,&DATA[count-blockchain_data.vin_type_data_length],blockchain_data.vin_type_data_length);

  // block_height
  if (number > 2097151)
  {
    blockchain_data.block_height_data_length = 8;
  }
  else
  {
    blockchain_data.block_height_data_length = 6;
  }
  count+= blockchain_data.block_height_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid block_height");
  }
  memcpy(blockchain_data.block_height_data,&DATA[count-blockchain_data.block_height_data_length],blockchain_data.block_height_data_length);
  blockchain_data.block_height = varint_decode((size_t)strtol(blockchain_data.block_height_data, NULL, 16));

  // block_reward_output
  blockchain_data.block_reward_output_data_length = sizeof(BLOCK_REWARD_OUTPUT)-1;
  count+= blockchain_data.block_reward_output_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid block_reward_output");
  }
  memcpy(blockchain_data.block_reward_output_data,&DATA[count-blockchain_data.block_reward_output_data_length],blockchain_data.block_reward_output_data_length);

  // block_reward
  // since the block reward could be any number because of transactions fees, get the position of BLOCKCHAIN_RESERVED_BYTES_START to get the length of the block reward
  data3 = strstr((char*)DATA,BLOCKCHAIN_RESERVED_BYTES_START);
  if (data3 == NULL)
  {
    data3 = strstr((char*)DATA,BLOCKCHAIN_RESERVED_BYTES_DATA_HASH);
    if (data3 == NULL)
    {
      NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid block_reward");
    }
  }
  //blockchain_data.block_reward_data_length = 12;
  // if the block contained BLOCKCHAIN_RESERVED_BYTES_DATA_HASH subtract 136 since we already included the extra nonce tag and the reserve bytes size
  if (strstr(DATA,BLOCKCHAIN_RESERVED_BYTES_START) != NULL)
  {
    blockchain_data.block_reward_data_length = strlen(DATA) - strlen(data3) - count - 140;
  }
  else if (strstr(DATA,BLOCKCHAIN_RESERVED_BYTES_DATA_HASH) != NULL)
  {
    blockchain_data.block_reward_data_length = strlen(DATA) - strlen(data3) - count - 136;
  }
  count+= blockchain_data.block_reward_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid block_reward");
  }
  memcpy(blockchain_data.block_reward_data,&DATA[count-blockchain_data.block_reward_data_length],blockchain_data.block_reward_data_length);
  blockchain_data.block_reward = varint_decode((size_t)strtol(blockchain_data.block_reward_data, NULL, 16));  

  // stealth_address_output_tag
  blockchain_data.stealth_address_output_tag_data_length = sizeof(STEALTH_ADDRESS_OUTPUT_TAG)-1;
  count+= blockchain_data.stealth_address_output_tag_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid stealth_address_output_tag");
  }
  memcpy(blockchain_data.stealth_address_output_tag_data,&DATA[count-blockchain_data.stealth_address_output_tag_data_length],blockchain_data.stealth_address_output_tag_data_length);

  // stealth_address_output
  blockchain_data.stealth_address_output_data_length = STEALTH_ADDRESS_OUTPUT_LENGTH;
  count+= blockchain_data.stealth_address_output_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid stealth_address_output");
  }
  memcpy(blockchain_data.stealth_address_output_data,&DATA[count-blockchain_data.stealth_address_output_data_length],blockchain_data.stealth_address_output_data_length);

  // extra_bytes_size
  blockchain_data.extra_bytes_size_data_length = 2;
  count+= blockchain_data.extra_bytes_size_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid extra_bytes_size");
  }
  memcpy(blockchain_data.extra_bytes_size_data,&DATA[count-blockchain_data.extra_bytes_size_data_length],blockchain_data.extra_bytes_size_data_length);
  blockchain_data.extra_bytes_size = varint_decode((size_t)strtol(blockchain_data.extra_bytes_size_data, NULL, 16));

  // transaction_public_key_tag
  blockchain_data.transaction_public_key_tag_data_length = sizeof(TRANSACTION_PUBLIC_KEY_TAG)-1;
  count+= blockchain_data.transaction_public_key_tag_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid transaction_public_key_tag");
  }
  memcpy(blockchain_data.transaction_public_key_tag_data,&DATA[count-blockchain_data.transaction_public_key_tag_data_length],blockchain_data.transaction_public_key_tag_data_length);

  // transaction_public_key
  blockchain_data.transaction_public_key_data_length = TRANSACTION_PUBLIC_KEY_LENGTH;
  count+= blockchain_data.transaction_public_key_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid transaction_public_key");
  }
  memcpy(blockchain_data.transaction_public_key_data,&DATA[count-blockchain_data.transaction_public_key_data_length],blockchain_data.transaction_public_key_data_length);

  // extra_nonce_tag
  blockchain_data.extra_nonce_tag_data_length = sizeof(EXTRA_NONCE_TAG)-1;
  count+= blockchain_data.extra_nonce_tag_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid extra_nonce_tag");
  }
  memcpy(blockchain_data.extra_nonce_tag_data,&DATA[count-blockchain_data.extra_nonce_tag_data_length],blockchain_data.extra_nonce_tag_data_length);

  // reserve_bytes_size
  blockchain_data.reserve_bytes_size_data_length = 2;
  count+= blockchain_data.reserve_bytes_size_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid reserve_bytes_size");
  }
  memcpy(blockchain_data.reserve_bytes_size_data,&DATA[count-blockchain_data.reserve_bytes_size_data_length],blockchain_data.reserve_bytes_size_data_length);
  blockchain_data.reserve_bytes_size = varint_decode((size_t)strtol(blockchain_data.reserve_bytes_size_data, NULL, 16));

  if (strstr(DATA,BLOCKCHAIN_RESERVED_BYTES_DATA_HASH) == NULL)
  {
  // blockchain_reserve_bytes
  // skip the BLOCKCHAIN_RESERVED_BYTES_START
  count+= sizeof(BLOCKCHAIN_RESERVED_BYTES_START)-1;

  // block_producer_delegates_name
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data,&DATA[count],blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data[number],2);
    blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;
  
  // block_producer_public_address
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data,&DATA[count],blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data[number],2);
    blockchain_data.blockchain_reserve_bytes.block_producer_public_address[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;
  
  // block_producer_node_backup_count
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,&DATA[count],blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data[number],2);
    blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;

  // block_producer_backup_nodes_names
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data,&DATA[count],blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data[number],2);
    blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;

  // vrf_secret_key_round_part_4
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_length_round_part_4 = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4,&DATA[count],blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_length_round_part_4);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_length_round_part_4; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4[number],2);
    blockchain_data.blockchain_reserve_bytes.vrf_secret_key_round_part_4[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_length_round_part_4 + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;

  // vrf_public_key_round_part_4
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4 = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4,&DATA[count],blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4[number],2);
    blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4 + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;

  // vrf_alpha_string_round_part_4
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4 = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,&DATA[count],blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4[number],2);
    blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_round_part_4[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4 + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;

  // vrf_proof_round_part_4
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4 = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4,&DATA[count],blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4[number],2);
    blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4 + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;

  // vrf_beta_string_round_part_4
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4 = (strlen(DATA) - strlen(message_copy1)) - count;
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4,&DATA[count],blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4);
  // convert the hexadecimal string to a string
  for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4; count2++, number += 2)
  {
    memset(data2,0,strnlen(data2,BUFFER_SIZE));
    memcpy(data2,&blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4[number],2);
    blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4[count2] = (int)strtol(data2, NULL, 16);
  }
  count += blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4 + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;

  // vrf_data_round_part_4
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,&DATA[count],sizeof(VRF_DATA)-1);
  count += (sizeof(VRF_DATA)-1) + (sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1);

  // vrf_data
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_data,&DATA[count],sizeof(VRF_DATA)-1);
  count += (sizeof(VRF_DATA)-1) + (sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1);

  // block_verifiers_vrf_secret_key_data
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length = VRF_SECRET_KEY_LENGTH;
  for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++)
  { 
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count3],&DATA[count],blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;
    // convert the hexadecimal string to a string
    for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length; count2++, number += 2)
    {
      memset(data2,0,strnlen(data2,BUFFER_SIZE));
      memcpy(data2,&blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count3][number],2);
      blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count3][count2] = (int)strtol(data2, NULL, 16);
    }    
  }

  // block_verifiers_vrf_public_key_data
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data_length = VRF_PUBLIC_KEY_LENGTH;
  for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++)
  { 
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count3],&DATA[count],blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data_length + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;
    // convert the hexadecimal string to a string
    for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data_length; count2++, number += 2)
    {
      memset(data2,0,strnlen(data2,BUFFER_SIZE));
      memcpy(data2,&blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count3][number],2);
      blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count3][count2] = (int)strtol(data2, NULL, 16);
    }    
  }

  // block_verifiers_random_data
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length = RANDOM_STRING_LENGTH*2;
  for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++)
  { 
    memset(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count3],0,strlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count3]));
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count3],&DATA[count],blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;
    // convert the hexadecimal string to a string
    for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length; count2++, number += 2)
    {
      memset(data2,0,strnlen(data2,BUFFER_SIZE));
      memcpy(data2,&blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count3][number],2);
      blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count3][count2] = (int)strtol(data2, NULL, 16);
    } 
  }

  // next_block_verifiers_public_address_data
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data_length = (strlen(DATA) - strlen(message_copy1)) - count;
  for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++)
  { 
    memcpy(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count3],&DATA[count],blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data_length);
    count += blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data_length + sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1;
    // convert the hexadecimal string to a string
    for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data_length; count2++, number += 2)
    {
      memset(data2,0,strnlen(data2,BUFFER_SIZE));
      memcpy(data2,&blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count3][number],2);
      blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count3][count2] = (int)strtol(data2, NULL, 16);
    }
  }
  count += (sizeof(BLOCKCHAIN_DATA_SEGMENT_STRING)-1);

  // previous block hash
  blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length = BLOCK_HASH_LENGTH;
  memcpy(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,blockchain_data.previous_block_hash_data,blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length);
  count += blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length + BLOCK_HASH_LENGTH;

  // block_validation_node_signature_data
  message_copy1 = strstr((char*)DATA,BLOCKCHAIN_DATA_SEGMENT_SIGN_DATA_STRING);
  blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length = XCASH_SIGN_DATA_LENGTH*2;
  
  for (counter = 64, count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++)
  { 
    memcpy(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count3],&message_copy1[counter],blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length + BLOCK_HASH_LENGTH;
    counter += blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length + BLOCK_HASH_LENGTH;
    // convert the hexadecimal string to a string
    for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length; count2++, number += 2)
    {
      memset(data2,0,strnlen(data2,BUFFER_SIZE));
      memcpy(data2,&blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count3][number],2);
      blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count3][count2] = (int)strtol(data2, NULL, 16);
    }
  }

  // set the count to the end of the reserve bytes
  message_copy1 = strstr((char*)DATA,BLOCKCHAIN_RESERVED_BYTES_END);
  count = strnlen(DATA,BUFFER_SIZE) - strnlen(message_copy1,BUFFER_SIZE) + sizeof(BLOCKCHAIN_RESERVED_BYTES_END)-1;
  }
  else
  {
    message_copy1 = strstr((char*)DATA,BLOCKCHAIN_RESERVED_BYTES_DATA_HASH);
    count = strnlen(DATA,BUFFER_SIZE) - strnlen(message_copy1,BUFFER_SIZE) + (sizeof(BLOCKCHAIN_RESERVED_BYTES_DATA_HASH)-1);
  }

  // ringct_version
  blockchain_data.ringct_version_data_length = sizeof(RINGCT_VERSION)-1;
  count+= blockchain_data.ringct_version_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid ringct_version");
  }
  memcpy(blockchain_data.ringct_version_data,&DATA[count-blockchain_data.ringct_version_data_length],blockchain_data.ringct_version_data_length);

  // transaction_amount
  // get how many bytes are left in the network_block_string
  blockchain_data.transaction_amount_data_length = (strnlen(DATA,BUFFER_SIZE) - count) % TRANSACTION_LENGTH;
  count+= blockchain_data.transaction_amount_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid transaction_amount");
  }
  memcpy(blockchain_data.transaction_amount_data,&DATA[count-blockchain_data.transaction_amount_data_length],blockchain_data.transaction_amount_data_length);
  blockchain_data.transaction_amount = varint_decode((size_t)strtol(blockchain_data.transaction_amount_data, NULL, 16));

  // get all of the transactions
  for (number = 0; number < blockchain_data.transaction_amount; number++)
  {
    count+= TRANSACTION_LENGTH;
    if (count > DATA_LENGTH)
    {
      NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string, Invalid transactions");
    }
    memcpy(blockchain_data.transactions[number],&DATA[count-TRANSACTION_LENGTH],TRANSACTION_LENGTH);
  }

  pointer_reset_all;
  return 1;

  #undef pointer_reset_all
  #undef NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR
}

bool t_rpc_command_executor::verify_round_statistics(const std::string block_data)
{
  // Variables
  cryptonote::COMMAND_RPC_GET_BLOCK::request get_block_req;
  cryptonote::COMMAND_RPC_GET_BLOCK::response get_block_res;
  epee::json_rpc::error error_resp;
  crypto::hash block_hash;
  bool hash_parsed;
  char* data = (char*)calloc(1000,sizeof(char));
  char* data2 = (char*)calloc(1000,sizeof(char));
  char* block_height = (char*)calloc(100,sizeof(char));
  char* previous_network_block_reserve_bytes_block_verifiers_public_addresses_data = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* previous_network_block_reserve_bytes_block_verifiers_public_addresses[BLOCK_VERIFIERS_AMOUNT];
  char* message_copy1;
  std::size_t current_block_height;
  std::string network_block_string;
  std::string data_hash;
  std::string reserve_bytes_data;
  std::string string;
  std::string string2;
  std::string message;
  std::size_t count = 0;
  std::size_t count2 = 0;
  std::size_t count3 = 0;
  std::size_t number = 0;

  // define macros
  #define BLOCK_DATA_TOTAL_TEST 19
  #define RESERVE_BYTES_TOTAL_TEST 34

  #define VERIFY_ROUND_STATISTICS_ERROR \
  color_print("Could not get the blocks data","red"); \
  pointer_reset_all; \
  return true;

  #define pointer_reset_all \
  free(data); \
  data = NULL; \
  free(data2); \
  data2 = NULL; \
  free(block_height); \
  block_height = NULL; \
  free(previous_network_block_reserve_bytes_block_verifiers_public_addresses_data); \
  previous_network_block_reserve_bytes_block_verifiers_public_addresses_data = NULL; \
  free(blockchain_data.network_version_data); \
  blockchain_data.network_version_data = NULL; \
  free(blockchain_data.timestamp_data); \
  blockchain_data.timestamp_data = NULL; \
  free(blockchain_data.previous_block_hash_data); \
  blockchain_data.previous_block_hash_data = NULL; \
  free(blockchain_data.block_height_data); \
  blockchain_data.block_height_data = NULL; \
  free(blockchain_data.nonce_data); \
  blockchain_data.nonce_data = NULL; \
  free(blockchain_data.block_reward_transaction_version_data); \
  blockchain_data.block_reward_transaction_version_data = NULL; \
  free(blockchain_data.unlock_block_data); \
  blockchain_data.unlock_block_data = NULL; \
  free(blockchain_data.block_reward_input_data); \
  blockchain_data.block_reward_input_data = NULL; \
  free(blockchain_data.vin_type_data); \
  blockchain_data.vin_type_data = NULL; \
  free(blockchain_data.block_height_data); \
  blockchain_data.block_height_data = NULL; \
  free(blockchain_data.block_reward_output_data); \
  blockchain_data.block_reward_output_data = NULL; \
  free(blockchain_data.block_reward_data); \
  blockchain_data.block_reward_data = NULL; \
  free(blockchain_data.stealth_address_output_tag_data); \
  blockchain_data.stealth_address_output_tag_data = NULL; \
  free(blockchain_data.stealth_address_output_data); \
  blockchain_data.stealth_address_output_data = NULL; \
  free(blockchain_data.extra_bytes_size_data); \
  blockchain_data.extra_bytes_size_data = NULL; \
  free(blockchain_data.transaction_public_key_tag_data); \
  blockchain_data.transaction_public_key_tag_data = NULL; \
  free(blockchain_data.transaction_public_key_data); \
  blockchain_data.transaction_public_key_data = NULL; \
  free(blockchain_data.transaction_public_key_data); \
  blockchain_data.transaction_public_key_data = NULL; \
  free(blockchain_data.extra_nonce_tag_data); \
  blockchain_data.extra_nonce_tag_data = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data); \
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name); \
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data); \
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.block_producer_public_address); \
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data); \
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count); \
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data); \
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names); \
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4); \
  blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4 = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.vrf_data); \
  blockchain_data.blockchain_reserve_bytes.vrf_data = NULL; \
  free(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data); \
  blockchain_data.blockchain_reserve_bytes.previous_block_hash_data = NULL; \
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) \
  { \
    free(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count]); \
    blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count] = NULL; \
    free(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count]); \
    blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count] = NULL; \
    free(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count]); \
    blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count] = NULL; \
    free(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count]); \
    blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count] = NULL; \
  }

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || block_height == NULL)
  {
    if (data != NULL)
    {
      pointer_reset(data);
    }
    if (block_height != NULL)
    {
      pointer_reset(block_height);
    }
    color_print("Could not allocate the memory needed on the heap","red");
    exit(0);
  }

  // initialize the blockchain_data struct 
  blockchain_data.network_version_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.timestamp_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.previous_block_hash_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.nonce_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_reward_transaction_version_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.unlock_block_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_reward_input_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.vin_type_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_height_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_reward_output_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_reward_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.stealth_address_output_tag_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.stealth_address_output_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.extra_bytes_size_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.transaction_public_key_tag_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.transaction_public_key_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.extra_nonce_tag_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.reserve_bytes_size_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));  
  blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4 = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_secret_key_round_part_4 = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4 = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4 = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4 = (char*)calloc(BUFFER_SIZE,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_round_part_4 = (unsigned char*)calloc(BUFFER_SIZE,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4 = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4 = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4 = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4 = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4 = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.previous_block_hash_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));

  // check if the memory needed was allocated on the heap successfully
  if (blockchain_data.network_version_data == NULL || blockchain_data.timestamp_data == NULL || blockchain_data.previous_block_hash_data == NULL || blockchain_data.nonce_data == NULL || blockchain_data.block_reward_transaction_version_data == NULL || blockchain_data.unlock_block_data == NULL || blockchain_data.block_reward_input_data == NULL || blockchain_data.vin_type_data == NULL || blockchain_data.block_height_data == NULL || blockchain_data.block_reward_output_data == NULL || blockchain_data.block_reward_data == NULL || blockchain_data.stealth_address_output_tag_data == NULL || blockchain_data.stealth_address_output_data == NULL || blockchain_data.extra_bytes_size_data == NULL || blockchain_data.transaction_public_key_tag_data == NULL || blockchain_data.transaction_public_key_data == NULL || blockchain_data.extra_nonce_tag_data == NULL || blockchain_data.reserve_bytes_size_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_public_address == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names == NULL || blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4 == NULL || blockchain_data.blockchain_reserve_bytes.vrf_data == NULL || blockchain_data.blockchain_reserve_bytes.previous_block_hash_data == NULL)
  {
    color_print("Could not allocate the memory needed on the heap","red");
    exit(0);
  }
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count] = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count] = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));

    // check if the memory needed was allocated on the heap successfully
    if (blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count] == NULL || blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count] == NULL)
    {
      color_print("Could not allocate the memory needed on the heap","red");
      exit(0);
    }
  }
  blockchain_data.ringct_version_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.transaction_amount_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++)
  {
    blockchain_data.transactions[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_TRANSACTIONS_DATA,sizeof(char));

    // check if the memory needed was allocated on the heap successfully
    if (blockchain_data.transactions[count] == NULL)
    {
      color_print("Could not allocate the memory needed on the heap","red");
      exit(0);
    }
  }

  // initialize the network_data_nodes_list struct
  network_data_nodes_list.network_data_nodes_public_address[0] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_1;
  network_data_nodes_list.network_data_nodes_IP_address[0] = NETWORK_DATA_NODE_IP_ADDRESS_1;
  network_data_nodes_list.network_data_nodes_public_address[1] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_2;
  network_data_nodes_list.network_data_nodes_IP_address[1] = NETWORK_DATA_NODE_IP_ADDRESS_2;

try
{
  // get the height of the block to get the block blob from
  if (block_data.length() == 64)
  {
    // the data is a block hash
    hash_parsed = parse_hash256(block_data, block_hash);
    if(!hash_parsed)
    {
      VERIFY_ROUND_STATISTICS_ERROR;
    }
    // get the block height from the block hash
    get_block_req.hash = epee::string_tools::pod_to_hex(block_hash);
    get_block_req.fill_pow_hash = true;
    if (m_is_rpc)
    {
      if (!m_rpc_client->json_rpc_request(get_block_req, get_block_res, "getblock", "Unsuccessful"))
      {
        VERIFY_ROUND_STATISTICS_ERROR;
      }
    }
    else
    {
      if (!m_rpc_server->on_get_block(get_block_req, get_block_res, error_resp) || get_block_res.status != CORE_RPC_STATUS_OK)
      {
        VERIFY_ROUND_STATISTICS_ERROR;
      }
    }

    // error check
    if (get_block_res.block_header.height < HF_BLOCK_HEIGHT_PROOF_OF_STAKE)
    {
      VERIFY_ROUND_STATISTICS_ERROR;
    }
    sprintf(block_height,"%ld",get_block_res.block_header.height); 
    current_block_height = (std::size_t)get_block_res.block_header.height; 
  }
  else
  {
    // the data is a block height
    sscanf(block_data.c_str(),"%zu",&count);
    // error check
    if (count < HF_BLOCK_HEIGHT_PROOF_OF_STAKE)
    {
      VERIFY_ROUND_STATISTICS_ERROR;
    }
    memcpy(block_height,block_data.c_str(),strnlen(block_data.c_str(),100));
    current_block_height = count;
  } 

  // get the network block string
  sscanf(block_height,"%zu",&get_block_req.height);
  get_block_req.fill_pow_hash = false;
  if (m_is_rpc)
  {
    if (!m_rpc_client->json_rpc_request(get_block_req, get_block_res, "getblock", "Unsuccessful"))
    {
      VERIFY_ROUND_STATISTICS_ERROR;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_block(get_block_req, get_block_res, error_resp) || get_block_res.status != CORE_RPC_STATUS_OK)
    {
      VERIFY_ROUND_STATISTICS_ERROR;
    }
  }
  network_block_string = get_block_res.blob;

  // get the data hash
  data_hash = network_block_string.substr(network_block_string.find(BLOCKCHAIN_RESERVED_BYTES_START)+(sizeof(BLOCKCHAIN_RESERVED_BYTES_START)-1),DATA_HASH_LENGTH);

  // create the message
  message = "{\r\n \"message_settings\": \"NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES\",\r\n \"block_height\": \"" + std::to_string(current_block_height) + "\",\r\n}"; 

  // send the message to a random network data node
  for (count = 0; string != "socket_timeout" || count == MAXIMUM_CONNECTION_TIMEOUT_SETTINGS; count++)
  {
    string = send_and_receive_data(network_data_nodes_list.network_data_nodes_IP_address[(int)(rand() % NETWORK_DATA_NODES_AMOUNT)],message);
  }

  if (count == MAXIMUM_CONNECTION_TIMEOUT_SETTINGS)
  {
    VERIFY_ROUND_STATISTICS_ERROR;
  }

  // verify the message
  if (verify_data(string,0) == 0)
  {    
    VERIFY_ROUND_STATISTICS_ERROR;
  }  

  // create the message
  message = "{\r\n \"message_settings\": \"NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES\",\r\n \"block_height\": \"" + std::to_string(current_block_height - 1) + "\",\r\n}";  

  // send the message to a random network data node
  for (count = 0; string2 != "socket_timeout" || count == MAXIMUM_CONNECTION_TIMEOUT_SETTINGS; count++)
  {
    string2 = send_and_receive_data(network_data_nodes_list.network_data_nodes_IP_address[(int)(rand() % NETWORK_DATA_NODES_AMOUNT)],message);
  }

  if (count == MAXIMUM_CONNECTION_TIMEOUT_SETTINGS)
  {
    VERIFY_ROUND_STATISTICS_ERROR;
  }

  // verify the message
  if (verify_data(string2,0) == 0)
  {
    VERIFY_ROUND_STATISTICS_ERROR;
  }  

  // get the network block string
  string = string.substr(43,string.find("|",43)-43);

  // get the previous_network block string
  string2 = string2.substr(43,string2.find("|",43)-43);

  // check if the data hash matches the network block string
  memset(data,0,strlen(data));
  crypto_hash_sha512((unsigned char*)data,(const unsigned char*)string.c_str(),strlen(string.c_str()));

  // convert the SHA512 data hash to a string
  for (count2 = 0, count = 0; count2 < DATA_HASH_LENGTH / 2; count2++, count += 2)
  {
    sprintf(data2+count,"%02x",data[count2] & 0xFF);
  }

  if (memcmp(data2,data_hash.c_str(),DATA_HASH_LENGTH) != 0)
  {
    VERIFY_ROUND_STATISTICS_ERROR;
  }

  // convert the network_block_string to a blockchain_data struct
  if (network_block_string_to_blockchain_data(string.c_str(),(const char*)block_height) == 0)
  {
    VERIFY_ROUND_STATISTICS_ERROR;
  }

  // print the network block string
  // print the block data, reserve bytes and transactions in a different color
  fprintf(stderr,"\nBlock blob\n\n");
  
  color_print("Block data\n","green");
  color_print("Reserve bytes\n","red");
  color_print("Transactions data\n\n","blue");
    
  count = string.find(BLOCKCHAIN_RESERVED_BYTES_START);
  color_print(string.substr(0,count).c_str(),"green");
  
  count = string.find(BLOCKCHAIN_RESERVED_BYTES_START);
  count2 = string.find(BLOCKCHAIN_RESERVED_BYTES_END) + (sizeof(BLOCKCHAIN_RESERVED_BYTES_END)-1);
  color_print(string.substr(count,count2 - count).c_str(),"red");
    
  color_print(string.substr(count2).c_str(),"blue");
    
  // print each section in the block data
    
  fprintf(stderr,"\n\nBlock data\n\n"); 
 
  color_print(blockchain_data.network_version_data,"green");
  color_print(blockchain_data.timestamp_data,"blue");
  color_print(blockchain_data.previous_block_hash_data,"red");
  color_print(blockchain_data.nonce_data,"green");
  color_print(blockchain_data.block_reward_transaction_version_data,"blue");
  color_print(blockchain_data.unlock_block_data,"red");
  color_print(blockchain_data.block_reward_input_data,"green");
  color_print(blockchain_data.vin_type_data,"blue");
  color_print(blockchain_data.block_height_data,"red");
  color_print(blockchain_data.block_reward_output_data,"green");
  color_print(blockchain_data.block_reward_data,"blue");
  color_print(blockchain_data.stealth_address_output_tag_data,"red");
  color_print(blockchain_data.stealth_address_output_data,"green");
  color_print(blockchain_data.extra_bytes_size_data,"blue");
  color_print(blockchain_data.transaction_public_key_tag_data,"red");
  color_print(blockchain_data.transaction_public_key_data,"green");
  color_print(blockchain_data.extra_nonce_tag_data,"blue");
  color_print(blockchain_data.reserve_bytes_size_data,"red");
  color_print(blockchain_data.ringct_version_data,"green");

  // verify the block data
  fprintf(stderr,"\n\nVerifying block data\n\n");
    
  // write the start test message
  color_print(TEST_OUTLINE,"blue");
  fprintf(stderr,"\n");
  fprintf(stderr,"\033[1;34mVerifying block data - Total test: %d\033[0m\n",BLOCK_DATA_TOTAL_TEST);
  color_print(TEST_OUTLINE,"blue");
  fprintf(stderr,"\n\n");

  fprintf(stderr,"\033[1;32mPASSED! Network Version - Hard fork version 13\033[0m\n\033[1;34mPASSED! Timestamp - %zu\033[0m\n\033[1;31mPASSED! Previous Block Hash\n\033[0m",blockchain_data.timestamp);
 
  if (memcmp(blockchain_data.nonce_data,BLOCK_PRODUCER_NETWORK_BLOCK_NONCE,sizeof(BLOCK_PRODUCER_NETWORK_BLOCK_NONCE)-1) == 0)
  {
    color_print("PASSED! Nonce Data - Created by the block producer\n","green");
  }
  else
  {
    color_print("PASSED! Nonce Data - Created by the consnesus node\n","green");
  }

  color_print("PASSED! Block Reward Transaction Version - Should always be 02\n","blue");

  fprintf(stderr,"\033[1;31mPASSED! Unlock Block - Block %zu\033[0m\n\033[1;32mPASSED! Block Reward Input - Should always be 01\033[0m\n\033[1;34mPASSED! Vin Type - Should always be FF\033[0m\n\033[1;31mPASSED! Block Height - Block %zu\033[0m\n\033[1;32mPASSED! Block Reward Output - Should always be 01\033[0m\n\033[1;34mPASSED! Block Reward - %zu\033[0m\n\033[1;31mPASSED! Stealth Address Output Tag - Should always be 02\033[0m\n\033[1;32mPASSED! Stealth Address Output - %s\033[0m\n\033[1;34mPASSED! Extra Bytes Size - Should always be 163\033[0m\n\033[1;31mPASSED! Transaction Public Key Tag - Should always be 01\033[0m\n\033[1;32mPASSED! Extra Nonce Tag - Should always be 02\033[0m\n\033[1;34mPASSED! Reserve Bytes Size - Should always be 128\033[0m\n\033[1;31mPASSED! Transaction Public Key Tag - Should always be 01\033[0m\n\033[1;32mPASSED! Extra Nonce Tag - Should always be 02\033[0m\n",blockchain_data.unlock_block,blockchain_data.block_height,blockchain_data.block_reward,blockchain_data.stealth_address_output_data); 

  // write the end test message
  fprintf(stderr,"\n");
  color_print(TEST_OUTLINE,"green");
  fprintf(stderr,"\n\033[1;32mVerifying block data - Passed test: %d, Failed test: 0\033[0m\n",BLOCK_DATA_TOTAL_TEST);
  color_print(TEST_OUTLINE,"green");
  fprintf(stderr,"\n\n");

  // print each section in the Reserve Bytes
  fprintf(stderr,"Reserve Bytes\n\n"); 
  
  fprintf(stderr,BLOCKCHAIN_RESERVED_BYTES_START); 
  color_print(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data,"green");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data,"blue");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,"red");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data,"green");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4,"blue");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4,"red");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,"green");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4,"blue");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4,"red");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,"green");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_data,"blue");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count],"red");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count],"green");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count],"blue");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count],"red");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }
  color_print(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,"green");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count],"blue"); if (count+1 != BLOCK_VERIFIERS_AMOUNT)   
    {
      fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
    }
    else
    {
      fprintf(stderr,BLOCKCHAIN_RESERVED_BYTES_END);
    }
  }

  // verify the reserve bytes
  fprintf(stderr,"\n\nVerifying reserve bytes\n\n");

  // write the start test message
  color_print(TEST_OUTLINE,"blue");
  fprintf(stderr,"\n");
  fprintf(stderr,"\033[1;34mVerifying reserve bytes - Total test: %d\033[0m\n",RESERVE_BYTES_TOTAL_TEST);
  color_print(TEST_OUTLINE,"blue");
  fprintf(stderr,"\n\n");

  fprintf(stderr,"\033[1;32mPASSED! Block Producer Delegate Name - %s\033[0m\n\033[1;34mPASSED! Block Producer Public Address - %s\033[0m\n\033[1;31mPASSED! Block Producer Node Backup Count - %s\033[0m\n\033[1;32mPASSED! Block Producer Backup Nodes Names - %s\033[0m\n\033[1;34mPASSED! VRF Secret Key - %s\033[0m\n\033[1;31mVRF Public Key - %s\033[0m\n\033[1;32mPASSED! VRF Alpha String - %s\033[0m\n\033[1;34mPASSED! VRF Proof - %s\033[0m\n\033[1;31mPASSED! VRF Beta String - %s\033[0m\n\033[1;32mPASSED! VRF Data Current Round - %s\033[0m\n\033[1;34mVRF Data - %s\033[0m",blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,blockchain_data.blockchain_reserve_bytes.block_producer_public_address,blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names,blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_data);

  // block_verifiers_vrf_secret_key_data  
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    fprintf(stderr,"\033[0m\n\033[1;31mBlock Verifiers VRF Secret Key %zu - %s\033[0m",count+1,blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count]);
  }

  // block_verifiers_vrf_public_key_data  
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    fprintf(stderr,"\033[0m\n\033[1;32mBlock Verifiers VRF Public Key %zu - %s\033[0m",count+1,blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count]);
  }

  // block_verifiers_random_data  
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    fprintf(stderr,"\033[0m\n\033[1;34mBlock Verifiers Random Data %zu - %s\033[0m",count+1,blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count]);
  }

  // next_block_verifiers_public_address
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    fprintf(stderr,"\033[0m\n\033[1;31mNext Block Verifiers Public Address %zu - %s\033[0m",count+1,blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count]);
  }

  fprintf(stderr,"\033[0m\n\033[1;32mPASSED! Previous Block Hash - %s\033[0m",blockchain_data.blockchain_reserve_bytes.previous_block_hash_data);

  // block_verifiers_signature_data
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    fprintf(stderr,"\033[0m\n\033[1;34mBlock Verifiers Random Data %zu - %s\033[0m",count+1,blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count]);
  }

  // write the end test message
  fprintf(stderr,"\n");
  color_print(TEST_OUTLINE,"green");
  fprintf(stderr,"\n\033[1;32mVerifying reserve bytes - Passed test: %d, Failed test: 0\033[0m\n",RESERVE_BYTES_TOTAL_TEST);
  color_print(TEST_OUTLINE,"green");
  fprintf(stderr,"\n\n");  

  // print each section in the Transaction Data
  fprintf(stderr,"Transaction Data\n"); 
 
  fprintf(stderr,"\033[0m\n\033[1;32mAmount of Transactions - %zu\033[0m",blockchain_data.transaction_amount);
  for (count = 0; count < blockchain_data.transaction_amount; count++)
  {
    fprintf(stderr,"\033[0m\n\033[1;34mTransaction %zu - %s\033[0m",count+1,blockchain_data.transactions[count]);
  }  

  // write the end test message
  fprintf(stderr,"\n");
  color_print(TEST_OUTLINE,"green");
  fprintf(stderr,"\n\033[1;32mVerify Round Statistics - Passed test: %d, Failed test: 0\033[0m\n",BLOCK_DATA_TOTAL_TEST+RESERVE_BYTES_TOTAL_TEST);
  color_print(TEST_OUTLINE,"green");
  fprintf(stderr,"\n\n");
}
catch(...)
{
VERIFY_ROUND_STATISTICS_ERROR;
}

  pointer_reset_all;
  return true;

  #undef pointer_reset_all
  #undef BLOCK_DATA_TOTAL_TEST
  #undef RESERVE_BYTES_TOTAL_TEST
}

}// namespace daemonize


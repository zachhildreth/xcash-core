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

// lengths
#define BUFFER_SIZE 164000
#define BUFFER_SIZE_NETWORK_BLOCK_DATA 500
#define DATA_HASH_LENGTH 128 // The length of the SHA2-512 hash
#define BUFFER_SIZE_NETWORK_BLOCK_TRANSACTIONS_DATA 100
#define XCASH_WALLET_LENGTH 98 // The length of a XCA address

// VRF
#define VRF_PUBLIC_KEY_LENGTH 64
#define VRF_SECRET_KEY_LENGTH 128
#define VRF_PROOF_LENGTH 160
#define VRF_BETA_LENGTH 128
#define VRF_DATA_LENGTH 8 // true when the VRF data is verified

#define XCASH_WALLET_PREFIX "XCA" // The prefix of a XCA address
#define XCASH_SIGN_DATA_PREFIX "SigV1" // The prefix of a xcash_proof_of_stake_signature for the signed data
#define XCASH_SIGN_DATA_LENGTH 93 // The length of a xcash_proof_of_stake_signature for the signed data
#define NETWORK_VERSION "0d0d" // the network version
#define MAXIMUM_TRANSACATIONS_PER_BLOCK 1000000 // The maximum amount of transaction per block
#define TEST_OUTLINE "-----------------------------------------------------------------------------------------------"
#define RESERVE_BYTE_START_STRING "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // The reserve bytes the block producer will create using the get block template
#define GET_BLOCK_TEMPLATE_RESERVED_BYTES "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // This is the place holder data for the block validation signatures. This has to be replaced with all of the block validation signatures when verifiyng the block, since the block validation signatures are added after the block validation nodes sign the place holder block validation node data.
#define BLOCK_PRODUCER_NETWORK_BLOCK_NONCE "00000000" // the network block nonce used when the block producer creates the block
#define NETWORK_DATA_NODE_NETWORK_BLOCK_NONCE "11111111" // the network block nonce used when the network data node creates the block
#define BLOCKCHAIN_RESERVED_BYTES_START "7c424c4f434b434841494e5f52455345525645445f42595445535f53544152547c"
#define BLOCKCHAIN_DATA_SEGMENT_STRING "7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c"
#define BLOCKCHAIN_RESERVED_BYTES_END "7c424c4f434b434841494e5f52455345525645445f42595445535f454e447c"
#define BLOCK_VALIDATION_NODE_SIGNED_BLOCK_LENGTH 186 // The length of the block validation signature

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

#define pointer_reset(pointer) \
free(pointer); \
pointer = NULL;

// Global Structures

struct network_data_nodes_list {
    std::string network_data_nodes_public_address[NETWORK_DATA_NODES_AMOUNT]; // The network data nodes public address
    std::string network_data_nodes_IP_address[NETWORK_DATA_NODES_AMOUNT]; // The network data nodes IP address
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
struct blockchain_data blockchain_data; // The data for a new block to be added to the network.



std::string send_and_receive_data(std::string IP_address,std::string data2)
{
  // Variables
  boost::asio::io_service http_service;
  boost::asio::streambuf message;

  // send the data to the server
  tcp::resolver resolver(http_service);
  tcp::resolver::query query(IP_address, SEND_DATA_PORT);
  tcp::resolver::iterator data = resolver.resolve(query);
  tcp::socket socket(http_service);
  boost::asio::connect(socket, data);

  std::ostream http_request(&message);
  http_request << data2;
 
  // send the message and read the response
  boost::asio::write(socket, message);
  boost::asio::streambuf response;
  boost::asio::read_until(socket, response, SOCKET_END_STRING);
  std::istream response_stream(&response);
  std::string string;
  response_stream >> string;
  return string;
}



size_t string_count(const char* DATA, const char* STRING)
{
  // Constants
  const size_t STRING_LENGTH = strnlen(STRING,BUFFER_SIZE);
  
  // Variables
  char* datacopy1 = (char*)calloc(BUFFER_SIZE,sizeof(char)); 
  // since were going to be changing where datacopy1 is referencing, we need to create a copy to pointer_reset
  char* datacopy2 = datacopy1; 
  size_t count = 0;

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
    datacopy1+= STRING_LENGTH;
  } 

  pointer_reset(datacopy2);
  return count;
}

int string_replace(char *data, const char* STR1, const char* STR2)
{  
  // check if the str to replace exist in the string
  if (strstr(data,STR1) != NULL)
  { 
    // Variables
    char* datacopy = (char*)calloc(BUFFER_SIZE,sizeof(char));
    char* string;
    size_t data_length;
    size_t str2_length;
    size_t start;
    size_t total = 0;
    size_t count = 0; 

    // define macros
    #define REPLACE_STRING "|REPLACE_STRING|" 

    // check if the memory needed was allocated on the heap successfully
    if (datacopy == NULL)
    {
      color_print("Could not allocate the memory needed on the heap","red");
      exit(0);
    } 

    // get the occurences of STR1   
    total = string_count(data,(char*)STR1);

    // replace the string with the REPLACE_STRING
    for (count = 0; count < total; count++)
    {
      // reset the variables
      memset(datacopy,0,strnlen(datacopy,BUFFER_SIZE));
      data_length = strnlen(data,BUFFER_SIZE);
      str2_length = strnlen(REPLACE_STRING,BUFFER_SIZE);
      start = data_length - strnlen(strstr(data,STR1),BUFFER_SIZE);
   
      // get a pointer to where the rest of the data string should be copied to
      string = strstr(data,STR1)+strnlen(STR1,BUFFER_SIZE);
           
      // copy the bytes before STR1 to the new string
      memcpy(datacopy,data,start);
      // copy STR2 to the new string
      memcpy(datacopy+start,REPLACE_STRING,str2_length);
      // copy the bytes after STR1 to the new string
      memcpy(datacopy+start+str2_length,string,strnlen(string,BUFFER_SIZE));
      // copy the new string to the string pointer
      memset(data,0,data_length);
      memcpy(data,datacopy,strnlen(datacopy,BUFFER_SIZE));
    }
    // replace the REPLACE_STRING with STR2
    for (count = 0; count < total; count++)
    {
      // reset the variables
      memset(datacopy,0,strnlen(datacopy,BUFFER_SIZE));
      data_length = strnlen(data,BUFFER_SIZE);
      str2_length = strnlen(STR2,BUFFER_SIZE);
      start = data_length - strnlen(strstr(data,REPLACE_STRING),BUFFER_SIZE);
   
      // get a pointer to where the rest of the data string should be copied to
      string = strstr(data,REPLACE_STRING)+strnlen(REPLACE_STRING,BUFFER_SIZE);
           
      // copy the bytes before REPLACE_STRING to the new string
      memcpy(datacopy,data,start);
      // copy STR2 to the new string
      memcpy(datacopy+start,STR2,str2_length);
      // copy the bytes after REPLACE_STRING to the new string
      memcpy(datacopy+start+str2_length,string,strnlen(string,BUFFER_SIZE));
      // copy the new string to the string pointer
      memset(data,0,data_length);
      memcpy(data,datacopy,strnlen(datacopy,BUFFER_SIZE));
    }
    pointer_reset(datacopy);
    return 1;
  }
  else
  {
    return 0;
  } 

  #undef REPLACE_STRING
}

int varint_encode(long long int number, char* result)
{
  // Variables
  char* data = (char*)calloc(BUFFER_SIZE,sizeof(char));
  size_t length;
  size_t count = 0;
  size_t count2 = 0;
  int binary_numbers[8];
  int binary_number_copy;
  long long int number_copy = (long long int)number;  

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL)
  {     
    color_print("Could not allocate the memory needed on the heap","red");  
    pointer_reset(data); 
    exit(0);
  } 

  memset(result,0,strlen(result));  

  // check if it should not be encoded
  if (number <= 0xFF)
  {
    sprintf(result,"%02llx",number);
    pointer_reset(data);
    return 1;
  }

  // convert the number to a binary string
  for (count = 0; number_copy != 0; count++)
  {
    if (number_copy % 2 == 1)
    {
      memcpy(data+count,"1",1);
    }
    else
    {
      memcpy(data+count,"0",1);
    }
    number_copy /= 2; 
  }

  // pad the string to a mulitple of 7 bits  
  for (count = strnlen(data,BUFFER_SIZE); count % 7 != 0; count++)
  {
    memcpy(result+strnlen(result,BUFFER_SIZE),"0",1);
  }

  // reverse the string
  length = strnlen(data,BUFFER_SIZE);
  for (count = 0; count <= length; count++)
  {
    memcpy(result+strnlen(result,BUFFER_SIZE),&data[length - count],1);
  }
  memset(data,0,strnlen(data,BUFFER_SIZE));
  memcpy(data,result,strnlen(result,BUFFER_SIZE));
  memset(result,0,strnlen(result,BUFFER_SIZE));

  /*
  convert each 7 bits to one byte
  set the first bit to 1 for all groups of 7 except for the first group of 7
  */
  length = strnlen(data,BUFFER_SIZE) + (strnlen(data,BUFFER_SIZE) / 7);
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
   if (count % 8 == 0)
   {
     if (count == 0)
     {
       // clear the binary bit to 0
       binary_numbers[count2] &= ~(1 << (count % 8));      
     }
     else
     {
       // set the binary bit to 1
       binary_numbers[count2] |= 1 << (count % 8);
     }
   }
   else
   {
     if (memcmp(data + (count - (count2+1)),"1",1) == 0)
     {
       // set the binary bit to 1
       binary_numbers[count2] |= 1 << (count % 8);
     }
     else
     {
       // clear the binary bit to 0
       binary_numbers[count2] &= ~(1 << (count % 8));
     }     
   }
 }

  // reverse the last binary_number
  length = strnlen(data,BUFFER_SIZE) / 8;
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

  pointer_reset(data);
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
    bytes[count] = ((varint >> (8 * count)) & 0xFF);
  }
    
  for (count = 0, counter = 7, bytecount = 0, start = 0; count < length * 8; count++)
  {
    // loop through each bit until you find the first 1. for every bit after this:
    // if 0 then number = number * 2;
    // if 1 then number = (number * 2) + 1;
    // dont use the bit if its the first bit
    if (counter != 7)
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
      counter = 7;
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

  if (DATA_SIGNATURE.size() < 5 || DATA_SIGNATURE.substr(0, 5) != "SigV1")
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

int verify_data(const std::string MESSAGE)
{
// Constants
const std::string public_address = MESSAGE.substr(MESSAGE.find("XCA"),XCASH_WALLET_LENGTH);
const std::string xcash_proof_of_stake_signature = MESSAGE.substr(MESSAGE.find("SigV1"),93);

// Variables
int count;
int settings;

// check if the public address is in the network_data_nodes_list struct
for (count = 0, settings = 0; count < NETWORK_DATA_NODES_AMOUNT; count++)
{
if (network_data_nodes_list.network_data_nodes_public_address[count] == public_address)
{
settings = 1;
}
}
if (settings != 1)
{
return 0;
}
return data_verify(public_address,xcash_proof_of_stake_signature,MESSAGE.substr(0,MESSAGE.length()-134)+"}");
}

int network_block_string_to_blockchain_data(const char* DATA, const char* BLOCK_HEIGHT)
{
  // Constants
  const size_t DATA_LENGTH = strnlen(DATA,BUFFER_SIZE);

  // Variables
  size_t count;
  size_t count2;
  size_t count3;
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
  blockchain_data.network_version_data_length = 4;
  count+= blockchain_data.network_version_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid network_version\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.network_version_data,DATA,blockchain_data.network_version_data_length);

  // timestamp
  blockchain_data.timestamp_data_length = 10;
  count+= blockchain_data.timestamp_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid timestamp\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.timestamp_data,&DATA[count-blockchain_data.timestamp_data_length],blockchain_data.timestamp_data_length);
  blockchain_data.timestamp = varint_decode((size_t)strtol(blockchain_data.timestamp_data, NULL, 16));

  // previous_block_hash
  blockchain_data.previous_block_hash_data_length = 64;
  count+= blockchain_data.previous_block_hash_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid previous_block_hash\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.previous_block_hash_data,&DATA[count-blockchain_data.previous_block_hash_data_length],blockchain_data.previous_block_hash_data_length);

  // nonce
  blockchain_data.nonce_data_length = 8;
  count+= blockchain_data.nonce_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid nonce\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.nonce_data,&DATA[count-blockchain_data.nonce_data_length],blockchain_data.nonce_data_length);

  // block_reward_transaction_version
  blockchain_data.block_reward_transaction_version_data_length = 2;
  count+= blockchain_data.block_reward_transaction_version_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid block_reward_transaction_version\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.block_reward_transaction_version_data,&DATA[count-blockchain_data.block_reward_transaction_version_data_length],blockchain_data.block_reward_transaction_version_data_length);

  // unlock_block
  // get the current block height
  sscanf(BLOCK_HEIGHT, "%zu", &number);
  number += 60;


  if (number > 2097091)
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
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid unlock_block\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.unlock_block_data,&DATA[count-blockchain_data.unlock_block_data_length],blockchain_data.unlock_block_data_length);
  blockchain_data.unlock_block = varint_decode((size_t)strtol(blockchain_data.unlock_block_data, NULL, 16));

  // block_reward_input
  blockchain_data.block_reward_input_data_length = 2;
  count+= blockchain_data.block_reward_input_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid block_reward_input\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.block_reward_input_data,&DATA[count-blockchain_data.block_reward_input_data_length],blockchain_data.block_reward_input_data_length);

  // vin_type
  blockchain_data.vin_type_data_length = 2;
  count+= blockchain_data.vin_type_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid vin_type\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.vin_type_data,&DATA[count-blockchain_data.vin_type_data_length],blockchain_data.vin_type_data_length);

  // block_height
  sscanf(current_block_height, "%zu", &number);
  number += 1;

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
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid block_height\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.block_height_data,&DATA[count-blockchain_data.block_height_data_length],blockchain_data.block_height_data_length);
  blockchain_data.block_height = varint_decode((size_t)strtol(blockchain_data.block_height_data, NULL, 16));

  // block_reward_output
  blockchain_data.block_reward_output_data_length = 2;
  count+= blockchain_data.block_reward_output_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid block_reward_output\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.block_reward_output_data,&DATA[count-blockchain_data.block_reward_output_data_length],blockchain_data.block_reward_output_data_length);

  // block_reward
  // since the block reward could be any number because of transactions fees, get the position of BLOCKCHAIN_RESERVED_BYTES_START to get the length of the block reward
  data3 = strstr((char*)DATA,BLOCKCHAIN_RESERVED_BYTES_START);
  if (data3 == NULL)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid block_reward\nFunction: network_block_string_to_blockchain_data");
  }
  blockchain_data.block_reward_data_length = strnlen(DATA,BUFFER_SIZE) - strnlen(data3,BUFFER_SIZE) - count - 138;
  count+= blockchain_data.block_reward_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid block_reward\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.block_reward_data,&DATA[count-blockchain_data.block_reward_data_length],blockchain_data.block_reward_data_length);
  blockchain_data.block_reward = varint_decode((size_t)strtol(blockchain_data.block_reward_data, NULL, 16));

  // stealth_address_output_tag
  blockchain_data.stealth_address_output_tag_data_length = 2;
  count+= blockchain_data.stealth_address_output_tag_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid stealth_address_output_tag\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.stealth_address_output_tag_data,&DATA[count-blockchain_data.stealth_address_output_tag_data_length],blockchain_data.stealth_address_output_tag_data_length);

  // stealth_address_output
  blockchain_data.stealth_address_output_data_length = 64;
  count+= blockchain_data.stealth_address_output_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid stealth_address_output\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.stealth_address_output_data,&DATA[count-blockchain_data.stealth_address_output_data_length],blockchain_data.stealth_address_output_data_length);

  // extra_bytes_size
  blockchain_data.extra_bytes_size_data_length = 2;
  count+= blockchain_data.extra_bytes_size_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid extra_bytes_size\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.extra_bytes_size_data,&DATA[count-blockchain_data.extra_bytes_size_data_length],blockchain_data.extra_bytes_size_data_length);
  blockchain_data.extra_bytes_size = varint_decode((size_t)strtol(blockchain_data.extra_bytes_size_data, NULL, 16));

  // transaction_public_key_tag
  blockchain_data.transaction_public_key_tag_data_length = 2;
  count+= blockchain_data.transaction_public_key_tag_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid transaction_public_key_tag\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.transaction_public_key_tag_data,&DATA[count-blockchain_data.transaction_public_key_tag_data_length],blockchain_data.transaction_public_key_tag_data_length);

  // transaction_public_key
  blockchain_data.transaction_public_key_data_length = 64;
  count+= blockchain_data.transaction_public_key_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid transaction_public_key\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.transaction_public_key_data,&DATA[count-blockchain_data.transaction_public_key_data_length],blockchain_data.transaction_public_key_data_length);

  // extra_nonce_tag
  blockchain_data.extra_nonce_tag_data_length = 2;
  count+= blockchain_data.extra_nonce_tag_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid extra_nonce_tag\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.extra_nonce_tag_data,&DATA[count-blockchain_data.extra_nonce_tag_data_length],blockchain_data.extra_nonce_tag_data_length);

  // reserve_bytes_size
  blockchain_data.reserve_bytes_size_data_length = 2;
  count+= blockchain_data.reserve_bytes_size_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid reserve_bytes_size\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.reserve_bytes_size_data,&DATA[count-blockchain_data.reserve_bytes_size_data_length],blockchain_data.reserve_bytes_size_data_length);
  blockchain_data.reserve_bytes_size = varint_decode((size_t)strtol(blockchain_data.reserve_bytes_size_data, NULL, 16));


  // blockchain_reserve_bytes
  // skip the BLOCKCHAIN_RESERVED_BYTES_START
  count+= 66;

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
  count += blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length + 64;
  
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
  count += blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length + 64;
  
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
  count += blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length + 64;

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
  count += blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length + 64;

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
  count += blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_length_round_part_4 + 64;

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
  count += blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4 + 64;

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
  count += blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4 + 64;

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
  count += blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4 + 64;

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
  count += blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4 + 64;

  // vrf_data_round_part_4
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,&DATA[count],VRF_DATA_LENGTH);
  count += VRF_DATA_LENGTH + 64;

  // vrf_data
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_data,&DATA[count],VRF_DATA_LENGTH);
  count += VRF_DATA_LENGTH + 64;

  // block_verifiers_vrf_secret_key_data
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length = VRF_SECRET_KEY_LENGTH;
  for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++)
  { 
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count3],&DATA[count],blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length + 64;
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
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data_length + 64;
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
  blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length = 200;
  for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++)
  { 
    memset(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count3],0,strlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count3]));
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count3],&DATA[count],blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length + 64;
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
    count += blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data_length + 64;
    // convert the hexadecimal string to a string
    for (number = 0, count2 = 0; number < blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data_length; count2++, number += 2)
    {
      memset(data2,0,strnlen(data2,BUFFER_SIZE));
      memcpy(data2,&blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count3][number],2);
      blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count3][count2] = (int)strtol(data2, NULL, 16);
    }
  }
  count += 64;

  // previous block hash
  blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length = 64;
  memcpy(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,blockchain_data.previous_block_hash_data,blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length);
  count += blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length + 64;

  // block_validation_node_signature_data
  message_copy1 = strstr((char*)DATA+count,BLOCKCHAIN_DATA_SEGMENT_STRING);
  blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length = (strlen(DATA) - strlen(message_copy1)) - count;
  
  size_t count5 = string_count(DATA,"5369675631");
  for (count3 = 0; count3 < count5; count3++)
  { 
    memcpy(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count3],&DATA[count],blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length + 64;
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
  count = strnlen(DATA,BUFFER_SIZE) - strnlen(message_copy1,BUFFER_SIZE) + 62;

  // ringct_version
  blockchain_data.ringct_version_data_length = 2;
  count+= blockchain_data.ringct_version_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid ringct_version\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.ringct_version_data,&DATA[count-blockchain_data.ringct_version_data_length],blockchain_data.ringct_version_data_length);

  // transaction_amount
  // get how many bytes are left in the network_block_string
  blockchain_data.transaction_amount_data_length = (strnlen(DATA,BUFFER_SIZE) - count) % 64;
  count+= blockchain_data.transaction_amount_data_length;
  if (count > DATA_LENGTH)
  {
    NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid transaction_amount\nFunction: network_block_string_to_blockchain_data");
  }
  memcpy(blockchain_data.transaction_amount_data,&DATA[count-blockchain_data.transaction_amount_data_length],blockchain_data.transaction_amount_data_length);
  blockchain_data.transaction_amount = varint_decode((size_t)strtol(blockchain_data.transaction_amount_data, NULL, 16));

  // get all of the transactions
  for (number = 0; number < blockchain_data.transaction_amount; number++)
  {
    count+= 64;
    if (count > DATA_LENGTH)
    {
      NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR("Invalid network_block_string\nInvalid transactions\nFunction: network_block_string_to_blockchain_data");
    }
    memcpy(blockchain_data.transactions[number],&DATA[count-64],64);
  }

  pointer_reset_all;
  return 1;

  #undef pointer_reset_all
  #undef NETWORK_BLOCK_STRING_TO_BLOCKCHAIN_DATA_ERROR
}

int blockchain_data_to_network_block_string(char* result)
{
  // Variables
  size_t count = 0;
  size_t count2 = 0;
  size_t counter = 0;

  // define macros  
  #define BLOCKCHAIN_RESERVED_BYTES_LENGTH_TEXT "7c424c4f434b434841494e5f52455345525645445f42595445535f4c454e4754487c"
  #define BLOCKCHAIN_EXTRA_BYTES_LENGTH_TEXT "7c424c4f434b434841494e5f45585452415f42595445535f4c454e4754487c"
  #define BLOCKCHAIN_DATA_TO_NETWORK_BLOCK_ERROR(settings) \
  color_print(settings,"red"); \
  return 0; 

  memset(result,0,strlen(result));
  
  // network_version
  count = 0;
  blockchain_data.network_version_data_length = strnlen(blockchain_data.network_version_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.network_version_data,blockchain_data.network_version_data_length);
  count += blockchain_data.network_version_data_length;
  
  // timestamp
  if (varint_encode((long long int)blockchain_data.timestamp,blockchain_data.timestamp_data) == 0)
  {
    BLOCKCHAIN_DATA_TO_NETWORK_BLOCK_ERROR("Could not create the varint for the timestamp\nFunction: blockchain_data_to_network_block_string");
  }
  blockchain_data.timestamp_data_length = strnlen(blockchain_data.timestamp_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.timestamp_data,blockchain_data.timestamp_data_length);  
  count += blockchain_data.timestamp_data_length;

  // previous_block_hash
  blockchain_data.previous_block_hash_data_length = strnlen(blockchain_data.previous_block_hash_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.previous_block_hash_data,blockchain_data.previous_block_hash_data_length);
  count += blockchain_data.previous_block_hash_data_length;

  // nonce
  blockchain_data.nonce_data_length = strnlen(blockchain_data.nonce_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.nonce_data,blockchain_data.nonce_data_length);
  count += blockchain_data.nonce_data_length;

  // block_reward_transaction_version
  blockchain_data.block_reward_transaction_version_data_length = strnlen(blockchain_data.block_reward_transaction_version_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.block_reward_transaction_version_data,blockchain_data.block_reward_transaction_version_data_length);
  count += blockchain_data.block_reward_transaction_version_data_length;

  // unlock_block
  if (varint_encode((long long int)blockchain_data.unlock_block,blockchain_data.unlock_block_data) == 0)
  {
    BLOCKCHAIN_DATA_TO_NETWORK_BLOCK_ERROR("Could not create the varint for the timestamp\nFunction: blockchain_data_to_network_block_string");
  }
  blockchain_data.unlock_block_data_length = strnlen(blockchain_data.unlock_block_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.unlock_block_data,blockchain_data.unlock_block_data_length);  
  count += blockchain_data.unlock_block_data_length;

  // block_reward_input
  blockchain_data.block_reward_input_data_length = strnlen(blockchain_data.block_reward_input_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.block_reward_input_data,blockchain_data.block_reward_input_data_length);
  count += blockchain_data.block_reward_input_data_length;

  // vin_type
  blockchain_data.vin_type_data_length = strnlen(blockchain_data.vin_type_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.vin_type_data,blockchain_data.vin_type_data_length);
  count += blockchain_data.vin_type_data_length;

  // block_height
  if (varint_encode((long long int)blockchain_data.block_height,blockchain_data.block_height_data) == 0)
  {
    BLOCKCHAIN_DATA_TO_NETWORK_BLOCK_ERROR("Could not create the varint for the block height\nFunction: blockchain_data_to_network_block_string");
  }
  blockchain_data.block_height_data_length = strnlen(blockchain_data.block_height_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.block_height_data,blockchain_data.block_height_data_length);  
  count += blockchain_data.block_height_data_length;

  // block_reward_output
  blockchain_data.block_reward_output_data_length = strnlen(blockchain_data.block_reward_output_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.block_reward_output_data,blockchain_data.block_reward_output_data_length);
  count += blockchain_data.block_reward_output_data_length;

  // block_reward
  if (varint_encode((long long int)blockchain_data.block_reward,blockchain_data.block_reward_data) == 0)
  {
    BLOCKCHAIN_DATA_TO_NETWORK_BLOCK_ERROR("Could not create the varint for the block reward\nFunction: blockchain_data_to_network_block_string");
  }
  blockchain_data.block_reward_data_length = strnlen(blockchain_data.block_reward_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.block_reward_data,blockchain_data.block_reward_data_length);  
  count += blockchain_data.block_reward_data_length;

  // stealth_address_output_tag
  blockchain_data.stealth_address_output_tag_data_length = strnlen(blockchain_data.stealth_address_output_tag_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.stealth_address_output_tag_data,blockchain_data.stealth_address_output_tag_data_length);
  count += blockchain_data.stealth_address_output_tag_data_length;

  // stealth_address_output
  blockchain_data.stealth_address_output_data_length = strnlen(blockchain_data.stealth_address_output_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.stealth_address_output_data,blockchain_data.stealth_address_output_data_length);
  count += blockchain_data.stealth_address_output_data_length;

  // extra_bytes_size
  memset(blockchain_data.extra_bytes_size_data,0,strlen(blockchain_data.extra_bytes_size_data));
  memcpy(blockchain_data.extra_bytes_size_data,"a3",2);
  blockchain_data.extra_bytes_size = 163;
  blockchain_data.extra_bytes_size_data_length = 2;
  memcpy(result+count,blockchain_data.extra_bytes_size_data,blockchain_data.extra_bytes_size_data_length);
  count += blockchain_data.extra_bytes_size_data_length;

  // transaction_public_key_tag
  blockchain_data.transaction_public_key_tag_data_length = strnlen(blockchain_data.transaction_public_key_tag_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.transaction_public_key_tag_data,blockchain_data.transaction_public_key_tag_data_length);
  count += blockchain_data.transaction_public_key_tag_data_length;

  // transaction_public_key
  blockchain_data.transaction_public_key_data_length = strnlen(blockchain_data.transaction_public_key_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.transaction_public_key_data,blockchain_data.transaction_public_key_data_length);
  count += blockchain_data.transaction_public_key_data_length;

  // extra_nonce_tag
  blockchain_data.extra_nonce_tag_data_length = strnlen(blockchain_data.extra_nonce_tag_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.extra_nonce_tag_data,blockchain_data.extra_nonce_tag_data_length);
  count += blockchain_data.extra_nonce_tag_data_length;

  // reserve_bytes_size
  memset(blockchain_data.reserve_bytes_size_data,0,strlen(blockchain_data.reserve_bytes_size_data));
  memcpy(blockchain_data.reserve_bytes_size_data,"80",2);
  blockchain_data.reserve_bytes_size = 128;
  blockchain_data.reserve_bytes_size_data_length = 2;
  memcpy(result+count,blockchain_data.reserve_bytes_size_data,blockchain_data.reserve_bytes_size_data_length);
  count += blockchain_data.reserve_bytes_size_data_length;

  // blockchain_reserve_bytes
  memcpy(result+count,BLOCKCHAIN_RESERVED_BYTES_START,66);
  count+= 66;  

  // block_producer_delegates_name  
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length = strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  // convert the string to hexadecimal
  for (count2 = 0, counter = 0; count2 < blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length; count2++, counter += 2)
  {
    sprintf(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data+counter,"%02x",blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name[count2] & 0xFF);
  }
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length *= 2;
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data,blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length);  
  count += blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // block_producer_public_address  
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length = strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  // convert the string to hexadecimal
  for (count2 = 0, counter = 0; count2 < blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length; count2++, counter += 2)
  {
    sprintf(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data+counter,"%02x",blockchain_data.blockchain_reserve_bytes.block_producer_public_address[count2] & 0xFF);
  }
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length *= 2;
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data,blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length);  
  count += blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64; 

  // block_producer_node_backup_count
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length = strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  // convert the string to hexadecimal
  if (memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"0",1) == 0)
  {
    memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,"30",2);
  }
  if (memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"1",1) == 0)
  {
    memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,"31",2);
  }
  if (memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"2",1) == 0)
  {
    memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,"32",2);
  }
  if (memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"3",1) == 0)
  {
    memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,"33",2);
  }
  if (memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"4",1) == 0)
  {
    memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,"34",2);
  }
  if (memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"5",1) == 0)
  {
    memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,"35",2);
  }
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length = 2;
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data,blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length);  
  count += blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;  

  // block_producer_backup_nodes_names
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length = strnlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  // convert the string to hexadecimal
  for (count2 = 0, counter = 0; count2 < blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length; count2++, counter += 2)
  {
    sprintf(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data+counter,"%02x",blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names[count2] & 0xFF);
  }
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length *= 2;
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data,blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length);  
  count += blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // vrf_secret_key_round_part_4
  blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_length_round_part_4 = strnlen(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4,VRF_SECRET_KEY_LENGTH);
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_length_round_part_4);
  count += blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_length_round_part_4;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // vrf_public_key_round_part_4
  blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4 = strnlen(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4,VRF_PUBLIC_KEY_LENGTH);
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4);
  count += blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // vrf_alpha_string_round_part_4
  blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4 = strnlen(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,BUFFER_SIZE);
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4);
  count += blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4; 
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // vrf_proof_round_part_4
  blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4 = strnlen(blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4,VRF_PROOF_LENGTH);
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4);
  count += blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4;  
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // vrf_beta_string_round_part_4
  blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4 = strnlen(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4,VRF_BETA_LENGTH);
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4,blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4);
  count += blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // vrf_data_round_part_4
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,"74727565",VRF_DATA_LENGTH);
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,VRF_DATA_LENGTH);
  count += VRF_DATA_LENGTH;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // vrf_data
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_data,"74727565",VRF_DATA_LENGTH);
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.vrf_data,VRF_DATA_LENGTH);
  count += VRF_DATA_LENGTH;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // block_verifiers_vrf_secret_key_data  
  for (count2 = 0; count2 < BLOCK_VERIFIERS_AMOUNT; count2++)
  {
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length = strnlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count2],VRF_SECRET_KEY_LENGTH);
    memcpy(result+count,blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count2],blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data_length;
    memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
    count += 64;
  }

  // block_verifiers_vrf_public_key_data  
  for (count2 = 0; count2 < BLOCK_VERIFIERS_AMOUNT; count2++)
  {
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data_length = strnlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count2],VRF_PUBLIC_KEY_LENGTH);
    memcpy(result+count,blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count2],blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data_length;
    memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
    count += 64;
  }

  // block_verifiers_random_data  
  for (count2 = 0; count2 < BLOCK_VERIFIERS_AMOUNT; count2++)
  {
    blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length = strnlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count2],200);
    memcpy(result+count,blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count2],blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length);
    count += blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_length;
    memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
    count += 64;
  }

  // next_block_verifiers_public_address_data  
  blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data_length = 196;
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    // convert the string to hexadecimal
    for (count2 = 0, counter = 0; count2 < XCASH_WALLET_LENGTH; count2++, counter += 2)
    {
      sprintf(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count]+counter,"%02x",blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count][count2] & 0xFF);
    }
    memcpy(result+strnlen(result,BUFFER_SIZE),blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count],blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data_length);  
    if (count+1 != BLOCK_VERIFIERS_AMOUNT)
    {
      memcpy(result+strnlen(result,BUFFER_SIZE),BLOCKCHAIN_DATA_SEGMENT_STRING,64);
    }
  }    
  count = strnlen(result,BUFFER_SIZE);
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // previous block hash
  blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length = strnlen(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length);
  count += blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length;
  memcpy(result+count,BLOCKCHAIN_DATA_SEGMENT_STRING,64);
  count += 64;

  // block_validation_node_signature_data  
  blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length = BLOCK_VALIDATION_NODE_SIGNED_BLOCK_LENGTH;
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    // convert the string to hexadecimal
    for (count2 = 0, counter = 0; count2 < XCASH_SIGN_DATA_LENGTH; count2++, counter += 2)
    {
      sprintf(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count]+counter,"%02x",blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count][count2] & 0xFF);
    }
    memcpy(result+strnlen(result,BUFFER_SIZE),blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count],blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data_length);  
    if (count+1 != BLOCK_VERIFIERS_AMOUNT)
    {
      memcpy(result+strnlen(result,BUFFER_SIZE),BLOCKCHAIN_DATA_SEGMENT_STRING,64);
    }
  }  
  count = strnlen(result,BUFFER_SIZE);
  memcpy(result+count,BLOCKCHAIN_RESERVED_BYTES_END,62);
  count += 62;

  // ringct_version
  blockchain_data.ringct_version_data_length = strnlen(blockchain_data.ringct_version_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.ringct_version_data,blockchain_data.ringct_version_data_length);
  count += blockchain_data.ringct_version_data_length;

  // transaction_amount
  if (varint_encode((long long int)blockchain_data.transaction_amount,blockchain_data.transaction_amount_data) == 0)
  {
    BLOCKCHAIN_DATA_TO_NETWORK_BLOCK_ERROR("Could not create the varint for the transaction amount\nFunction: blockchain_data_to_network_block_string");
  }
  blockchain_data.transaction_amount_data_length = strnlen(blockchain_data.transaction_amount_data,BUFFER_SIZE_NETWORK_BLOCK_DATA);
  memcpy(result+count,blockchain_data.transaction_amount_data,blockchain_data.transaction_amount_data_length);  
  count += blockchain_data.transaction_amount_data_length;

  // get all of the transactions
  for (count2 = 0; count2 < blockchain_data.transaction_amount; count2++)
  {
    memcpy(result+count,blockchain_data.transactions[count2],64);
    count += 64;
  }

  return 1;

  #undef BLOCKCHAIN_RESERVED_BYTES_LENGTH_TEXT
  #undef BLOCKCHAIN_EXTRA_BYTES_LENGTH_TEXT
  #undef BLOCKCHAIN_DATA_TO_NETWORK_BLOCK_ERROR
}

int verify_network_block_data(const char* BLOCK_HEIGHT, const char* PREVIOUS_BLOCK_HASH, const char* PREVIOUS_NETWORK_BLOCK_RESERVE_BYTES)
{
  // Variables
  size_t count;
  int counter;
  size_t count2;
  size_t count3;
  size_t number;
  char* previous_block_hash = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* current_block_height = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* data = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* data2 = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* network_block_string = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* previous_network_block_reserve_bytes_block_verifiers_public_addresses_data = (char*)calloc(BUFFER_SIZE,sizeof(char));
  char* previous_network_block_reserve_bytes_block_verifiers_public_addresses[BLOCK_VERIFIERS_AMOUNT];
  char* message_copy1;

  // define macros
  #define BLOCK_REWARD_TRANSACTION_VERSION "02"
  #define BLOCK_REWARD_INPUT "01"
  #define VIN_TYPE "ff"
  #define BLOCK_REWARD_OUTPUT "01"
  #define STEALTH_ADDRESS_OUTPUT_TAG "02"
  #define TRANSACTION_PUBLIC_KEY_TAG "01"
  #define EXTRA_NONCE_TAG "02"
  #define RINGCT_VERSION "00"
  #define BLOCK_VALIDATION_NODE_SIGNATURE_DATA "7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631"

  #define pointer_reset_all \
  free(previous_block_hash); \
  previous_block_hash = NULL; \
  free(current_block_height); \
  current_block_height = NULL; \
  free(data); \
  data = NULL; \
  free(data2); \
  data2 = NULL; \
  free(network_block_string); \
  network_block_string = NULL; \
  free(previous_network_block_reserve_bytes_block_verifiers_public_addresses_data); \
  previous_network_block_reserve_bytes_block_verifiers_public_addresses_data = NULL;

  #define VERIFY_NETWORK_BLOCK_DATA_ERROR(settings) \
  color_print(settings,"red"); \
  pointer_reset_all; \
  return 0; 

  // check if the memory needed was allocated on the heap successfully
  if (previous_block_hash == NULL || current_block_height == NULL || data == NULL || data2 == NULL || network_block_string == NULL || previous_network_block_reserve_bytes_block_verifiers_public_addresses_data == NULL)
  {
    if (previous_block_hash != NULL)
    {
      pointer_reset(previous_block_hash);
    }
    if (current_block_height != NULL)
    {
      pointer_reset(current_block_height);
    }
    if (data != NULL)
    {
      pointer_reset(data);
    }
    if (data2 != NULL)
    {
      pointer_reset(data2);
    }
    if (network_block_string != NULL)
    {
      pointer_reset(network_block_string);
    }
    if (previous_network_block_reserve_bytes_block_verifiers_public_addresses_data != NULL)
    {
      pointer_reset(previous_network_block_reserve_bytes_block_verifiers_public_addresses_data);
    }
    color_print("Could not allocate the memory needed on the heap","red");
    exit(0);
  }   

  // network_version
  if (blockchain_data.network_version_data_length != 4 || memcmp(blockchain_data.network_version_data,NETWORK_VERSION,4) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid network_version\nFunction: verify_network_block_data");
  } 

  // timestamp
  if (blockchain_data.timestamp_data_length != 10)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid timestamp\nFunction: verify_network_block_data");
  }

  // previous_block_hash
  if (blockchain_data.previous_block_hash_data_length != 64 || memcmp(blockchain_data.previous_block_hash_data,PREVIOUS_BLOCK_HASH,64) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Could not get the previous block hash\nFunction: verify_network_block_data");
  }
    
  // nonce
  if (blockchain_data.nonce_data_length != 8 || (memcmp(blockchain_data.nonce_data,NETWORK_DATA_NODE_NETWORK_BLOCK_NONCE,8) != 0 && memcmp(blockchain_data.nonce_data,NETWORK_DATA_NODE_NETWORK_BLOCK_NONCE,8) != 0))
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid network block nonce\nFunction: verify_network_block_data");
  }

  // block_reward_transaction_version
  if (blockchain_data.block_reward_transaction_version_data_length != 2 || memcmp(blockchain_data.block_reward_transaction_version_data,BLOCK_REWARD_TRANSACTION_VERSION,2) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_reward_transaction_version\nFunction: verify_network_block_data");
  }

  // unlock_block
  sscanf(current_block_height, "%zu", &number);
  if ((blockchain_data.unlock_block <= 2097091 && blockchain_data.unlock_block_data_length != 6) || (blockchain_data.unlock_block > 2097091 && blockchain_data.unlock_block_data_length != 8) || blockchain_data.unlock_block != number+61)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid unlock_block\nFunction: verify_network_block_data");
  }

  // block_reward_input
  if (blockchain_data.block_reward_input_data_length != 2 || memcmp(blockchain_data.block_reward_input_data,BLOCK_REWARD_INPUT,2) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_reward_input\nFunction: verify_network_block_data");
  }

  // vin_type
  if (blockchain_data.vin_type_data_length != 2 || memcmp(blockchain_data.vin_type_data,VIN_TYPE,2) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid vin_type\nFunction: verify_network_block_data");
  }

  // block_height
  if (memcmp(BLOCK_HEIGHT,"0",1) == 0)
  {
    if ((blockchain_data.block_height <= 2097151 && blockchain_data.block_height_data_length != 6) || (blockchain_data.block_height > 2097151 && blockchain_data.block_height_data_length != 8) || blockchain_data.block_height != number+1)
    {
      VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_height\nFunction: verify_network_block_data");
    }
  }
  else
  {
    if ((blockchain_data.block_height <= 2097151 && blockchain_data.block_height_data_length != 6) || (blockchain_data.block_height > 2097151 && blockchain_data.block_height_data_length != 8))
    {
      VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_height\nFunction: verify_network_block_data");
    }
  }
  

  // block_reward_output
  if (blockchain_data.block_reward_output_data_length != 2 || memcmp(blockchain_data.block_reward_output_data,BLOCK_REWARD_OUTPUT,2) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_reward_output\nFunction: verify_network_block_data");
  }

  // block_reward
  if ((blockchain_data.block_reward <= 34359738367 && blockchain_data.block_reward_data_length != 10) || (blockchain_data.block_reward > 34359738367 && blockchain_data.block_reward <= 4398046511104 && blockchain_data.block_reward_data_length != 12) || (blockchain_data.block_reward > 4398046511104 && blockchain_data.block_reward <= 562949953421312 && blockchain_data.block_reward_data_length != 14) || (blockchain_data.block_reward > 562949953421312 && blockchain_data.block_reward <= 72057594037927936 && blockchain_data.block_reward_data_length != 16) || (blockchain_data.block_reward > 72057594037927936 && blockchain_data.block_reward_data_length != 18))
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_reward\nFunction: verify_network_block_data");
  }

  // stealth_address_output_tag
  if (blockchain_data.stealth_address_output_tag_data_length != 2 || memcmp(blockchain_data.stealth_address_output_tag_data,STEALTH_ADDRESS_OUTPUT_TAG,2) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid stealth_address_output_tag\nFunction: verify_network_block_data");
  }

  // stealth_address_output
  if (blockchain_data.stealth_address_output_data_length != 64)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid stealth_address_output\nFunction: verify_network_block_data");
  }

  // extra_bytes_size
  if (blockchain_data.extra_bytes_size_data_length != 2 || blockchain_data.extra_bytes_size != 163 || (((blockchain_data.transaction_public_key_tag_data_length + blockchain_data.transaction_public_key_data_length + blockchain_data.extra_nonce_tag_data_length + blockchain_data.reserve_bytes_size_data_length) / 2) + blockchain_data.reserve_bytes_size) != blockchain_data.extra_bytes_size)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid extra_bytes_size\nFunction: verify_network_block_data");
  }

  // transaction_public_key_tag
  if (blockchain_data.transaction_public_key_tag_data_length != 2 || memcmp(blockchain_data.transaction_public_key_tag_data,TRANSACTION_PUBLIC_KEY_TAG,2) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid transaction_public_key_tag\nFunction: verify_network_block_data");
  }

  // transaction_public_key
  if (blockchain_data.transaction_public_key_data_length != 64)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid transaction_public_key\nFunction: verify_network_block_data");
  }

  // extra_nonce_tag
  if (blockchain_data.extra_nonce_tag_data_length != 2 || memcmp(blockchain_data.extra_nonce_tag_data,EXTRA_NONCE_TAG,2) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid extra_nonce_tag\nFunction: verify_network_block_data");
  }

  // reserve_bytes_size
  if (blockchain_data.reserve_bytes_size_data_length != 2 || blockchain_data.reserve_bytes_size != 128)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid reserve_bytes_size\nFunction: verify_network_block_data");
  }

  // blockchain_reserve_bytes
  // block_producer_delegates_name
  if (blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length < 10 || blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data_length > 40)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_producer_delegates_name\nFunction: verify_network_block_data");
  }

  // block_producer_public_address
  if (blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data_length != 196 || memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data,"584341",6) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_producer_public_address\nFunction: verify_network_block_data");
  }

  // block_producer_node_backup_count
  if (blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data_length != 2 || (memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"0",1) != 0 && memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"1",1) != 0 && memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"2",1) != 0 && memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"3",1) != 0 && memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"4",1) != 0 && memcmp(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,"5",1) != 0))
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_producer_node_backup_count\nFunction: verify_network_block_data");
  }

  // block_producer_backup_nodes_names
  if (blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length < 58 || blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data_length > 208 || string_count(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data,"2c") != 4)
  {  
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid block_producer_backup_nodes_names\nFunction: verify_network_block_data");
  }

  // vrf_public_key_round_part_4  
  if (blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_length_round_part_4 != VRF_PUBLIC_KEY_LENGTH || crypto_vrf_is_valid_key((const unsigned char*)blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4) != 1)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid vrf_public_key_round_part_4\nFunction: verify_network_block_data");
  }

  // vrf_alpha_string_round_part_4
  // convert the previous block hash to hexadecimal
  memset(data2,0,strnlen(data2,BUFFER_SIZE));
  for (count = 0, number = 0; count < 64; count++, number += 2)
  {
    sprintf(data2+number,"%02x",blockchain_data.previous_block_hash_data[count] & 0xFF);
  }
  if (blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_length_round_part_4 != 20128 || memcmp(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,data2,64) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid vrf_alpha_string_round_part_4\nFunction: verify_network_block_data");
  }

  // vrf_proof_round_part_4
  if (blockchain_data.blockchain_reserve_bytes.vrf_proof_data_length_round_part_4 != VRF_PROOF_LENGTH)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid vrf_proof_round_part_4\nFunction: verify_network_block_data");
  }

  // vrf_beta_string_round_part_4
  if (blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_length_round_part_4 != VRF_BETA_LENGTH)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid vrf_beta_string_round_part_4\nFunction: verify_network_block_data");
  }

  // vrf_data_round_part_4
  if (crypto_vrf_verify((unsigned char*)blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4,(const unsigned char*)blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4,(const unsigned char*)blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4,(const unsigned char*)blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,(unsigned long long)strlen((const char*)blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4)) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid vrf_data_round_part_4\nFunction: verify_network_block_data");
  }
  memset(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,11));
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,"74727565",VRF_DATA_LENGTH);

  // vrf_data
  memset(blockchain_data.blockchain_reserve_bytes.vrf_data,0,strnlen(blockchain_data.blockchain_reserve_bytes.vrf_data,11));
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_data,"74727565",VRF_DATA_LENGTH);

  // verify that all of the data to create the VRF data is correct
  memset(data,0,strlen(data));
  memcpy(data,blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length);
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    if (strlen((const char*)blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count]) == 64 && strlen((const char*)blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count]) == 32 && strlen(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count]) == 100)
    {
      memcpy(data+strlen(data),blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count],100);
    }
  } 

  memset(data2,0,strlen(data2));
  // convert the vrf alpha string to a string
  for (count2 = 0, count = 0; count2 < strlen(data); count2++, count += 2)
  {
    sprintf(data2+count,"%02x",data[count2] & 0xFF);
  }

  memset(data,0,strlen(data));
  crypto_hash_sha512((unsigned char*)data,(const unsigned char*)data2,strlen(data2));
  memset(data2,0,strlen(data2));
  // convert the SHA512 data hash to a string
  for (count2 = 0, count = 0; count2 < 64; count2++, count += 2)
  {
    sprintf(data2+count,"%02x",data[count2] & 0xFF);
  }
  
  // check what block verifiers vrf secret key and vrf public key to use
  for (count = 0; count < DATA_HASH_LENGTH; count += 2)
  {
    memset(data,0,strlen(data));
    memcpy(data,&data2[count],2);
    counter = (int)strtol(data, NULL, 16);  
   
    // if it is not in the range of 01 - C8 then skip the byte
    if (counter != 0 && counter <= 200)
    {
      counter = counter % 100;
      break;
    }
  }

  // check if the selected vrf secret key and vrf public key are the same as the vrf_secret_key_round_part_4 and vrf_public_key_round_part_4
  if (memcmp(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_round_part_4,blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[counter],64) != 0 || memcmp(blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4,blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[counter],32) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid VRF data\nFunction: verify_network_block_data");
  }

  // previous_block_hash
  if (blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length != 64 || memcmp(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,PREVIOUS_BLOCK_HASH,64) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid previous block hash\nFunction: verify_network_block_data");
  } 

  // block_validation_node_signature
  // initialize the previous_network_block_reserve_bytes_block_verifiers_public_addresses
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    previous_network_block_reserve_bytes_block_verifiers_public_addresses[count] = (char*)calloc(XCASH_WALLET_LENGTH+1,sizeof(char));
 
    // check if the memory needed was allocated on the heap successfully
    if (previous_network_block_reserve_bytes_block_verifiers_public_addresses[count] == NULL)
    {
      color_print("Could not allocate the memory needed on the heap","red");
      exit(0);
    }
  }

    // get the next block verifiers public addresses from the previous network blocks reserve bytes
    message_copy1 = strstr((char*)PREVIOUS_NETWORK_BLOCK_RESERVE_BYTES,BLOCK_VALIDATION_NODE_SIGNATURE_DATA);
    count2 = strlen(PREVIOUS_NETWORK_BLOCK_RESERVE_BYTES) - (strlen(message_copy1) + 64);
    count = strlen(PREVIOUS_NETWORK_BLOCK_RESERVE_BYTES) - (strlen(message_copy1) + 64 + 26000);
    memcpy(previous_network_block_reserve_bytes_block_verifiers_public_addresses_data,&PREVIOUS_NETWORK_BLOCK_RESERVE_BYTES[count],count2 - count);
    
    for (count = 0, count2 = 0; count < BLOCK_VERIFIERS_AMOUNT; count++, count2 += 260)
    {
      memset(data2,0,strlen(data2));
      memcpy(data2,&previous_network_block_reserve_bytes_block_verifiers_public_addresses_data[count2],196);
      
      // convert the hexadecimal string to a string
      for (number = 0, count3 = 0; number < 196; count3++, number += 2)
      {
        memset(data,0,strnlen(data,BUFFER_SIZE));
        memcpy(data,&data2[number],2);
        previous_network_block_reserve_bytes_block_verifiers_public_addresses[count][count3] = (int)strtol(data, NULL, 16);
      }      
    }

    // create a network block string
    if (blockchain_data_to_network_block_string(network_block_string) == 0)
    {
      VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid network_block_string\nThe block was not signed by the required amount of block validation nodes\nFunction: verify_network_block_data");
    }
    // replace the block validation signatures with the GET_BLOCK_TEMPLATE_RESERVED_BYTES
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    { 
      string_replace(network_block_string,blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count],GET_BLOCK_TEMPLATE_RESERVED_BYTES);
    }

    // check if at least 67 of the next block verifiers in the previous block signed the data in the current block
    for (count = 0, number = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {       
      if (memcmp(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count],"5369675631",10) == 0)
      {
        // check the signed data
        if (data_verify(previous_network_block_reserve_bytes_block_verifiers_public_addresses[count],blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count],network_block_string) == 1)
        {
          number++;
          break;
        }       
      }
    }
    if (number < BLOCK_VERIFIERS_VALID_AMOUNT)
    {
      VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid network_block_string\nThe block was not signed by the required amount of block validation nodes\nFunction: verify_network_block_data");
    }

  // ringct_version
  if (blockchain_data.ringct_version_data_length != 2 || memcmp(blockchain_data.ringct_version_data,RINGCT_VERSION,2) != 0)
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid ringct_version\nFunction: verify_network_block_data");
  }

  // transaction_amount
  if ((blockchain_data.transaction_amount <= 255 && blockchain_data.transaction_amount_data_length != 2) || (blockchain_data.transaction_amount > 255 && blockchain_data.transaction_amount <= 16383 && blockchain_data.transaction_amount_data_length != 4) || (blockchain_data.transaction_amount > 16383 && blockchain_data.transaction_amount_data_length != 6))
  {
    VERIFY_NETWORK_BLOCK_DATA_ERROR("Invalid transaction_amount\nFunction: verify_network_block_data");
  }  

  pointer_reset_all;
  return 1;

  #undef BLOCK_REWARD_TRANSACTION_VERSION
  #undef BLOCK_REWARD_INPUT
  #undef VIN_TYPE
  #undef BLOCK_REWARD_OUTPUT
  #undef STEALTH_ADDRESS_OUTPUT_TAG
  #undef TRANSACTION_PUBLIC_KEY_TAG
  #undef EXTRA_NONCE_TAG
  #undef RINGCT_VERSION
  #undef pointer_reset_all
  #undef VERIFY_NETWORK_BLOCK_DATA_ERROR
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
  char* previous_block_height = (char*)calloc(100,sizeof(char));
  char* block_height = (char*)calloc(100,sizeof(char));
  std::size_t current_block_height;
  std::string previous_network_block_string;
  std::string network_block_string;
  std::string previous_data_hash;
  std::string previous_block_hash;
  std::string data_hash;
  std::string reserve_bytes_data;
  std::string string;
  std::string string2;
  std::string message;
  std::size_t count = 0;
  std::size_t count2 = 0;

  // define macros
  #define MESSAGE "{\r\n \"message_settings\": \"NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST\",\r\n}"
  #define BLOCK_DATA_TOTAL_TEST 19
  #define RESERVE_BYTES_TOTAL_TEST 34
  #define NETWORK_BLOCK "0d0da5d5f1e00500000000000000000000000000000000000000000000000000000000000000050000000002b5d9ab0101fff9d8ab0101b2cce199a30202b1ae08c48f3b3e9ba6e22d9fdaf289eda8565179ebff7787883ecaf49f1ebdfba301159a7ed6a1065b708355d900b06e4e1c47238397723f4d379945b3bcdf10f09702807c424c4f434b434841494e5f52455345525645445f42595445535f53544152547c64656c65676174656e616d65317c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c307c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c64656c65676174655f6261636b75705f312c64656c65676174655f6261636b75705f322c64656c65676174655f6261636b75705f332c64656c65676174655f6261636b75705f342c64656c65676174655f6261636b75705f357c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c50729768e95b1257a6db3c68e20985c0766eabaef23a41c05f5c90ca9e2c8e6e6a6348d90370d1eed9607618538ef7da054b01214535ee7124be448176bf12db7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6a6348d90370d1eed9607618538ef7da054b01214535ee7124be448176bf12db7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030354a4d53546b76686f3978443341634f6470364a79504143396f6738344c5350697578324354375151736a48526a6c557866755455536c5336714f595a774437515a58684753566b623352516332417a355368517971777345616774764972397663675a5633647748446639706f7a5543434f373030386d67713333594861777337503359536e756a74747946536a366a5633374c5a685064384931464a6c594530507347314d4e6934614e4b68485232414f42705467745250696e6d75394f694d344e4448714c4258615148503151384766627057574c4b5268514b72336676536435574e336879335634494d4b4667504774417334383839504771474c4b6f4d46397179674d715a47577a68724755575a6b655368615055473471664543533742367446474a7564755369516376536953584b435234464f697269385449746d795470376e673731774b4977336f434a3964624f35457462547a3943367450756132706d386b6474564a504d56696d546a6c7863514f647a65613061724673737848457451464d4264716459776e46636e4d66546b467152575748464a4e4f326c63316f65707476526b3575476475554e7a42573250444f7a6169374c575a575750613034726a4a42663338676e51524b66444453366669346e664637327254487149434850623953333557654a45504d376734666851414d364f38454f3272696c4b734532694f645533585a5568315157545633786a4475584157417162497a4d5932453447474e787241697a70596c384a637651444e44337833687a4148626d7a4466333951727267784f766c5a74535a4d79716f75677548687a7365507a48397938614f4e6570374562646b443744746a3837426672386b506f6f754f55726151724e7475306f59327136766e414e777749564258544c43363057494965496f746a464c6155783261756c6e5357486575734769396649356e6e4b496e716c767a7a457361436c344c704647596c55507665464c3970556b4275524d4932353572416e7030776a424c4e35785951636b5547545254443069564856737a516e4f657a3334566274764f70534133544b4c70727436556866454f3055627367344d4e755369626a753772345768636b6c43326c4c51716c686a494747304e7a416f526a7753714f4e46477a4c4a4a57397a3549676c556c7371525767736c4547304e314732466a786347384a675347444e66485758536364795a684f384c6a5a707941795a31315971343276447863647a45436b383270707839454631485a55337067536737477531774f7352517668695670654c467438435743747472646d456a344a6679333654486e416d47487373567831714f595141713954466233376956476e6b366c6e72447268734e6f32756c4f52366944354a377a61775a4c45567a58647536714c7a46515267354841656a67627048365a457558596879743256653566616a50414e7666546f4c6974556d7561546f586d474b614e36744452787758774543576856696a597a7138744634384e30386d573169396c685a6f364f48636e6a6976356f44544e5450346d4a315a7a58616d4f696a5a7038646a4d4a6b5953716a4c464b766774386245493074354e7466727a6f674d6d68575851364c796b5361507474554b7254356c494d766c42576f4174344e36764d6e506c306c42437361756d694557737936306172397a656f5a76694470426641676f70704f50494d395355434361307959304f5971516364396b47704c4a4e5157303541464263466a56374d565638494a4b775a305a5a756c7178677668567155305159354b6157795575384643685934647855316c63617a7a6555475a386f4e4e64476e62714a554b4670634d62364f774f464651443565484e4b774d58377059444158533748734455746656705267326b4c494e454d5a4735484376456d6d5a545666574d314d584f6c6a69597a58636c675647484b63416845564a4f3577795141697472556533336e62524b5a555433447179637359685649527a4462566b423444514d464a47534c6e71793539727a70504247444770396c4e6d426f5a5471674d58366361774d42686b346d6349337751656b666e6c67597947646c6e72725a646c3064484146504b785a4c3353354a56664d387151574d6b58587964636c676f396854414b7738356c4a593245764e48374a594d747957666b696951776635516e4e495072787443375867353473574b7270494e434b68305659456633415665627254714e64514b30584456666e7475435a3635796454685a6f6d534d36574e6e45313048487a7675326578677751476c4b7a484c6a4f427631683756324969736f396e796d4179443844656e6559396367786d646b4d59666374313555616f36397a756c5a514d58684f386a44366d4a72774b43387848385179327977657577444f4873736964795763466e3650566e39765036536b3277485555335965707051567457624d794b796e643058527151644e7349316e4a3032454a4a4e4837476271726330504b6e304e644e74747477354b325758414b50326a6f46506b635179725470347443553544786f56514951714241645a39515267356e56646e4342436c517743674e53516c62577438695977446b51486a6a437777415461304a59345365633850564d3055796852473562616452466e5a364a6c77716c6b583765476268435230654649444e7039476f374b3642565678753454496634776436326362735231776e795a593344504a767a5239326c3472787952446d6c43325043595974686c486e74776755624e674175647347374833756f7647785678616e6c5a477338624672784a63796e6757466a636265483377556f3366396f676b7a35515133536a6964546941346f6b7853774a7a4b745a6337767a57373839416a3257643570384f5976714c306e554a487438684c586847684773654373444c6b704d64434b517133343255684d724f346e54463830626677726959484c7851596154724b7a464374786d79384261324f54764b5346547372797a4d446b58454f6d6749696a537a78715062575573636a6a32314f4a68333745467a4f71337443395a4b6a463845564e46477658494334797347377a7a33343471476c6a584e684c6d6f676b5330566c776537344831725a796d6d566667556e79324f75365161674569695434794a6d5842364a6f4135664236664d335a597050414b4d674951495258734a6c5a54367150464564414843764d666f7a334466746250794b763670676d577162466d736953556c67734c42325150734868765a69614d787546584f6a7a38727048475731357844347a384b665356325958593138796f73313935617933714f795779715254544b67506b6d7935656b5130624f6f7136677031654f53757166654d76557663754253454c657a516f64476e5254444c5852425a3768536b7431506f766e456d447052567530724643397359695436384a336a48385a50705175443949366c626c3358445263386a3972366838306647526d644e6253305061734f496f304978527430797658477465414161714547374f48494f6e79746f4f6a7943454c35665256634b67714632337a5a39585553556d6633395771464141313332435737694838534f6d6d45664a7464776254656d5a366c4c6d4f624b463243364e79636b75555745346f4942494a564873305468553551364a5146644735376a425a4868324c526a6c5138774273586375757672494c574274725a395576356a6943716162356a6d4d664764777265514d7a386938534a7339787254536b31594b685a4c6436564e6170517748556368693870675157794f684f7858596f4d7a7542387643656b7a4f5a3439464443697161425a367944475137346c62513845796774306b42705a716857554a6e325a6e744d6850664e76624648636a4646484b597855704c484453736e72466467517751586255797654333256627671493563344f72466a566e4d6d5a4b5479353754703344324b6378394f6c4d5733725a706f755434624f466e4266355a61324a6e55616473634172514b3141446a7052784979714a63565644595172584759617159654a59435943615132435a676a6b4f48796c486a3638384b7056626e5230364a41696f42764a743752725461333950505844764a6f4c49523948324f77586e5735436e6f39486d525933505132757450584f6d397054526d7148304d7563796f434b4342664d69314458487768596233436d32513548306c66525778546b42743562654653544c6e34625831446f716548754a776f70715a524966707a474973484e58717578426f796d665a417532354f4273325147527665574b4271685256554639653241726f4d7565614f363671786d69625358775648346b586232485476474b7945393358427856595838487874714f7a7550647131426c357830755974326b5632634a747873686a714f474a336b376c59387a507a4b4c56423348535751434d5139336472386d494c5266455a61504e396574794d32686456505546766d66626c3859575158754b587574583751564d776833344b6d6b52703767435846304d3650794d41516b6c384438356b524845597a78784c486331436974704e693248586f686e33727931547556316371765950516c726e6e6950757a333748544473354b445932316d7a31524d616b6a4a56725252676874614d47443756586350444f647642414830726d4170774a5766314556354c63336c487769736869354b5738336e7a42624f4e413238394f625969555452584d33733639496369454b3241456758336843474673436959626a6238343848446f62656146546f4b743469387949527145364330504a504f53514b4b4d6965596867594e30636e6a357466743156497452616b754a583771424830644e323256394f7958524a344d32373355537a6278416c5137384e6e78696350376e6d576a647a564435365778615549425765743671696564694a386c454f6752593030306e4b74684564454357613347656b43757347767a65734949364d6e534163494f4d3056653170474e6f7a6b734b4d4c3068366e6c6f56546976365a573678505673524f58416656367857326a52766e51473347676f4738624368525562774675646868436d3079484d6f51724a32376556436939386738416c50696d394f4762564c4236415844616269734c616e50565058534c3151616375696d72575273477152543770736233366351715470625a6b6561437a476f6f506f6e51374d753367643076765a6d705a31464a6545796f49784f3531326b4566766c61364633634853763246486976774c3242676f504d4a7549426b51356e39656f354b66376658733772596446307265483574596c304b304762427a4365455a704f68464b50535861354d4456314871585a66364e50586a516d47686f6136445062386e4f4f624d4b4c6676424c4d6d4150696273356c3668506476513757743655454a7a466c37667073473032536f6330795570654b74565262414d616371466b7243437045624761794c6d376e6e594a37624c4673786d7458587258625536746e794952796353554e34535a68457764463849587454656545763246665757716b743849764f74374739574d44675038636c7756305567343836623847426a4358595256573171545875685865423037456c517335576d34516c326e4e395079587569486c776f365176545357494e6f5475474d6551475632783846754c316933394e65743238386e5051386e736d344b52484f786234434e4e6a486e3674537769485034776a76594a39486c4731444958694f676367544e6e70306a4948464f656b497a72316c305a536174484232754a45424a49696e5678623435497a4b4c4967615a386c5158314f657a6636544d41696c387279524f796967466f4a617a6474484e704266327a3646724658496d715969645451707058745462325279333836486f784d67554a4a396577496f4b77774f666331735a6b625a63526e36506842334364376d4b486b4d33533043636b67666e357861667858666339674d32506a736d33746c55346575767a3337594b53694d4546396461414a43456c736b764c756d324634574b6d6837676457515632716e797071794e58596839677273504c4348667774504a7a4d504377746c70487a4e574e39784258457931554f487462777178766f6937597234514f666576346e5152534371514b5177774e756d4d4f4438395265374677316a38366f74597a384768415557397967743979474c633948634f4d37683659723453466c48346a623949545446685959676d755070726e70355871783649364c744f553847354b345934585863443178464c34574552376b506e484b54446a636733384d594a464c42717745546e316d585637724334436767394f5a425830464f596842784b63585a7972494a69567733514d754b63795162634541587541446473354d6c6d397a53346c7749753032634e55585a74486177503952527a6a555065765970736d376d78735550694b515675424b4f364c384c4b4f723758624d5a7542654d4e63576173454f4165756c7a5455625076396f334c46307746436d5a3368376b6d6d6a78785a364d4d4d5446633743416e637472506b4e445a67564c6e51547a3232556e50525a7372475874446e534f716235336d4878394e674b5957746c4e6a3630594c4f65326b5a6a4d64316f7233696b64504863714e4d6379336e62616a52463849644b6f545736726d345056626836514977384b584d4543727a70546753504d567030443955556b4e78354f435a75626c714c3730647a66434d5a47754569655337485052705a754d53376649706552474e4f77516341684f704e395257627a52447577766255364c6b664350345755764349594742335a3836586f396e6d4c4f473561465034675961474232736c6c5355376f6c596268555a775561477450636f4e4634484c5146666876777345656142726b71737261664e53676a62546a71754f695a4e454c45676f506e355a55326849665474783658537371565539683330736c4255573559614961337755564471596d4b6b6776327a4c4e684b556179616a5853335148336f46564970456146746b64447277764f3736564652553150334f795875334f487271416a754773494d326268566b464d6379685068726c445a436a717675664b494454303939774b5a78524b486b6c4b4773704d4a796679596d4d6845505361697a31667a6e506f4a775a6745614f6271314e5a70516c6430586a754331754b716a504e47426e6b656c7352577a4970686d3746624f524c486e4c6f646a6b39785773316c4462714e72357a51434f564f4a714f6f376e546b58376d36696c7232436a64336b7247416e34674e493272676733756366646d3238775965476536366e385a76707756777778654164485133576a35385364426c41514d31506d416d70724c483365326e7a364e434272776e7a706a68744a74527035493467386676704f3067535373674e3547656c30714b677a52783838636d324b6738486a725558685a455968497a6365446d34646a3743443832586d685343766a3158746576715452773841446f4e54794657494370397966584b6d4661464d327234364d6b5173464d53385974506e5742546d4f534c52466a32386b784a614f4436704c4b48676c6e633948526d72683345544d556a4d436f64534f58627364355775446e5a544a677763417a466e4c494d78745537543861424d564135577450675732334541383043796e364d5a456d6b58366845336636463075794d4f6551793448327546515632345243526c4f31374a367a4139747079684d4f444e74526d596f6f3947696644455a4b437a4c38326333765853496c5a6c59715766363633696b324e71356755544f6c677168387138726452307045396256546750513958595a416654465a416a38477866434f6553505447346e4635366d634a56786f486b36614245335a387349466834685037425130356e4e77344377446c545153314d5173674a66635a4d493647504a42656f726142337576745157457a436b716630486a7a4b6d6f6d5569517851684234787a7471544f4a7a796257316c64794b71575145753978383951746577484742646d716b7a42514e416463417341384a6b4f62434f79414c63545079706c597376634355446a78336b787442567038333239764776566679445555533349386f4c79386546743651516e6642446475766150427767676d5347506c426a343639484575463877684f416b5549486d4e46796332466a636c4e527865597039585844677341414165304957776738384c786142306a4262566a7958374d57547a6f5a504f706451644d4379514277705777504b45674c6e614c7049756844745562344f4e6c495a355a5064425636784679587741797a79374f347355784a45784368614e4e59474144495a6f456d533237637274425070654b4657356571734576726736644d78476b6d544d787a467342554d31783135377752315756766268716d465a547a4643385945364c307668584d614956594f4d45677970427a75524c5a45756d385569576d657662414359614175547038765263523444676f6951634c386d4a52767433784f34566651564639465337597a614774424b47497172526f354c6e30784b41625263764a6952343936646e6a52535635553678706c6442684f5035396e76613477774445627842357a4d6365745837625275713378536161763337497036444a7334647273446b50666d547939517852384f4975754773507a6f545730346d7866326d54544f44545848544b387777654a4242715845787951676947387534656e655834546f4c45567466535042576e306e424e50593976326930314355334e594f46463368384d7964756445676f73735134354333707639666b415839794747426367436c65474e66636a7659377048514f664e744d4f6a4b44394a31446471456853506c6f71716f7a4b63775a4862444d4d566e71345852317547767657584145434c51525a34677a35427043415164634271717662386c7443454d70726369776e475743394d4a33506a6c4257484d4c6969424f59494e37705a7961544575346166773850365a76666257304777424f4531727378346f4e554d4c42673676656251614f4d3039505a5444766633384b55703068686353314f7571536f4b567071565541586f59796c4563626b6f4a646f6d65724934376d38766550436c4a73697353354746725039724f6b446c6c53766e3732663465656e6a524e736f3679474d7361684a4e6831727075417961574b384f503051526358794e654e4a43686d55677273545859586e6d564e76743968476a4a7a75555269614a46534a62674e30584239496e57567a4677565974307444785356687a3368397758477832696c4e4a6a6c5735356b7a72336e4c544563676e566c4d4d744a38656775346f4448564d5246474d5035314a58346b6f70347a55746e47703778703967424575794b71596d563650674c7034447867537344424a5137574c73624b79416454574e394b595346445a6553524865586e77714f35354d52473451667265693830543579484e31394335506a4154344f64534a534d6d30577937707264314d393831414364596e58704e314f7670674e375075495a6b736e664846677966677736455937743955494c4a6b3459714955343073543849376466416b42446f597a534b7562496448684d51624236486c30784249763967546e4c6d4875436d56736d6d4f6f6a6633584a37754a6f5337344c4f4a3853716c7444524e3533776c664a587353326a447a6859377445326d664756646f616e46423467775643465a6273685269716a48783545527a773143304d45634b5248624a4e4e4e545751586242634574577567363073466d353168397250566d6d66546551755644394a43794a3653746f597063665470384b75375a3953396c57526f4339393338477478666e6477435a4d4532745230336359513945506a717778527775497331326c314c7975646e734176364c754a4b626d627438523866653948387256546d34495673315a466a703064306b4e796a587a4455664258687a73664f65583038744c726b7957734c4e764256365835536c7743715670766b497a594d6d4d4b446d5a4d4b4d7855583852357447543153374e4e4256514172476136396b674c6a305952416a426e67696a7a503072765732366c4e4b4c33684c586556335033524349684c39755267426856717765636f386e304957524e7945526876763861584566774578634b5a68716c4874303048775046476b326c747369595167644a694f34477058563939396b457361735875387431676a617a7a676f666b704e723146586774486471476e54586c624b4739317667387446787a52424934655a56484d31306a34665166594472586278584a6f49344a504e4a6e334658396e35525631496e3265554e61466e36634a524b5671457535683368397834384b5a4e744f6c45476e6e686d537667533459735063563835305a635a6d3558565379637849483156553935417561696d597a5a596b583470695361547448647267545a6d74666130716d507a4751777148666a6c4462794b547774623375733965676a766c686b7a745a5759476965646c6c6d4d6e496d3634453757596f563275336d44617730736c4d6750536b513176304447775142706b7949793876714c754d6c505866694a6671616c65765052684c524a61336a566850686662794f7438303756336673377674697a4d566654775571774e7a6955657058644c43784a7175746a784c675332706645386b6c763242524530586d336461364d417444486b72456f6a696a6f32487256654f45635352314a694845496b3976654f5a4a596764636e6b6b426350515654756e5663344c4d62676548716232735052324456334438644e786573655a627762567a357739364162445063773750625a6958524c54795a4b31386d754558497575676b566461505131347077694d386a506a3144485065794e6f5266636e417573496676495539784d7055535a515a455a523675773851376d78646d4c424733394c6d46756c3134794c4e6e70435165684d77424b637a5541765545574b6f5a4f466b314d41447271726d4a5569613042304455665a4655696e6d35584153423331714470535646393564546264484333396d3859505137323030507147656a78744c4d62776761726a52716b7054646d333961484e357844546254716d356c4f6a4978423279323550426a4c644c414f395630744446786f334f6166486a52515166664944354467774d50786c663969305a43727558466c7a4572374e364c7462525a434b734735326c736270736b64664b767978594a577359543456766c5745544255534332434e6a6a674a3441446a385279454542535564354f39676a455a4b6f496467385170665557616b716a6835464a7a35706a3869563770354265444e4b4755496c374f33554f63385668336f51736a357a66626a6471634374466733615954374c55426e55324d346e6e50563877545a653051613738734b777a6947363043464b33537354756d34463251456d7a72717137716c3447546f3532565a536c757163634956755451304c757558544a623747726a4157324e50537946414858514a306e6a5a656875767749746c5a714475746d4b6f4647316e35314267496e67427470707676485152673730356f7570464530543975496d6f414d75385a4178694f4d44396b69516f66456a72597857716c447146614152416362773141523965734264434852725a506a565658616433415939747344705572614f58534b4b324830476c525839753655675553684c6a354a436c63503675504966776a506f4f4453306c475a444348486b714f577a48765a547646504e696e534575795137317a5861354b4376683947795344467262776a655a4e7045303545777179553765684974334551503678624f3046335a3163334f4f696a45654c5973374a6e624f56764670626c6a776b566d504f394550326a74627156645a4a745767475953716a6f4469784e464877506c62505032534b7a5371364746586958674730526265524d4f765456744464733038375351486678586331715839653144324743346e65494758745a6f7768657663563948307573306c4a4c694c434a423862766d6532535a6c4765474e695a5133576c53684549316f6d445967457661316538664555447a4c7836486568784b4532697538376d6b6a4e377169737137786e615a37456f475a6a6534717a4353724b646f496e7950307433384d6b3337763457737761576c683064796e4467466368544975666e6c7a686837367146583872634f3141436f304d315533364e7056643550515638795173764b47597843647867345848684f6a38776334377250616c73513671654b47786b636a46456b324a6450676b7270694c71614a484f4851366d4d6e6f6d544b7555525a6d327552416b556272356c4d6830433465394f44684a67426d7264476c4666364c794e6249796158746a7879395a746558354634444a744e30776a62307037424c4a436a3542366d4b744c4b67324d315668566f516331477a62466e6f424f5861653633463050683874734448765434696c333744796a57774972574a486a4f54796e5455303051686a6a4f43304749617a4644584d6f696b443452626277537a4a4368797159467a356930554f795565326c5a457a374e33317532314f4b716d63774b746b6451646c33475077777939654b635277356c4252466c62646578394762626274695264396d52754964744b4c76723870427836364735394a7336667237674964564d6437727647754f67363877326e5870685257634f74754b794b464367496e514a6c3734507348304371547245424f56366e79474853596670327a687666466c3665514a48637a3974677258483547426934354e4e5552304b6735356a41666644564d615839386566705a4b697662706f34305a4f4850704e496955376e5a4138427955417757464c4d646430416b586d687944516c76576761316f427572746d654a794d746c5668525735663753706367515170634476617349424c5a555832736a454a756e4f39614a643572733777394e4c3965373978464238736a546b7a324d396d594e6b576c6e5243444d4e594e64673441544f6f75506c4f3047304a306d6a5752433279427a4a39526c58756d31704d4b31593447374775457734734862636f42354b30736b3039744c7346444666627733343130416a7356624c73614e45434763715a6d6757445165386a4a64594248466d34786e636e594367617379536e3571714c495734327276575932497078647a737a4b754d795651796466666f387443485a704352475643754c384a386138717a484a39357551737854784b524f63704472506b59794b67374a51354a4d6b3631764732355a6e6a446a6654677145766378766d5a4374596e75774a4557637569496b6276786b574671464c45393448757152695162363276727a5a647a686c37736d714e7663694a485564454d4959307136487233784b6b557a6c6a467865584875416651763545514c72693971504b5165546b486b636f635845786f3048526a32575a6c51745a72493870584c584450484c6b504c79517931644b504c725942634c4e5332433741796b6c37384d4e446e5669596b596b3930534f423841326162465133364e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd74288d087096fa6fabc20ba83244dee39517a723cde9d7d4efc7111613ce9590b6232e79736660ec90d6e40e325e06ee630f753a6b3c540077ae0564cd590339230e8ae8fc6bf801e73e232ce1fe6007c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd65cd4647f61953d6fa26fd80d1646ec96822abb5d3a87bcf84fc33daf32c0754932b5ec9abcbda86a053ce11508c08281a2fa386ed87edbd442d71934a6450d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c747275657c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c747275657c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477caa41923155c25d42474938bfbafb679230db914cd1dc0acc9bedc7b6edd6579730937f955e0b9aa2f34175644bb8757d2ea9824d6dbb720ddf776c3b79a9b5e47c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c8dd1395dda2041ea2b2c49b4dd9a1b631daf92c42b935bdf2915e6fdd0fde6dcd0b093749bdf2c6f29cb9c1faee7c584db36a23eee203eea6c8c4dd08abf08c27c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c324fdd1a8410265df339cade61d5fb0bac0e0a7ba62ed2b215e355051caed3cced9973057d63c20e99d585e64df30ea054876642a13b7252b5b5980ebc22d9e87c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c2093cdceb47fbe732d66033ca28703c67c98a04d8ccca2d7e7c763c9b5e13cd41726a5bde9805abb298f21e36b3939a1bd615f7357df92579748d683c9041fd17c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c95ba6e79ad687a54a020f802fdb397fb02b665aa65e52f801e1906d3f755e58c20721d4f35888c66b1a3ffae8707359ebf5a6fc364b7c7e372c38010bc5fe9ec7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf886ff90b2250fd7f99d6b64c5cc7394f5d19a3223b9b4916401d046d60e97ce7690af0ac5991ea4a074ceb153422643c8aca58bc6abf43f9123d3a5c1761b337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c8f9838bb7d19fa3172272e3d3b2822c3b34e9cadc0ae08c7f4cb0faf3a2fb8c8f7399437740690dd9dcdee87f324e752829716b211c773b2d75a28833e14bb037c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c809f7270d4451e20d8adbe540219e3450e7fb029562b2e62dfcf1c3d46faa4c696c2d06084e41ffb104548fcff856b7b5a5a3e4ee16cc07c4a58ccec28fe08f57c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf5f85b3c75a56bdac96c9c5d79d7243109aecae9567956b787bea5aaef46a4643541e7e48768b2e13d606b3ddceb3460c920d35786237f62ba7c6183988b9d277c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4cdd5a16d093573f8429911bfa281e70680ed4655c37d25de564035f714caf3ccadf12dae7cda45c0c55ce211bd88284ed80f8517e9ec2e50336d5825d7bdf577c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c9c014bf009e3cb77470f592e79f124a4e6182f4068feb1b127f85fad6f83d20bb9993e486ae271791437482d2435d4e33534c74ddfea4a995f33d5178c7659fc7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cfcf28ee3beaf4ffdbdb5a5a22bcb0c039d4d014c5e2699de50d125ba8db6bf896769b99b36be09e601189d456a4bd79447cf41d5facf4a6e71f853e9cfbef16f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cbea74e82df4d0d15c29163e69c898a1e97d1a5d5687acc87084ed1a12a25f8681faa209764502353955819dcb33ef0469572445be6fe2db9390d1ac5816f4e757c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c8cc909ca4b82294baa3aad94f9cf9fe692f8547d76b68bd54efebb852c438137f5f4a0e2274ed331b5a111cb08980d85cf509b7db465f75187086714599236787c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5f95ab231fda7460bc306c78a88d42055cc829f469b8f235617cbd253f3fa61ef341d693a057bea696c2fcf1e96b96365d1eeaaaf80589365a2408cf40d0022c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c60d8e766b8c85ce260290dc21c25fa37780d3978bba0bde63d2e2ecf5be2663ae957fb6923489cd7f814e4c4d012113abd23e59f3f81ae6028049478ffcbf4057c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c78b2c366b9f94b1d76610828a146be686193bf2fdc94ed080ca6a13e7633146df983b8197e56946a05785c01d8475e2adb1b49c0381b13ed30396551201a7b357c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ceff7ed59fd7b719a5b75141d7c3fc2a4fdf1ab714583c9c47e914a8d9f4e578fc023317a583604d29341143b40423f56dbf8ff80f04297a24ff09006308c0ade7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5d40e99ff86d1d88983d8481ab830b581c28f8706894776d746f3ba250ae842d07dd462fd6eb6ed1952719b7cfb7831128b75b0c5f3690e3cbb073842ff43dcf7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cabe893fc2ec13815f7013831de4862c9676cef5c7eaf6f76d156fb079f1b65c975eebc475adaade59a2fb6e70cbe285e7c8417c41720ca0a3c4083e2e1464a947c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ca1e98624e5901d4b28b9a951a2c1fdf6a1f6525f23e8773370d81bcfae4eb05038d05eff128133653d16fb2b2b57263a71df0d227acc0f17c87d06ff66086e957c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c2637e8487284ce518a6b8348ef1f01602b4f5afd7dc99ca3cf444a277309701968e9ee341d5c97e1d8951a9f5a623a31fb4abcc1b653257d2d678f5e0483e0ff7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ca264d37fc2a5b2e3bd360562fdaef7a239a50621031155c1e99872e88a52642c1148cce4b390feb64466749e8d68df0da6c7d411b4bf4393f8258e6081a6dac57c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c842798c4d5fbe6f082f6a4de47d517d6b7fd3e567e8c4452813df9658993a38c6346fc0de96ff7f56a8050d2069b47943992f5d76007c5fbae9a1c1da133e1527c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4459a84aaee5cd7da6f448ece69e7c1c8e55838c7da0ac0c2fc1e1764f173b120eece921c589e4e3dd3ec4b054a835313698aab431ca1dc56a3dfa1386c162337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5b15634311698aabaad8834053d56eab90b9701575c8ff05cb51282bcd4335a76a399375e4debfe259731e0872e6c22a5472a9299d5276ddf5837d0c615176387c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7e710a8edc28c1197827da8641a0db98b252db83917cbae640950656cf957c4d0c6e38c8bf1b1a183a18119122b1e32daa32db512b46eac72942f35802f5d3e47c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c10a48808a8cffd11c2c65007c757fdcb539ea3c8acb1b539619e31fb321ac141419d0dfdec6ca73df3e6b9b7eb419358ad480a8259b95f8406297d397bf09ac37c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ccb5dbab864ec23e527049d1c7e7b34f14e776a5f1b8e3b1844b3ad51b360f3fdf9e5adb17f2562830372a261a8ec66f21ef336ae7b59586311a151f7d85f69847c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c126bf372eeea825ca744e7f0555048e99861e213240187724065e6bb38f093c9328642cd32cbd97a7f7e3c91f09a3e8bb71e152902eb23bcdf14675f897915cc7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c540501eaf0ae87d20fd6c9a426f57ab7b3fd309e5528616d0e2e709c23c030f5552dac020558f9427e0322cb79acc6a7d4a38b377571d280aa31b2e1a932f1a67c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cb77d2ecd0fd13bd3f6090f3011b0741b32e2dfa941d5dfc7b9c88d7ab8910e70bf618d0d6b66d1a821adf4d36f6058e720f0c172bccec3ebd59fc9188a6575da7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c546e20e2a0e0aa0de3b439ad4682a26e7cecc536f177cb03b891ae5cec7921403d2e3f2a879d1b5d13aefcdcf8348b96452e6756de0a551520897bf48b93c6b27c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cfd97230150a97de7ddaed13c42fb8c640926f1f64fbde5870332737d58fe7f560f2073a1e2221d57ffe51fee52c97a8cd7d0da2e98967dab440358d819d09fc77c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c78393de0d93e83d2f94e218302bd5231cdb53c76cecfb62b06b824ada42b6e9b51b25559aebd26241c12e7505a83486c3627f66531bd966abd8d0f14ddaccee07c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ccfa9c7653e5ca7b59c7d48b59ffc8aed5d346ca1714a6f1c19148626c2824b11612f8dc71f4bf7707b0acdc3a0c8af9f53128e5146505e39628583099d8615147c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c9a6c9cf6ca333e5c826bb0e7e81faebc1a3370371891d40b576633ddc74fdf610466cab2eec90fdcdad82108a6d03b5b962fc24099b8c65187246e4c9057be167c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0f429799bf355c5557b5ad6725c4e8a24a26fa688430a63875bf49d831f4763f9964eb4e7e059e0dc2964aefbc6b0a4a4df66b0ef4734902413512d17b090be97c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ce5608e5c3182aacda6dfc6ece03d8edd20ceab5ef3b6a3fa91338bb612c19876443ed66d32ca047bc2eddfb75645a5ca9e6b1a97432ac1a6d0a070a673eae4737c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c065d01ed1aec41406c14101a6b8032c699223318687acf7a09bd1c997f0f85848446432c24496672949fe8f8d6c74f51bf57b0b359594f81f28e856d7fea21e37c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf531ab0c780950d1f787e478e24e5a09b52abe59f3d5fbc48a649a1dcaa491bfcb5be21662bae3871e4a41d9ac5710843705e24b08b1576c0d46943a5c3c77147c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cbf55a058ea8bba51a799cf4e1e8255b011f4d5bbaeb25543c36bbd4d4f43b10e8a300d99d414e65c4d20b031a9b40c67028c3b48f3a4a37a6fd64cc8c6c63a6d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cfe0fa669eb9d3ed9ef94ad08b1f2a61df3f31b496630bd807be92b97c4ea7242a55293b9b3a65b546bc5f5bbabe0e2be4acb5426ef7d98ec3d57c56fb6321a927c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd6f31f0bc1a1395385a40d60f48005513a2d8a5bd85c79c8f9bee7778c8828e1b493acef89701e6dcd5d7a9aacdc21523eb40858e018c3b955fe5b6fdc371c407c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cecc3af422a4c52fbb9964f27641639533954e61ae6a5bf4192f91e6d7c5b7f6977fe85fdc02638946ea11fdd84cebdb122a716d9e0b3bf7a9b1611414f6792de7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cada4f12bd80e320ae1a565e14fbac3b76cb307c95b3c9d4b76e23d988ae5c6b683638414bb2232505c689f3f7b2bbc6a92792404402dd9d092126caf5441a51e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c83ffb5a862d68ca4522b09e3da8ce1bc2406add791ee777d4c0c9e6ede5f6961de4126d97a1116162ba90921d926030b2dcd3b23a62379c38247018e685f35637c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c50729768e95b1257a6db3c68e20985c0766eabaef23a41c05f5c90ca9e2c8e6e6a6348d90370d1eed9607618538ef7da054b01214535ee7124be448176bf12db7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c32865e2d9016299b089a27f53e39d2efb4ce7dfc04addb9464dc2fa32cefabdd82bf6288af7e62bd44038e38e45f87e462b2af9eb3a2ecc551f7cf8c49b2e2277c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ce253b1ed6ddd95738991d8e01cbc6f04a199c6aa6fcea85dfdf1d8bafa088adc7531938049f00b8e9c190b4742e0c382106080bba4edd9c20def4071970991b37c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c705fe66426549c9e99a399ceeeb733539876fc90c01e0297c309c9c2d985a6c8a49f249e3fc327cb6d80f777da90d3d5dfbc2664df4268143d42ca4b3c37d93c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cbbb808426e42564757e4e9df1c19f93edac8d57948f4e0be0d0e1b185915b3947d8199dc289149775758f75de6ac2de7b91b664a99acbe2a092e3e6bd49289a47c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd60ba44c2da22211854a721f7afe2129f1c9631e314e8881d46db81f867e505c5097b01869d40c24f64a5ff014db088c99fbb9603956070448d48642c05c0e377c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cebdf5c54727a0b552cb19c339529d788b04f900754b4cdfc821a043c156ce7ff4eaee511d49f0d861281f3917173a4d84341568afadaea3da5e725ac2745d18b7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cac81b7dadea7873af6efab69c01ed0136a8aa9eded58821744d720a04b3391f6af141ac3c43b13bf9ec66b439e1846d3d7d51618bba39546631ca780506de36c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cc76725ac66c01c6fe1b9c2f118f6d9dde8d852127b6efc425d7b7e5c4cd77014227694d64606be78f9a9268da82c38aaa1a5e3d9358c7a305264153fc1c909c77c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cdae2df893be2526e4380dfd8a5b20c743f531de28dbc923c6e9725a4e9e75a43abe818088b0a41abc5982ff885578a531342acc2a628e1ae043d318425dc6d6f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cea42402a949afd5528f5d28c321bf908a4bc758b88db45d268ff5dca8006226bdeb862d78244d1bddf6b3aefaedff950532d8dd255552fc0e9d4dc3835bd09287c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c717a4c1fabac77eb4fdb6cfa353abd3ec5200ecd2fc230dfbe293a3f725530e2e583e269f759dc07ad2b52d61612bbc9307cc08c7bfb0b02bdc04151c36f66fe7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cfcb7f671031fcfa17be1622320d762e1d1a736dd568439337c1c81cb62fd7fdd2a62a0c3bc91fa2bc017859645b05fdfad43f9c0a62c1175f011a2ddca29616c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ca36d6cbe5a2526957911d0a50bc31e512170a2630eb986c304792b253d7b145f849fda1a1b6026a872a18a670a973fc6c8ebe45a6a1a5effd5c501e097b588eb7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cccbb3d1635a2f6655bbc96d1c14f752195ada395a18b0cd28137e06ef5ad914168768d07da3884c1deeacca28892be9f88e0dc29d0f87da09898e0011d267ea07c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ca745a239baec0408dd41ba01cbe66c4e216e566c481cdb7ebecee876112bfc38d3cf145bf976618db990c33bb76f51bc4afd11e7183965ecb814016d772afba97c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd16a6f957f5d0cb9cf74b7a1d4368733ac06fa083143b3d292b6a416a3532b7417da9f9e3f03f627e55d202024b6f3115a3a165c1e235015bb8f6da1758fdc3f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c9f4cd203b4aa1f386663dc176f6c80b3c29ec4ce8c09aa5c248a27739498c6b393686a2f1934f6b5ea2629b83c9155345ca93a8b9d4d4b282fe7b9a4c09862417c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c17d8645063e202c5be051c9c3e884befd222ff318ded21ab1d39ce87d01ef4e6dc1c875e69cc37fd0e34be64a4fd92ed483ceb0ccac4cfaa10887336522fdf827c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6f49c60479d87901fd4fc3f48f169eeee616ef2bc233cd764f913631f03e64de04a868c440a37ddcb2942d0402fc22098742d09fe9a7e5fcee37ec885de8ceb07c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cff28364846c15cb373e181313e75ad4d212ca0c8e005915951498958be3bebbdc8f3104d9e6e2afcea2f7bb478f6208873de13e6a58d6a8f99a8f0c682a76c377c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ce5145950154dc48a139ddc6116f8fd449d76425e9869396cf2cf7dbda339840836aa3f8d7ad3ef91ea898c4e4f10fc935186d4ec63d1432940cd05c7fbe048da7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cdf7c807b674ef4bc525b4e43d2d592eb7e7cb52f627353ae38321ef4bc8b841bd8b2edda01e597592052506299af9be1d37138825ac2e075fde15ab08267416c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cbfc601565a77b1bb8fc9274fdc9cc029180a5ec6f5a1a4fe9290381ad8738b17e583e63bb39e6d588f87cd650eb7e4d7c8c8f19b3fdf1158c7761ef5d2fad6d27c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4d3156e48c03300c305575496f32db1a3987269dc1d57c1825fbff214690a3120fb8294329744758fa467f74c064901f3daf4b2675c8e250e870a533fac495407c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c9712e616c11849095a830ffc57cbcbec5f8d6f07ce9323add389bd6f8cb680a29b20d2a9fb34341948b8e8840879d659632aee18bdc27e3181b4f257630443fd7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c1ae7fbd2699cb2e983609bfdd246fe2a81fe4654033dc732e9446931318888ca0935fd8cd4b9db46215df9c4b80d596f4a94e4930cc0d104611a0780f45bb68d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c8e1d81e0cb147c2d047a2dc3f8f30cc392d8134b57a3e6fba3b2da1618524025815a84e0c8774e3aecb0d4c40fe509dbedb7f57c54c1e7f971c4a2747586fa7e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0ed601561370a6a089fac4aa276819f696cc94edd2f7505e87dba560035d048ff41b2273c390e98c92ae4f22a80a50c11bc8d3e2945e4b7f5db448420dbfe3877c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c9e2c191bd0de7c79114cd93fe51bca02efedff66e69792fd3588e208d0cc216ed9a29198c006d593822b284b92c75dd8737f6f626f3b9043a1eb9754c5f117087c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c035c662cea91fc16d08f93aae42c3679de94aa333623cdf7050cc03760f76462540935942b5ba09215dd72cd70bf6f1abdf197fcc59d94e208d6f4a830f1df367c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6d5e746c01836bf3d384d38307de7f3a583d25b593c6d43af0d7f3b1bc8e692952d25ee4ce9e856aabb9cd86e7c216f79652d090aa5dad113103436c911067fe7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c9a9d7cba9e86e0a621fd19e592a0c1dbd87b050d124c6eae558f0f315deece7633f5d8ff0f84350c18fa9f6e0f8626d8532af913f57dc2ae406bde35e14317af7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c15e5d09c9887aee354d9c1a1bd7bc6aa2caaf9a08f78722c7b8268fe84b84f19f40a207cf108ba60164b5f78cafac7011e8aaf05441e14fe84c0b996b73c340f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c34216e260d73228966312f636b0ef814b3b5d5a82d9342894bf8a9af64cd889773c8fa4e0ae3425245ccd7208856c94c02f54c065d803eca9ce27c034ad8994d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c03a9f1f5e2c7550b637c02daf2ba07c67137b1121f381187cd55755babc9cd2d540cd998dba56754cea1e032f486460ae1ce4e7dfb5a414bb2ff5fb3460f54e97c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5a84cbf22ee03bfbf4778952fb9be47d75ab65048525091e70ba41413fbec398a096cbe8f24f602f9df753ee289c3d505e56489f1b7314ceaf8726842ff1a7787c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cc05f218fe8fab18051e8bda87a5b0eca8448fb25db70e9e54b0f8c9bbc3c5d7c78e73e7b50141515d0dd52a395d239e3bb2b92e7adf8ae497087102b3aea19c87c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6bdf05e7b00d1b5670c8b1708e9336ef15fafb6c337ba9cbd35abde8823c236d3878fc828b2b7879a9353af19ba7a144d671411aeeeac3a94c56ade9bed1d6427c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6e8506fd1a27e3ed31612f09e8833cb667afc63ccd4e87e89e75aa5363a829d023e76ffed8469dfb4945606d5f1dadef49f3d34fd43cc39b8118dea6b45c14f47c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cec4af60ab9fad68d2d48b91220fdb28bb68fdb150a10efd1cf4ce60b83f6e1ee56f6805c9411c390126c277317b80e8125f001979352028354d399d054d195307c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c75b2da64e17d260b4787c6bc61be505a694181c6d05b3aaf2bfb05a914449708309b4951ab5f42bf1dd86f3a43e07093c8cd59826683fa087d4e1d37c855077d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd1c6c593dff6282bf10f77c615f0c138ebaa7a63da206cb0e10a76d1ae05e080606b0881ebf2b2f3ffb76a36255b1236b4521bbbb3e9ffea64ed1efdc0365a587c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cb5caf865a97afb2c2536dcfda9e67899d30c4081e3dd2b26f7b00d418a89bc3fab9a92bb1cb8d687a154d42559a6e4d9fdff66038b7c83c5025cc6c32dd5ab3f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c69a0c756b54b2544cda71d888fee6235616e7dd8c95479507716fe1eb0f0269827ad077327a64402ec370822b8a1e7309711b2711ba5086085867480daabc8b77c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c23c97f8b448212d367906ff427e0ee4869aa62e62ed4dc978e3b71c2a7592dca2e8e36a90f9a4a1993e001dc6ac569fd3a4e79ce480bad9c3be84b94c5d184a57c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd3d001f08fb182d45da7e2d7aa52cdec47aa3e287eca05a2db9b4521d3f97da6d0692732d0a5e0ad1a98eee803581018daa36705d1d1a9300bb584a4a6b3f2357c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ccd3313e98e775fdee149018d9ba3b002e1377a9343d7f570bac22dbec2e7070f198c1c92df831e28a243f92bc016ae97542a07136964b95e4bd0eaecc66c1eab7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c61a450e9351435c16e267cf85e704273609922ce1292c3ca01df5b53ceb06e2f5bcff2c6835c402130d3b8c62598032c88a2da9bad409edf8c2bb8935d134f237c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c532ddc5e20089576da891037dae041f45d7d1bc93c44dafeb7015cc77eb78dd00f4febfbffbba7e18144cfcca1d61d20661f359139cfb60d38e353bffdbb258f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c08048580fedbdb21c2d41d48646750feadbff5e37ad109b37a87ca5db8625c40ffd90e4e42457c855e0650503c011e1b99f5f07d5d7b107827999d272e4fe1db7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd78753e76c2a2cccc6776c3f955e2e05adb78d4637da6b4578423bd6aa0a6702025cdceec253ba08ac2468a032a4c4a78631dad46093ff07559f154cc01d93117c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ccd4533d6eb31f694ec7495289b32e4385ca8e85a7a074bfb5e0edc925126c39d780959e473ce4804c00652d4824b5bffbd946259ffeed7e01928fb92ddd944fd7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c30937f955e0b9aa2f34175644bb8757d2ea9824d6dbb720ddf776c3b79a9b5e47c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd0b093749bdf2c6f29cb9c1faee7c584db36a23eee203eea6c8c4dd08abf08c27c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ced9973057d63c20e99d585e64df30ea054876642a13b7252b5b5980ebc22d9e87c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c1726a5bde9805abb298f21e36b3939a1bd615f7357df92579748d683c9041fd17c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c20721d4f35888c66b1a3ffae8707359ebf5a6fc364b7c7e372c38010bc5fe9ec7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7690af0ac5991ea4a074ceb153422643c8aca58bc6abf43f9123d3a5c1761b337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf7399437740690dd9dcdee87f324e752829716b211c773b2d75a28833e14bb037c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c96c2d06084e41ffb104548fcff856b7b5a5a3e4ee16cc07c4a58ccec28fe08f57c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c3541e7e48768b2e13d606b3ddceb3460c920d35786237f62ba7c6183988b9d277c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ccadf12dae7cda45c0c55ce211bd88284ed80f8517e9ec2e50336d5825d7bdf577c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cb9993e486ae271791437482d2435d4e33534c74ddfea4a995f33d5178c7659fc7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6769b99b36be09e601189d456a4bd79447cf41d5facf4a6e71f853e9cfbef16f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c1faa209764502353955819dcb33ef0469572445be6fe2db9390d1ac5816f4e757c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf5f4a0e2274ed331b5a111cb08980d85cf509b7db465f75187086714599236787c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf341d693a057bea696c2fcf1e96b96365d1eeaaaf80589365a2408cf40d0022c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ce957fb6923489cd7f814e4c4d012113abd23e59f3f81ae6028049478ffcbf4057c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf983b8197e56946a05785c01d8475e2adb1b49c0381b13ed30396551201a7b357c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cc023317a583604d29341143b40423f56dbf8ff80f04297a24ff09006308c0ade7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c07dd462fd6eb6ed1952719b7cfb7831128b75b0c5f3690e3cbb073842ff43dcf7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c75eebc475adaade59a2fb6e70cbe285e7c8417c41720ca0a3c4083e2e1464a947c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c38d05eff128133653d16fb2b2b57263a71df0d227acc0f17c87d06ff66086e957c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c68e9ee341d5c97e1d8951a9f5a623a31fb4abcc1b653257d2d678f5e0483e0ff7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c1148cce4b390feb64466749e8d68df0da6c7d411b4bf4393f8258e6081a6dac57c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6346fc0de96ff7f56a8050d2069b47943992f5d76007c5fbae9a1c1da133e1527c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0eece921c589e4e3dd3ec4b054a835313698aab431ca1dc56a3dfa1386c162337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6a399375e4debfe259731e0872e6c22a5472a9299d5276ddf5837d0c615176387c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0c6e38c8bf1b1a183a18119122b1e32daa32db512b46eac72942f35802f5d3e47c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c419d0dfdec6ca73df3e6b9b7eb419358ad480a8259b95f8406297d397bf09ac37c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf9e5adb17f2562830372a261a8ec66f21ef336ae7b59586311a151f7d85f69847c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c328642cd32cbd97a7f7e3c91f09a3e8bb71e152902eb23bcdf14675f897915cc7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c552dac020558f9427e0322cb79acc6a7d4a38b377571d280aa31b2e1a932f1a67c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cbf618d0d6b66d1a821adf4d36f6058e720f0c172bccec3ebd59fc9188a6575da7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c3d2e3f2a879d1b5d13aefcdcf8348b96452e6756de0a551520897bf48b93c6b27c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0f2073a1e2221d57ffe51fee52c97a8cd7d0da2e98967dab440358d819d09fc77c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c51b25559aebd26241c12e7505a83486c3627f66531bd966abd8d0f14ddaccee07c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c612f8dc71f4bf7707b0acdc3a0c8af9f53128e5146505e39628583099d8615147c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0466cab2eec90fdcdad82108a6d03b5b962fc24099b8c65187246e4c9057be167c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c9964eb4e7e059e0dc2964aefbc6b0a4a4df66b0ef4734902413512d17b090be97c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c443ed66d32ca047bc2eddfb75645a5ca9e6b1a97432ac1a6d0a070a673eae4737c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c8446432c24496672949fe8f8d6c74f51bf57b0b359594f81f28e856d7fea21e37c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ccb5be21662bae3871e4a41d9ac5710843705e24b08b1576c0d46943a5c3c77147c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c8a300d99d414e65c4d20b031a9b40c67028c3b48f3a4a37a6fd64cc8c6c63a6d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ca55293b9b3a65b546bc5f5bbabe0e2be4acb5426ef7d98ec3d57c56fb6321a927c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cb493acef89701e6dcd5d7a9aacdc21523eb40858e018c3b955fe5b6fdc371c407c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c77fe85fdc02638946ea11fdd84cebdb122a716d9e0b3bf7a9b1611414f6792de7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c83638414bb2232505c689f3f7b2bbc6a92792404402dd9d092126caf5441a51e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cde4126d97a1116162ba90921d926030b2dcd3b23a62379c38247018e685f35637c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6a6348d90370d1eed9607618538ef7da054b01214535ee7124be448176bf12db7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c82bf6288af7e62bd44038e38e45f87e462b2af9eb3a2ecc551f7cf8c49b2e2277c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7531938049f00b8e9c190b4742e0c382106080bba4edd9c20def4071970991b37c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ca49f249e3fc327cb6d80f777da90d3d5dfbc2664df4268143d42ca4b3c37d93c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7d8199dc289149775758f75de6ac2de7b91b664a99acbe2a092e3e6bd49289a47c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5097b01869d40c24f64a5ff014db088c99fbb9603956070448d48642c05c0e377c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4eaee511d49f0d861281f3917173a4d84341568afadaea3da5e725ac2745d18b7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477caf141ac3c43b13bf9ec66b439e1846d3d7d51618bba39546631ca780506de36c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c227694d64606be78f9a9268da82c38aaa1a5e3d9358c7a305264153fc1c909c77c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cabe818088b0a41abc5982ff885578a531342acc2a628e1ae043d318425dc6d6f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cdeb862d78244d1bddf6b3aefaedff950532d8dd255552fc0e9d4dc3835bd09287c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ce583e269f759dc07ad2b52d61612bbc9307cc08c7bfb0b02bdc04151c36f66fe7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c2a62a0c3bc91fa2bc017859645b05fdfad43f9c0a62c1175f011a2ddca29616c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c849fda1a1b6026a872a18a670a973fc6c8ebe45a6a1a5effd5c501e097b588eb7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c68768d07da3884c1deeacca28892be9f88e0dc29d0f87da09898e0011d267ea07c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd3cf145bf976618db990c33bb76f51bc4afd11e7183965ecb814016d772afba97c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c17da9f9e3f03f627e55d202024b6f3115a3a165c1e235015bb8f6da1758fdc3f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c93686a2f1934f6b5ea2629b83c9155345ca93a8b9d4d4b282fe7b9a4c09862417c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cdc1c875e69cc37fd0e34be64a4fd92ed483ceb0ccac4cfaa10887336522fdf827c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c04a868c440a37ddcb2942d0402fc22098742d09fe9a7e5fcee37ec885de8ceb07c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cc8f3104d9e6e2afcea2f7bb478f6208873de13e6a58d6a8f99a8f0c682a76c377c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c36aa3f8d7ad3ef91ea898c4e4f10fc935186d4ec63d1432940cd05c7fbe048da7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd8b2edda01e597592052506299af9be1d37138825ac2e075fde15ab08267416c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ce583e63bb39e6d588f87cd650eb7e4d7c8c8f19b3fdf1158c7761ef5d2fad6d27c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0fb8294329744758fa467f74c064901f3daf4b2675c8e250e870a533fac495407c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c9b20d2a9fb34341948b8e8840879d659632aee18bdc27e3181b4f257630443fd7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0935fd8cd4b9db46215df9c4b80d596f4a94e4930cc0d104611a0780f45bb68d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c815a84e0c8774e3aecb0d4c40fe509dbedb7f57c54c1e7f971c4a2747586fa7e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf41b2273c390e98c92ae4f22a80a50c11bc8d3e2945e4b7f5db448420dbfe3877c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd9a29198c006d593822b284b92c75dd8737f6f626f3b9043a1eb9754c5f117087c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c540935942b5ba09215dd72cd70bf6f1abdf197fcc59d94e208d6f4a830f1df367c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c52d25ee4ce9e856aabb9cd86e7c216f79652d090aa5dad113103436c911067fe7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c33f5d8ff0f84350c18fa9f6e0f8626d8532af913f57dc2ae406bde35e14317af7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cf40a207cf108ba60164b5f78cafac7011e8aaf05441e14fe84c0b996b73c340f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c73c8fa4e0ae3425245ccd7208856c94c02f54c065d803eca9ce27c034ad8994d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c540cd998dba56754cea1e032f486460ae1ce4e7dfb5a414bb2ff5fb3460f54e97c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477ca096cbe8f24f602f9df753ee289c3d505e56489f1b7314ceaf8726842ff1a7787c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c78e73e7b50141515d0dd52a395d239e3bb2b92e7adf8ae497087102b3aea19c87c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c3878fc828b2b7879a9353af19ba7a144d671411aeeeac3a94c56ade9bed1d6427c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c23e76ffed8469dfb4945606d5f1dadef49f3d34fd43cc39b8118dea6b45c14f47c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c56f6805c9411c390126c277317b80e8125f001979352028354d399d054d195307c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c309b4951ab5f42bf1dd86f3a43e07093c8cd59826683fa087d4e1d37c855077d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c606b0881ebf2b2f3ffb76a36255b1236b4521bbbb3e9ffea64ed1efdc0365a587c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cab9a92bb1cb8d687a154d42559a6e4d9fdff66038b7c83c5025cc6c32dd5ab3f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c27ad077327a64402ec370822b8a1e7309711b2711ba5086085867480daabc8b77c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c2e8e36a90f9a4a1993e001dc6ac569fd3a4e79ce480bad9c3be84b94c5d184a57c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cd0692732d0a5e0ad1a98eee803581018daa36705d1d1a9300bb584a4a6b3f2357c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c198c1c92df831e28a243f92bc016ae97542a07136964b95e4bd0eaecc66c1eab7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5bcff2c6835c402130d3b8c62598032c88a2da9bad409edf8c2bb8935d134f237c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c0f4febfbffbba7e18144cfcca1d61d20661f359139cfb60d38e353bffdbb258f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477cffd90e4e42457c855e0650503c011e1b99f5f07d5d7b107827999d272e4fe1db7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c025cdceec253ba08ac2468a032a4c4a78631dad46093ff07559f154cc01d93117c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c780959e473ce4804c00652d4824b5bffbd946259ffeed7e01928fb92ddd944fd7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4a4d53546b76686f3978443341634f6470364a79504143396f6738344c5350697578324354375151736a48526a6c557866755455536c5336714f595a774437515a58684753566b623352516332417a355368517971777345616774764972397663675a567c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c33647748446639706f7a5543434f373030386d67713333594861777337503359536e756a74747946536a366a5633374c5a685064384931464a6c594530507347314d4e6934614e4b68485232414f42705467745250696e6d75394f694d344e4448714c427c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c58615148503151384766627057574c4b5268514b72336676536435574e336879335634494d4b4667504774417334383839504771474c4b6f4d46397179674d715a47577a68724755575a6b655368615055473471664543533742367446474a75647553697c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c516376536953584b435234464f697269385449746d795470376e673731774b4977336f434a3964624f35457462547a3943367450756132706d386b6474564a504d56696d546a6c7863514f647a65613061724673737848457451464d4264716459776e467c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c636e4d66546b467152575748464a4e4f326c63316f65707476526b3575476475554e7a42573250444f7a6169374c575a575750613034726a4a42663338676e51524b66444453366669346e664637327254487149434850623953333557654a45504d37677c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c34666851414d364f38454f3272696c4b734532694f645533585a5568315157545633786a4475584157417162497a4d5932453447474e787241697a70596c384a637651444e44337833687a4148626d7a4466333951727267784f766c5a74535a4d79716f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c75677548687a7365507a48397938614f4e6570374562646b443744746a3837426672386b506f6f754f55726151724e7475306f59327136766e414e777749564258544c43363057494965496f746a464c6155783261756c6e5357486575734769396649357c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6e6e4b496e716c767a7a457361436c344c704647596c55507665464c3970556b4275524d4932353572416e7030776a424c4e35785951636b5547545254443069564856737a516e4f657a3334566274764f70534133544b4c70727436556866454f3055627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7367344d4e755369626a753772345768636b6c43326c4c51716c686a494747304e7a416f526a7753714f4e46477a4c4a4a57397a3549676c556c7371525767736c4547304e314732466a786347384a675347444e66485758536364795a684f384c6a5a707c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7941795a31315971343276447863647a45436b383270707839454631485a55337067536737477531774f7352517668695670654c467438435743747472646d456a344a6679333654486e416d47487373567831714f595141713954466233376956476e6b7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c366c6e72447268734e6f32756c4f52366944354a377a61775a4c45567a58647536714c7a46515267354841656a67627048365a457558596879743256653566616a50414e7666546f4c6974556d7561546f586d474b614e367444527877587745435768567c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c696a597a7138744634384e30386d573169396c685a6f364f48636e6a6976356f44544e5450346d4a315a7a58616d4f696a5a7038646a4d4a6b5953716a4c464b766774386245493074354e7466727a6f674d6d68575851364c796b5361507474554b72547c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c356c494d766c42576f4174344e36764d6e506c306c42437361756d694557737936306172397a656f5a76694470426641676f70704f50494d395355434361307959304f5971516364396b47704c4a4e5157303541464263466a56374d565638494a4b775a7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c305a5a756c7178677668567155305159354b6157795575384643685934647855316c63617a7a6555475a386f4e4e64476e62714a554b4670634d62364f774f464651443565484e4b774d58377059444158533748734455746656705267326b4c494e454d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5a4735484376456d6d5a545666574d314d584f6c6a69597a58636c675647484b63416845564a4f3577795141697472556533336e62524b5a555433447179637359685649527a4462566b423444514d464a47534c6e71793539727a70504247444770396c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4e6d426f5a5471674d58366361774d42686b346d6349337751656b666e6c67597947646c6e72725a646c3064484146504b785a4c3353354a56664d387151574d6b58587964636c676f396854414b7738356c4a593245764e48374a594d747957666b69697c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c51776635516e4e495072787443375867353473574b7270494e434b68305659456633415665627254714e64514b30584456666e7475435a3635796454685a6f6d534d36574e6e45313048487a7675326578677751476c4b7a484c6a4f42763168375632497c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c69736f396e796d4179443844656e6559396367786d646b4d59666374313555616f36397a756c5a514d58684f386a44366d4a72774b43387848385179327977657577444f4873736964795763466e3650566e39765036536b3277485555335965707051567c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7457624d794b796e643058527151644e7349316e4a3032454a4a4e4837476271726330504b6e304e644e74747477354b325758414b50326a6f46506b635179725470347443553544786f56514951714241645a39515267356e56646e4342436c517743677c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4e53516c62577438695977446b51486a6a437777415461304a59345365633850564d3055796852473562616452466e5a364a6c77716c6b583765476268435230654649444e7039476f374b3642565678753454496634776436326362735231776e795a597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c3344504a767a5239326c3472787952446d6c43325043595974686c486e74776755624e674175647347374833756f7647785678616e6c5a477338624672784a63796e6757466a636265483377556f3366396f676b7a35515133536a6964546941346f6b787c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53774a7a4b745a6337767a57373839416a3257643570384f5976714c306e554a487438684c586847684773654373444c6b704d64434b517133343255684d724f346e54463830626677726959484c7851596154724b7a464374786d79384261324f54764b7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5346547372797a4d446b58454f6d6749696a537a78715062575573636a6a32314f4a68333745467a4f71337443395a4b6a463845564e46477658494334797347377a7a33343471476c6a584e684c6d6f676b5330566c776537344831725a796d6d5666677c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c556e79324f75365161674569695434794a6d5842364a6f4135664236664d335a597050414b4d674951495258734a6c5a54367150464564414843764d666f7a334466746250794b763670676d577162466d736953556c67734c42325150734868765a69617c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4d787546584f6a7a38727048475731357844347a384b665356325958593138796f73313935617933714f795779715254544b67506b6d7935656b5130624f6f7136677031654f53757166654d76557663754253454c657a516f64476e5254444c5852425a7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c3768536b7431506f766e456d447052567530724643397359695436384a336a48385a50705175443949366c626c3358445263386a3972366838306647526d644e6253305061734f496f304978527430797658477465414161714547374f48494f6e79746f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4f6a7943454c35665256634b67714632337a5a39585553556d6633395771464141313332435737694838534f6d6d45664a7464776254656d5a366c4c6d4f624b463243364e79636b75555745346f4942494a564873305468553551364a5146644735376a7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c425a4868324c526a6c5138774273586375757672494c574274725a395576356a6943716162356a6d4d664764777265514d7a386938534a7339787254536b31594b685a4c6436564e6170517748556368693870675157794f684f7858596f4d7a754238767c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c43656b7a4f5a3439464443697161425a367944475137346c62513845796774306b42705a716857554a6e325a6e744d6850664e76624648636a4646484b597855704c484453736e72466467517751586255797654333256627671493563344f72466a566e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4d6d5a4b5479353754703344324b6378394f6c4d5733725a706f755434624f466e4266355a61324a6e55616473634172514b3141446a7052784979714a63565644595172584759617159654a59435943615132435a676a6b4f48796c486a3638384b70567c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c626e5230364a41696f42764a743752725461333950505844764a6f4c49523948324f77586e5735436e6f39486d525933505132757450584f6d397054526d7148304d7563796f434b4342664d69314458487768596233436d32513548306c66525778546b7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c42743562654653544c6e34625831446f716548754a776f70715a524966707a474973484e58717578426f796d665a417532354f4273325147527665574b4271685256554639653241726f4d7565614f363671786d69625358775648346b586232485476477c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4b7945393358427856595838487874714f7a7550647131426c357830755974326b5632634a747873686a714f474a336b376c59387a507a4b4c56423348535751434d5139336472386d494c5266455a61504e396574794d32686456505546766d66626c387c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c59575158754b587574583751564d776833344b6d6b52703767435846304d3650794d41516b6c384438356b524845597a78784c486331436974704e693248586f686e33727931547556316371765950516c726e6e6950757a333748544473354b445932317c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6d7a31524d616b6a4a56725252676874614d47443756586350444f647642414830726d4170774a5766314556354c63336c487769736869354b5738336e7a42624f4e413238394f625969555452584d33733639496369454b3241456758336843474673437c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6959626a6238343848446f62656146546f4b743469387949527145364330504a504f53514b4b4d6965596867594e30636e6a357466743156497452616b754a583771424830644e323256394f7958524a344d32373355537a6278416c5137384e6e7869637c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c50376e6d576a647a564435365778615549425765743671696564694a386c454f6752593030306e4b74684564454357613347656b43757347767a65734949364d6e534163494f4d3056653170474e6f7a6b734b4d4c3068366e6c6f56546976365a5736787c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c505673524f58416656367857326a52766e51473347676f4738624368525562774675646868436d3079484d6f51724a32376556436939386738416c50696d394f4762564c4236415844616269734c616e50565058534c3151616375696d725752734771527c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c543770736233366351715470625a6b6561437a476f6f506f6e51374d753367643076765a6d705a31464a6545796f49784f3531326b4566766c61364633634853763246486976774c3242676f504d4a7549426b51356e39656f354b6637665873377259647c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c46307265483574596c304b304762427a4365455a704f68464b50535861354d4456314871585a66364e50586a516d47686f6136445062386e4f4f624d4b4c6676424c4d6d4150696273356c3668506476513757743655454a7a466c37667073473032536f7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6330795570654b74565262414d616371466b7243437045624761794c6d376e6e594a37624c4673786d7458587258625536746e794952796353554e34535a68457764463849587454656545763246665757716b743849764f74374739574d44675038636c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7756305567343836623847426a4358595256573171545875685865423037456c517335576d34516c326e4e395079587569486c776f365176545357494e6f5475474d6551475632783846754c316933394e65743238386e5051386e736d344b52484f78627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c34434e4e6a486e3674537769485034776a76594a39486c4731444958694f676367544e6e70306a4948464f656b497a72316c305a536174484232754a45424a49696e5678623435497a4b4c4967615a386c5158314f657a6636544d41696c387279524f797c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6967466f4a617a6474484e704266327a3646724658496d715969645451707058745462325279333836486f784d67554a4a396577496f4b77774f666331735a6b625a63526e36506842334364376d4b486b4d33533043636b67666e3578616678586663397c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c674d32506a736d33746c55346575767a3337594b53694d4546396461414a43456c736b764c756d324634574b6d6837676457515632716e797071794e58596839677273504c4348667774504a7a4d504377746c70487a4e574e39784258457931554f48747c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c62777178766f6937597234514f666576346e5152534371514b5177774e756d4d4f4438395265374677316a38366f74597a384768415557397967743979474c633948634f4d37683659723453466c48346a623949545446685959676d755070726e7035587c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c71783649364c744f553847354b345934585863443178464c34574552376b506e484b54446a636733384d594a464c42717745546e316d585637724334436767394f5a425830464f596842784b63585a7972494a69567733514d754b6379516263454158757c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c41446473354d6c6d397a53346c7749753032634e55585a74486177503952527a6a555065765970736d376d78735550694b515675424b4f364c384c4b4f723758624d5a7542654d4e63576173454f4165756c7a5455625076396f334c46307746436d5a337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c68376b6d6d6a78785a364d4d4d5446633743416e637472506b4e445a67564c6e51547a3232556e50525a7372475874446e534f716235336d4878394e674b5957746c4e6a3630594c4f65326b5a6a4d64316f7233696b64504863714e4d6379336e62616a7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c52463849644b6f545736726d345056626836514977384b584d4543727a70546753504d567030443955556b4e78354f435a75626c714c3730647a66434d5a47754569655337485052705a754d53376649706552474e4f77516341684f704e395257627a527c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c447577766255364c6b664350345755764349594742335a3836586f396e6d4c4f473561465034675961474232736c6c5355376f6c596268555a775561477450636f4e4634484c5146666876777345656142726b71737261664e53676a62546a71754f695a7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4e454c45676f506e355a55326849665474783658537371565539683330736c4255573559614961337755564471596d4b6b6776327a4c4e684b556179616a5853335148336f46564970456146746b64447277764f3736564652553150334f795875334f487c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7271416a754773494d326268566b464d6379685068726c445a436a717675664b494454303939774b5a78524b486b6c4b4773704d4a796679596d4d6845505361697a31667a6e506f4a775a6745614f6271314e5a70516c6430586a754331754b716a504e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c47426e6b656c7352577a4970686d3746624f524c486e4c6f646a6b39785773316c4462714e72357a51434f564f4a714f6f376e546b58376d36696c7232436a64336b7247416e34674e493272676733756366646d3238775965476536366e385a767077567c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c777778654164485133576a35385364426c41514d31506d416d70724c483365326e7a364e434272776e7a706a68744a74527035493467386676704f3067535373674e3547656c30714b677a52783838636d324b6738486a725558685a455968497a6365447c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6d34646a3743443832586d685343766a3158746576715452773841446f4e54794657494370397966584b6d4661464d327234364d6b5173464d53385974506e5742546d4f534c52466a32386b784a614f4436704c4b48676c6e633948526d72683345544d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c556a4d436f64534f58627364355775446e5a544a677763417a466e4c494d78745537543861424d564135577450675732334541383043796e364d5a456d6b58366845336636463075794d4f6551793448327546515632345243526c4f31374a367a4139747c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7079684d4f444e74526d596f6f3947696644455a4b437a4c38326333765853496c5a6c59715766363633696b324e71356755544f6c677168387138726452307045396256546750513958595a416654465a416a38477866434f6553505447346e4635366d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c634a56786f486b36614245335a387349466834685037425130356e4e77344377446c545153314d5173674a66635a4d493647504a42656f726142337576745157457a436b716630486a7a4b6d6f6d5569517851684234787a7471544f4a7a796257316c647c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c794b71575145753978383951746577484742646d716b7a42514e416463417341384a6b4f62434f79414c63545079706c597376634355446a78336b787442567038333239764776566679445555533349386f4c79386546743651516e66424464757661507c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c427767676d5347506c426a343639484575463877684f416b5549486d4e46796332466a636c4e527865597039585844677341414165304957776738384c786142306a4262566a7958374d57547a6f5a504f706451644d4379514277705777504b45674c6e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c614c7049756844745562344f4e6c495a355a5064425636784679587741797a79374f347355784a45784368614e4e59474144495a6f456d533237637274425070654b4657356571734576726736644d78476b6d544d787a467342554d31783135377752317c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5756766268716d465a547a4643385945364c307668584d614956594f4d45677970427a75524c5a45756d385569576d657662414359614175547038765263523444676f6951634c386d4a52767433784f34566651564639465337597a614774424b4749717c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c72526f354c6e30784b41625263764a6952343936646e6a52535635553678706c6442684f5035396e76613477774445627842357a4d6365745837625275713378536161763337497036444a7334647273446b50666d547939517852384f4975754773507a7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6f545730346d7866326d54544f44545848544b387777654a4242715845787951676947387534656e655834546f4c45567466535042576e306e424e50593976326930314355334e594f46463368384d7964756445676f73735134354333707639666b41587c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c39794747426367436c65474e66636a7659377048514f664e744d4f6a4b44394a31446471456853506c6f71716f7a4b63775a4862444d4d566e71345852317547767657584145434c51525a34677a35427043415164634271717662386c7443454d7072637c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c69776e475743394d4a33506a6c4257484d4c6969424f59494e37705a7961544575346166773850365a76666257304777424f4531727378346f4e554d4c42673676656251614f4d3039505a5444766633384b55703068686353314f7571536f4b567071567c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5541586f59796c4563626b6f4a646f6d65724934376d38766550436c4a73697353354746725039724f6b446c6c53766e3732663465656e6a524e736f3679474d7361684a4e6831727075417961574b384f503051526358794e654e4a43686d55677273547c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5859586e6d564e76743968476a4a7a75555269614a46534a62674e30584239496e57567a4677565974307444785356687a3368397758477832696c4e4a6a6c5735356b7a72336e4c544563676e566c4d4d744a38656775346f4448564d5246474d5035317c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4a58346b6f70347a55746e47703778703967424575794b71596d563650674c7034447867537344424a5137574c73624b79416454574e394b595346445a6553524865586e77714f35354d52473451667265693830543579484e31394335506a4154344f647c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c534a534d6d30577937707264314d393831414364596e58704e314f7670674e375075495a6b736e664846677966677736455937743955494c4a6b3459714955343073543849376466416b42446f597a534b7562496448684d51624236486c3078424976397c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c67546e4c6d4875436d56736d6d4f6f6a6633584a37754a6f5337344c4f4a3853716c7444524e3533776c664a587353326a447a6859377445326d664756646f616e46423467775643465a6273685269716a48783545527a773143304d45634b5248624a4e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4e4e545751586242634574577567363073466d353168397250566d6d66546551755644394a43794a3653746f597063665470384b75375a3953396c57526f4339393338477478666e6477435a4d4532745230336359513945506a717778527775497331327c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6c314c7975646e734176364c754a4b626d627438523866653948387256546d34495673315a466a703064306b4e796a587a4455664258687a73664f65583038744c726b7957734c4e764256365835536c7743715670766b497a594d6d4d4b446d5a4d4b4d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7855583852357447543153374e4e4256514172476136396b674c6a305952416a426e67696a7a503072765732366c4e4b4c33684c586556335033524349684c39755267426856717765636f386e304957524e7945526876763861584566774578634b5a687c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c716c4874303048775046476b326c747369595167644a694f34477058563939396b457361735875387431676a617a7a676f666b704e723146586774486471476e54586c624b4739317667387446787a52424934655a56484d31306a3466516659447258627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c78584a6f49344a504e4a6e334658396e35525631496e3265554e61466e36634a524b5671457535683368397834384b5a4e744f6c45476e6e686d537667533459735063563835305a635a6d3558565379637849483156553935417561696d597a5a596b587c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c3470695361547448647267545a6d74666130716d507a4751777148666a6c4462794b547774623375733965676a766c686b7a745a5759476965646c6c6d4d6e496d3634453757596f563275336d44617730736c4d6750536b513176304447775142706b797c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c49793876714c754d6c505866694a6671616c65765052684c524a61336a566850686662794f7438303756336673377674697a4d566654775571774e7a6955657058644c43784a7175746a784c675332706645386b6c763242524530586d336461364d41747c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c44486b72456f6a696a6f32487256654f45635352314a694845496b3976654f5a4a596764636e6b6b426350515654756e5663344c4d62676548716232735052324456334438644e786573655a627762567a357739364162445063773750625a6958524c547c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c795a4b31386d754558497575676b566461505131347077694d386a506a3144485065794e6f5266636e417573496676495539784d7055535a515a455a523675773851376d78646d4c424733394c6d46756c3134794c4e6e70435165684d77424b637a55417c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c765545574b6f5a4f466b314d41447271726d4a5569613042304455665a4655696e6d35584153423331714470535646393564546264484333396d3859505137323030507147656a78744c4d62776761726a52716b7054646d333961484e357844546254717c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6d356c4f6a4978423279323550426a4c644c414f395630744446786f334f6166486a52515166664944354467774d50786c663969305a43727558466c7a4572374e364c7462525a434b734735326c736270736b64664b767978594a577359543456766c577c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c45544255534332434e6a6a674a3441446a385279454542535564354f39676a455a4b6f496467385170665557616b716a6835464a7a35706a3869563770354265444e4b4755496c374f33554f63385668336f51736a357a66626a647163437446673361597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c54374c55426e55324d346e6e50563877545a653051613738734b777a6947363043464b33537354756d34463251456d7a72717137716c3447546f3532565a536c757163634956755451304c757558544a623747726a4157324e50537946414858514a306e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6a5a656875767749746c5a714475746d4b6f4647316e35314267496e67427470707676485152673730356f7570464530543975496d6f414d75385a4178694f4d44396b69516f66456a72597857716c4471466141524163627731415239657342644348527c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c725a506a565658616433415939747344705572614f58534b4b324830476c525839753655675553684c6a354a436c63503675504966776a506f4f4453306c475a444348486b714f577a48765a547646504e696e534575795137317a5861354b43766839477c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c795344467262776a655a4e7045303545777179553765684974334551503678624f3046335a3163334f4f696a45654c5973374a6e624f56764670626c6a776b566d504f394550326a74627156645a4a745767475953716a6f4469784e464877506c6250507c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c32534b7a5371364746586958674730526265524d4f765456744464733038375351486678586331715839653144324743346e65494758745a6f7768657663563948307573306c4a4c694c434a423862766d6532535a6c4765474e695a5133576c536845497c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c316f6d445967457661316538664555447a4c7836486568784b4532697538376d6b6a4e377169737137786e615a37456f475a6a6534717a4353724b646f496e7950307433384d6b3337763457737761576c683064796e4467466368544975666e6c7a68687c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c37367146583872634f3141436f304d315533364e7056643550515638795173764b47597843647867345848684f6a38776334377250616c73513671654b47786b636a46456b324a6450676b7270694c71614a484f4851366d4d6e6f6d544b7555525a6d327c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c7552416b556272356c4d6830433465394f44684a67426d7264476c4666364c794e6249796158746a7879395a746558354634444a744e30776a62307037424c4a436a3542366d4b744c4b67324d315668566f516331477a62466e6f424f586165363346307c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c50683874734448765434696c333744796a57774972574a486a4f54796e5455303051686a6a4f43304749617a4644584d6f696b443452626277537a4a4368797159467a356930554f795565326c5a457a374e33317532314f4b716d63774b746b6451646c7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c33475077777939654b635277356c4252466c62646578394762626274695264396d52754964744b4c76723870427836364735394a7336667237674964564d6437727647754f67363877326e5870685257634f74754b794b464367496e514a6c37345073487c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c304371547245424f56366e79474853596670327a687666466c3665514a48637a3974677258483547426934354e4e5552304b6735356a41666644564d615839386566705a4b697662706f34305a4f4850704e496955376e5a4138427955417757464c4d647c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6430416b586d687944516c76576761316f427572746d654a794d746c5668525735663753706367515170634476617349424c5a555832736a454a756e4f39614a643572733777394e4c3965373978464238736a546b7a324d396d594e6b576c6e5243444d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c4e594e64673441544f6f75506c4f3047304a306d6a5752433279427a4a39526c58756d31704d4b31593447374775457734734862636f42354b30736b3039744c7346444666627733343130416a7356624c73614e45434763715a6d6757445165386a4a647c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c594248466d34786e636e594367617379536e3571714c495734327276575932497078647a737a4b754d795651796466666f387443485a704352475643754c384a386138717a484a39357551737854784b524f63704472506b59794b67374a51354a4d6b367c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c31764732355a6e6a446a6654677145766378766d5a4374596e75774a4557637569496b6276786b574671464c45393448757152695162363276727a5a647a686c37736d714e7663694a485564454d4959307136487233784b6b557a6c6a467865584875417c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c6651763545514c72693971504b5165546b486b636f635845786f3048526a32575a6c51745a72493870584c584450484c6b504c79517931644b504c725942634c4e5332433741796b6c37384d4e446e5669596b596b3930534f423841326162465133364e7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5843413176313851736635504b4c723847467231346a486b6a6766336d506d314d4156627377427339515037467747544c434534537759693831425270327672635631326d614d744377395445314e5a525679796e51336532633362376d785277337c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c00000000000000000000000000000000000000000000000000000000000000057c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631346d3250624c4832597436693672546734574d6a5a4b3842324850624e69347a47464d56534534724362673444634a6e3138486b734e5a58513936557451615272766639757532794a6f376571437a5a57326a6641566e597c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563151615254743652347737365a4c67534a58444d71684561506d4b6b3371414b4e7665524b34486578716e45755557776255626254373241524a683371376a5a7a614345486b54787246593570794d61476942595557426d517c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c5369675631616d716e55546263386448656243535a6b77414362445435434b6e6345555070594743786b4a317861586f393451794b586b685037634258327a616b796434466e7a34617757724834374c3878524e366553376d6f3942727c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c53696756316436315035577774726a54527a4237784850735436676a61476844763539596a6a52477066413863626d38576667687570634b6d637258387171444e43396a4646334b6d46527a7a675845336b36474c314d796d467439627c424c4f434b434841494e5f444154415f5345474d454e545f535452494e477c536967563155483236544230354133446441634659574355706d4850394863456e5a577731635645543973576e7a717130353644313175393773374e51694659524b34644866695774624d53614361394d31504d41705854784834564d7c424c4f434b434841494e5f52455345525645445f42595445535f454e447c000500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005"

  #define pointer_reset_all \
  pointer_reset(data); \
  pointer_reset(previous_block_height); \
  pointer_reset(block_height); \
  pointer_reset(blockchain_data.network_version_data); \
  pointer_reset(blockchain_data.timestamp_data); \
  pointer_reset(blockchain_data.previous_block_hash_data); \
  pointer_reset(blockchain_data.block_height_data); \
  pointer_reset(blockchain_data.nonce_data); \
  pointer_reset(blockchain_data.block_reward_transaction_version_data); \
  pointer_reset(blockchain_data.unlock_block_data); \
  pointer_reset(blockchain_data.block_reward_input_data); \
  pointer_reset(blockchain_data.vin_type_data); \
  pointer_reset(blockchain_data.block_height_data); \
  pointer_reset(blockchain_data.block_reward_output_data); \
  pointer_reset(blockchain_data.block_reward_data); \
  pointer_reset(blockchain_data.stealth_address_output_tag_data); \
  pointer_reset(blockchain_data.stealth_address_output_data); \
  pointer_reset(blockchain_data.extra_bytes_size_data); \
  pointer_reset(blockchain_data.transaction_public_key_tag_data); \
  pointer_reset(blockchain_data.transaction_public_key_data); \
  pointer_reset(blockchain_data.transaction_public_key_data); \
  pointer_reset(blockchain_data.extra_nonce_tag_data); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.block_producer_public_address); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_public_key_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_proof_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.vrf_data); \
  pointer_reset(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data); \
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) \
  { \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count]); \
    pointer_reset(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count]); \
  } \
  pointer_reset(blockchain_data.ringct_version_data); \
  pointer_reset(blockchain_data.transaction_amount_data); \
  for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++) \
  { \
    pointer_reset(blockchain_data.transactions[count]); \
  }



  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || previous_block_height == NULL || block_height == NULL)
  {
    if (data != NULL)
    {
      pointer_reset(data);
    }
    if (previous_block_height != NULL)
    {
      pointer_reset(previous_block_height);
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



  // get the height of the block to get the block blob from
  if (block_data.length() == 64)
  {
    // the data is a block hash
    hash_parsed = parse_hash256(block_data, block_hash);
    if(!hash_parsed)
    {
      color_print("Could not get the blocks data","red"); 
      pointer_reset_all;     
      return true;
    }
    // get the block height from the block hash
    get_block_req.hash = epee::string_tools::pod_to_hex(block_hash);
    get_block_req.fill_pow_hash = true;
    if (m_is_rpc)
    {
      if (!m_rpc_client->json_rpc_request(get_block_req, get_block_res, "getblock", "Unsuccessful"))
      {
        color_print("Could not get the blocks data","red");
        pointer_reset_all;
        return true;
      }
    }
    else
    {
      if (!m_rpc_server->on_get_block(get_block_req, get_block_res, error_resp) || get_block_res.status != CORE_RPC_STATUS_OK)
      {
        color_print("Could not get the blocks data","red");
        pointer_reset_all;
        return true;
      }
    }

    // error check
    if (get_block_res.block_header.height < HF_BLOCK_HEIGHT_PROOF_OF_STAKE)
    {
      color_print("This block was produced before X-CASH was using the X-CASH proof of stake consensus mechanism","red");
      pointer_reset_all;
      return true; 
    }
    sprintf(block_height,"%ld",get_block_res.block_header.height); 
    current_block_height = (std::size_t)get_block_res.block_header.height;
    get_block_res.block_header.height--; 
    sprintf(previous_block_height,"%ld",get_block_res.block_header.height);  
  }
  else
  {
    // the data is a block height
    sscanf(block_data.c_str(),"%zu",&count);
    // error check
    if (count < HF_BLOCK_HEIGHT_PROOF_OF_STAKE)
    {
      color_print("This block was produced before X-CASH was using the X-CASH proof of stake consensus mechanism","red");
      pointer_reset_all;
      return true; 
    }
    memcpy(block_height,block_data.c_str(),strnlen(block_data.c_str(),100));
    current_block_height = count;
    count--;
    sprintf(previous_block_height,"%ld",count); 
  } 

  // get the network block string
  sscanf(block_height,"%zu",&get_block_req.height);
  get_block_req.fill_pow_hash = false;
  if (m_is_rpc)
  {
    if (!m_rpc_client->json_rpc_request(get_block_req, get_block_res, "getblock", "Unsuccessful"))
    {
      color_print("Could not get the blocks data","red");
      pointer_reset_all;
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_block(get_block_req, get_block_res, error_resp) || get_block_res.status != CORE_RPC_STATUS_OK)
    {
      color_print("Could not get the blocks data","red");
      pointer_reset_all;
      return true;
    }
  }
  network_block_string = get_block_res.blob;  
  previous_block_hash = get_block_res.block_header.prev_hash.c_str();

  // get the data hash
  data_hash = network_block_string.substr(network_block_string.find(BLOCKCHAIN_RESERVED_BYTES_START)+66,DATA_HASH_LENGTH);

  // get the previous network block string
  sscanf(previous_block_height,"%zu",&get_block_req.height);
  get_block_req.fill_pow_hash = false;
  if (m_is_rpc)
  {
    if (!m_rpc_client->json_rpc_request(get_block_req, get_block_res, "getblock", "Unsuccessful"))
    {
      color_print("Could not get the blocks data","red");
      pointer_reset_all;
      return true;
    }
  }
  else
  {
    if (!m_rpc_server->on_get_block(get_block_req, get_block_res, error_resp) || get_block_res.status != CORE_RPC_STATUS_OK)
    {
      color_print("Could not get the blocks data","red");
      pointer_reset_all;
      return true;
    }
  }
  previous_network_block_string = get_block_res.blob;  

  // get the previous data hash
  previous_data_hash = previous_network_block_string.substr(previous_network_block_string.find(BLOCKCHAIN_RESERVED_BYTES_START)+66,DATA_HASH_LENGTH);

  // initialize the network_data_nodes_list struct
  network_data_nodes_list.network_data_nodes_public_address[0] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_1;
  network_data_nodes_list.network_data_nodes_IP_address[0] = NETWORK_DATA_NODE_IP_ADDRESS_1;
  network_data_nodes_list.network_data_nodes_public_address[1] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_2;
  network_data_nodes_list.network_data_nodes_IP_address[1] = NETWORK_DATA_NODE_IP_ADDRESS_2; 

  // create the message
  message = "{\r\n \"message_settings\": \"NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES\",\r\n \"block_height\": \"" + std::to_string(current_block_height) + "\",\r\n}";  

  // send the message to a random network data node
  while (string != "")
  {
    string = send_and_receive_data(network_data_nodes_list.network_data_nodes_IP_address[(int)(rand() % NETWORK_DATA_NODES_AMOUNT + 1)],MESSAGE);
  }

  // verify the message
  if (verify_data(string) == 0)
  {
    color_print("Invalid network data node message","red");
    pointer_reset_all;
    return true; 
  }  

  // create the message
  message = "{\r\n \"message_settings\": \"NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES\",\r\n \"block_height\": \"" + std::to_string(current_block_height - 1) + "\",\r\n}";  

  // send the message to a random network data node
  while (string2 != "")
  {
    string2 = send_and_receive_data(network_data_nodes_list.network_data_nodes_IP_address[(int)(rand() % NETWORK_DATA_NODES_AMOUNT + 1)],MESSAGE);
  }

  // verify the message
  if (verify_data(string2) == 0)
  {
    color_print("Invalid network data node message","red");
    pointer_reset_all;
    return true; 
  }  

  // get the network block string
  count = string.find("\"reserve_bytes\": \"")+18;
  count2 = string.find(",\r\n \"public_address\"");
  network_block_string = string.substr(count,count2 - count);

  // get the previous_network block string
  count = string.find("\"reserve_bytes\": \"")+18;
  count2 = string.find(",\r\n \"public_address\"");
  previous_network_block_string = string.substr(count,count2 - count);

  // check if the data hash matches the network block string
  memset(data,0,strlen(data));
  crypto_hash_sha512((unsigned char*)data,(const unsigned char*)network_block_string.c_str(),strlen(network_block_string.c_str()));
  if (memcmp(data,data_hash.c_str(),DATA_HASH_LENGTH) != 0)
  {
    color_print("Invalid data hash","red");
    pointer_reset_all;
    return true; 
  }

  // check if the previous data hash matches the previous_network block string
  memset(data,0,strlen(data));
  crypto_hash_sha512((unsigned char*)data,(const unsigned char*)previous_network_block_string.c_str(),strlen(previous_network_block_string.c_str()));
  if (memcmp(data,previous_data_hash.c_str(),DATA_HASH_LENGTH) != 0)
  {
    color_print("Invalid data hash","red");
    pointer_reset_all;
    return true; 
  }

  // convert the network_block_string to a blockchain_data struct
  if (network_block_string_to_blockchain_data(network_block_string.c_str(),(const char*)block_height) == 0)
  {
    color_print("Invalid block","red");
    pointer_reset_all;
    return true; 
  }

  // verify the network block string
  if (verify_network_block_data(block_height,previous_block_hash.c_str(),previous_network_block_string.c_str()) == 0)
  {
    color_print("Invalid block","red");
    pointer_reset_all;
    return true; 
  }

  // print the network block string
  // print the block data, reserve bytes and transactions in a different color
  fprintf(stderr,"\nBlock blob\n\n");
  count = network_block_string.find(BLOCKCHAIN_RESERVED_BYTES_START);
  color_print(network_block_string.substr(0,count).c_str(),"green");
  count += reserve_bytes_data.length();
  color_print(reserve_bytes_data.c_str(),"red");
  color_print(network_block_string.substr(count,2).c_str(),"green");
  count += 2;
  color_print(network_block_string.substr(count).c_str(),"blue");
  fprintf(stderr,"\n\n");
  color_print("Block data\n","green");
  color_print("Reserve bytes\n","red");
  color_print("Transactions data\n\n\n\n","blue");
  count = 0;

  // print each section in the block data
  fprintf(stderr,"Block data\n\n"); 
 
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

  sscanf(block_height, "%zu", &count);
  if (count >= HF_BLOCK_HEIGHT_PROOF_OF_STAKE)
  { 
    color_print("PASSED! Network Version - Hard fork version 13\n","green");
  }
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Timestamp - ",20);
  sprintf(data+20,"%zu",blockchain_data.timestamp);
  color_print(data,"blue");
  color_print("\nPASSED! Previous Block Hash\n","red");
  if (memcmp(blockchain_data.nonce_data,BLOCK_PRODUCER_NETWORK_BLOCK_NONCE,8) == 0)
  {
    color_print("PASSED! Nonce Data - Created by the block producer\n","green");
  }
  else
  {
    color_print("PASSED! Nonce Data - Created by the consnesus node\n","green");
  }
  color_print("PASSED! Block Reward Transaction Version - Should always be 02\n","blue");
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Unlock Block - Block ",29);
  sprintf(data+29,"%zu",blockchain_data.unlock_block);
  color_print(data,"red");
  color_print("\nPASSED! Block Reward Input - Should always be 01\n","green");
  color_print("PASSED! Vin Type - Should always be ff\n","blue");
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Block Height - Block ",29);
  sprintf(data+29,"%zu",blockchain_data.block_height);
  color_print(data,"red");
  color_print("\nPASSED! Block Reward Output - Should always be 01\n","green");
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Block Reward - ",23);
  sprintf(data+23,"%zu",blockchain_data.block_reward);
  color_print(data,"blue");
  color_print("\nPASSED! Stealth Address Output Tag - Should always be 02\n","red");
  color_print("PASSED! Stealth Address Output\n","green");
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Extra Bytes Size - ",27);
  sprintf(data+27,"%zu",blockchain_data.extra_bytes_size);
  color_print(data,"blue");
  color_print("\nPASSED! Transaction Public Key Tag - Should always be 01\n","red");
  color_print("PASSED! Extra Nonce Tag - Should always be 02\n","green");
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Reserve Bytes Size - ",29);
  sprintf(data+29,"%zu",blockchain_data.reserve_bytes_size);
  color_print(data,"blue");
  color_print("\nPASSED! Transaction Public Key Tag - Should always be 01\n","red");
  color_print("PASSED! RingCT Version - Should always be 00\n","green");

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
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data_round_part_4,"blue");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data_round_part_4,"red");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_proof_data_round_part_4,"green");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data_round_part_4,"blue");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_data_round_part_4,"red");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  color_print(blockchain_data.blockchain_reserve_bytes.vrf_data,"green");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count],"red");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count],"red");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count],"red");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count],"red");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }
  color_print(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,"green");
  fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    color_print(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count],"blue");    
    fprintf(stderr,BLOCKCHAIN_DATA_SEGMENT_STRING);
  }

  // verify the reserve bytes
  fprintf(stderr,"\n\nVerifying reserve bytes\n\n");

  // write the start test message
  color_print(TEST_OUTLINE,"blue");
  fprintf(stderr,"\n");
  fprintf(stderr,"\033[1;34mVerifying reserve bytes - Total test: %d\033[0m\n",RESERVE_BYTES_TOTAL_TEST);
  color_print(TEST_OUTLINE,"blue");
  fprintf(stderr,"\n\n");

  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Block Producer Delegate Name - ",39);
  memcpy(data+39,blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,strlen(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name));
  color_print(data,"green");
  fprintf(stderr,"\n");
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Block Producer Public Address - ",40);
  memcpy(data+40,blockchain_data.blockchain_reserve_bytes.block_producer_public_address,strlen(blockchain_data.blockchain_reserve_bytes.block_producer_public_address));
  color_print(data,"blue");
  fprintf(stderr,"\n");
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Block Producer Node Backup Count - ",43);
  memcpy(data+43,blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,strlen(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count));
  color_print(data,"red");
  fprintf(stderr,"\n");
  memset(data,0,strlen(data));
  memcpy(data,"PASSED! Block Producer Backup Nodes Names - ",44);
  memcpy(data+44,blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names,strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names));
  color_print(data,"green");
  fprintf(stderr,"\n");
  color_print("PASSED! VRF Secret Key Round Part 4\n","red");
  color_print("PASSED! VRF Public Key Round Part 4\n","red");  
  color_print("PASSED! VRF Alpha String Round Part 4\n","red");
  color_print("PASSED! VRF Proof Round Part 4\n","green");
  color_print("PASSED! VRF Beta String Round Part 4\n","blue");
  color_print("PASSED! VRF Data Round Part 4\n","red");
  color_print("PASSED! VRF Data\n","green");
  color_print("PASSED! Previous Block Hash\n","blue");

  color_print("PASSED! Block Validation Nodes Signatures\n","green");
  fprintf(stderr,"\n");

  // write the end test message
  fprintf(stderr,"\n");
  color_print(TEST_OUTLINE,"green");
  fprintf(stderr,"\n\033[1;32mVerifying reserve bytes - Passed test: %d, Failed test: 0\033[0m\n",RESERVE_BYTES_TOTAL_TEST);
  color_print(TEST_OUTLINE,"green");
  fprintf(stderr,"\n\n");  

  // print each section in the Transaction Data
  fprintf(stderr,"Transaction Data\n\n"); 
 
  color_print(blockchain_data.transaction_amount_data,"green");
  for (count = 0; count < blockchain_data.transaction_amount; count++)
  {
    color_print(blockchain_data.transactions[count],"blue");
  }

  // verify the transaction data
  fprintf(stderr,"\n\n");
  memset(data,0,strlen(data));
  memcpy(data,"Total transactions in the network block - ",42);
  sprintf(data+42,"%zu",blockchain_data.transaction_amount);
  memcpy(data+strlen(data),"\n",1);
  color_print(data,"green");

  for (count = 0; count < blockchain_data.transaction_amount; count++)
  {
    color_print(blockchain_data.transactions[count],"blue");
    fprintf(stderr,"\n");
  }

  pointer_reset_all;
  return true;

  #undef pointer_reset_all
  #undef BLOCK_DATA_TOTAL_TEST
  #undef RESERVE_BYTES_TOTAL_TEST
}

}// namespace daemonize


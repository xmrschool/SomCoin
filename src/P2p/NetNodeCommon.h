// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero project
// Copyright (c) 2014-2018, The Forknote developers
// Copyright (c) 2016-2019, The Karbowanec developers
//
// This file is part of SoM.

#pragma once

#include <list>
#include <boost/uuid/uuid.hpp>

#include "CryptoNote.h"
#include "P2pProtocolTypes.h"
#include "CryptoNoteConfig.h"

namespace CryptoNote {

  struct CryptoNoteConnectionContext;

  struct IP2pEndpoint {
    virtual void relay_notify_to_all(int command, const BinaryArray& data_buff, const net_connection_id* excludeConnection) = 0;
    virtual bool invoke_notify_to_peer(int command, const BinaryArray& req_buff, const CryptoNote::CryptoNoteConnectionContext& context) = 0;
    virtual uint64_t get_connections_count()=0;
    virtual bool ban_host(const uint32_t address_ip, time_t seconds = CryptoNote::P2P_IP_BLOCKTIME) = 0;
    virtual bool unban_host(const uint32_t address_ip) = 0;
    virtual void drop_connection(CryptoNoteConnectionContext& context, bool add_fail) = 0;
    virtual std::map<uint32_t, time_t> get_blocked_hosts() = 0;
    virtual void for_each_connection(std::function<void(CryptoNote::CryptoNoteConnectionContext&, PeerIdType)> f) = 0;
    // can be called from external threads
    virtual void externalRelayNotifyToAll(int command, const BinaryArray& data_buff, const net_connection_id* excludeConnection) = 0;
    virtual void externalRelayNotifyToList(int command, const BinaryArray &data_buff, const std::list<boost::uuids::uuid> relayList) = 0;
  };

  struct p2p_endpoint_stub: public IP2pEndpoint {
    virtual void relay_notify_to_all(int command, const BinaryArray& data_buff, const net_connection_id* excludeConnection) override {}
    virtual bool invoke_notify_to_peer(int command, const BinaryArray& req_buff, const CryptoNote::CryptoNoteConnectionContext& context) override { return true; }
    virtual bool ban_host(const uint32_t address_ip, time_t seconds) override { return true; }
    virtual bool unban_host(const uint32_t address_ip) override { return true; }
    virtual void drop_connection(CryptoNoteConnectionContext& context, bool add_fail) override {}
    virtual std::map<uint32_t, time_t> get_blocked_hosts() override { return std::map<uint32_t, time_t>(); }
    virtual void for_each_connection(std::function<void(CryptoNote::CryptoNoteConnectionContext&, PeerIdType)> f) override {}
    virtual uint64_t get_connections_count() override { return 0; }   
    virtual void externalRelayNotifyToAll(int command, const BinaryArray& data_buff, const net_connection_id* excludeConnection) override {}
    virtual void externalRelayNotifyToList(int command, const BinaryArray &data_buff, const std::list<boost::uuids::uuid> relayList) override {}
  };
}

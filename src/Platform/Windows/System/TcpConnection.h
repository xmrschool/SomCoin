// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <cstdint>
#include <string>

namespace System {

class Dispatcher;
class Ipv4Address;

class TcpConnection {
public:
  TcpConnection();
  TcpConnection(const TcpConnection&) = delete;
  TcpConnection(TcpConnection&& other);
  ~TcpConnection();
  TcpConnection& operator=(const TcpConnection&) = delete;
  TcpConnection& operator=(TcpConnection&& other);
  size_t read(uint8_t* data, size_t size);
  size_t write(const uint8_t* data, size_t size);
  std::pair<Ipv4Address, uint16_t> getPeerAddressAndPort() const;

private:
  friend class TcpConnector;
  friend class TcpListener;

  Dispatcher* dispatcher;
  size_t connection;
  void* readContext;
  void* writeContext;

  TcpConnection(Dispatcher& dispatcher, size_t connection);
};

}

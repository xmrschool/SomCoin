// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, The Karbo developers
//
// This file is part of SoM.

#pragma once

#include <boost/program_options.hpp>

namespace CryptoNote {

class RpcServerConfig {

public:
  RpcServerConfig();

  static void initOptions(boost::program_options::options_description& desc);
  void init(const boost::program_options::variables_map& options);

  bool isEnabledSSL() const;
  uint16_t getBindPort() const;
  uint16_t getBindPortSSL() const;
  std::string getBindIP() const;
  std::string getBindAddress() const;
  std::string getBindAddressSSL() const;
  std::string getDhFile() const;
  std::string getChainFile() const;
  std::string getKeyFile() const;

//private:
  bool        restrictedRPC;
  bool        enableSSL;
  uint16_t    bindPort;
  uint16_t    bindPortSSL;
  std::string bindIp;
  std::string dhFile;
  std::string chainFile;
  std::string keyFile;
  std::string enableCors;
  std::string contactInfo;
  std::string nodeFeeAddress;
  std::string nodeFeeAmountStr;
  std::string nodeFeeViewKey;
};

}

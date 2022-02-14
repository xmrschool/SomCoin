// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <cstdint>
#include <boost/program_options.hpp>

namespace PaymentService {

class RpcNodeConfiguration {
public:
  RpcNodeConfiguration();

  static void initOptions(boost::program_options::options_description& desc);
  void init(const boost::program_options::variables_map& options);

  std::string m_daemon_host;
  uint16_t m_daemon_port;
  uint16_t m_daemon_port_ssl;
  bool m_enable_ssl;
  std::string m_chain_file = "";
  std::string m_key_file = "";
  std::string m_dh_file = "";
};

} //namespace PaymentService

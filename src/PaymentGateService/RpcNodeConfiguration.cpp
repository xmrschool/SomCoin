// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#include "RpcNodeConfiguration.h"
#include "CryptoNoteConfig.h"

namespace PaymentService {

namespace po = boost::program_options;

RpcNodeConfiguration::RpcNodeConfiguration() {
  m_daemon_host = "";
  m_daemon_port = 0;
  m_daemon_port_ssl = 0;
  m_enable_ssl = false;
  m_chain_file = "";
  m_key_file = "";
  m_dh_file = "";
}

void RpcNodeConfiguration::initOptions(boost::program_options::options_description& desc) {
  desc.add_options()
    ("daemon-address", po::value<std::string>()->default_value("127.0.0.1"), "daemon address")
    ("daemon-port", po::value<uint16_t>()->default_value((uint16_t) CryptoNote::RPC_DEFAULT_PORT), "daemon port")
    ("daemon-port-ssl", po::value<uint16_t>()->default_value((uint16_t) CryptoNote::RPC_DEFAULT_SSL_PORT), "daemon port ssl")
    ("daemon-ssl-enable", po::bool_switch(), "")
    ("daemon-chain-file", po::value<std::string>()->default_value(std::string(CryptoNote::RPC_DEFAULT_CHAIN_FILE)), "")
    ("daemon-key-file", po::value<std::string>()->default_value(std::string(CryptoNote::RPC_DEFAULT_KEY_FILE)), "")
    ("daemon-dh-file", po::value<std::string>()->default_value(std::string(CryptoNote::RPC_DEFAULT_DH_FILE)), "");
}

void RpcNodeConfiguration::init(const boost::program_options::variables_map& options) {
  if (options.count("daemon-address") != 0 && (!options["daemon-address"].defaulted() || m_daemon_host.empty())) {
    m_daemon_host = options["daemon-address"].as<std::string>();
  }

  if (options.count("daemon-port") != 0 && (!options["daemon-port"].defaulted() || m_daemon_port == 0)) {
    m_daemon_port = options["daemon-port"].as<uint16_t>();
  }

  if (options.count("daemon-port-ssl") != 0 && (!options["daemon-port-ssl"].defaulted() || m_daemon_port_ssl == 0)) {
    m_daemon_port_ssl = options["daemon-port-ssl"].as<uint16_t>();
  }

  if (options["daemon-ssl-enable"].as<bool>()){
    m_enable_ssl = true;
  }

  if (options.count("daemon-chain-file") != 0 && (!options["daemon-chain-file"].defaulted() || m_chain_file.empty())) {
    m_chain_file = options["daemon-chain-file"].as<std::string>();
  }

  if (options.count("daemon-key-file") != 0 && (!options["daemon-key-file"].defaulted() || m_key_file.empty())) {
    m_key_file = options["daemon-key-file"].as<std::string>();
  }

  if (options.count("daemon-dh-file") != 0 && (!options["daemon-dh-file"].defaulted() || m_dh_file.empty())) {
    m_dh_file = options["daemon-dh-file"].as<std::string>();
  }
}

} //namespace PaymentService

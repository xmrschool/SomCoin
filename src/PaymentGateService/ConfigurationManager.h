// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include "CryptoNoteCore/CoreConfig.h"
#include "PaymentServiceConfiguration.h"
#include "P2p/NetNodeConfig.h"
#include "RpcNodeConfiguration.h"

namespace PaymentService {

class ConfigurationManager {
public:
  ConfigurationManager();
  bool init(int argc, char** argv);

  bool startInprocess;
  Configuration gateConfiguration;
  CryptoNote::NetNodeConfig netNodeConfig;
  CryptoNote::CoreConfig coreConfig;
  RpcNodeConfiguration remoteNodeConfig;
};

} //namespace PaymentService

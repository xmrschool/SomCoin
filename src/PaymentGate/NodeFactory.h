// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include "INode.h"

#include <string>

namespace PaymentService {

class NodeFactory {
public:
  static CryptoNote::INode* createNode(const std::string& daemonAddress,
                                       uint16_t daemonPort,
                                       const std::string &daemonPath,
                                       const bool &daemonSSL);
  static CryptoNote::INode* createNodeStub();
private:
  NodeFactory();
  ~NodeFactory();

  CryptoNote::INode* getNode(const std::string& daemonAddress,
                             uint16_t daemonPort,
                             const std::string &daemonPath,
                             const bool &daemonSSL);

  static NodeFactory factory;
};

} //namespace PaymentService

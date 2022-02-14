// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

namespace CryptoNote {
  class IBlockchainStorageObserver {
  public:
    virtual ~IBlockchainStorageObserver() {
    }

    virtual void blockchainUpdated() = 0;
  };
}

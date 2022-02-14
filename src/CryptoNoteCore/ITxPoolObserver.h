// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

namespace CryptoNote {
class ITxPoolObserver {
public:
  virtual ~ITxPoolObserver() {
  }

  virtual void txDeletedFromPool() = 0;
};
}

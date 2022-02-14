// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

namespace CryptoNote {

class ICoreObserver {
public:
  virtual ~ICoreObserver() {};
  virtual void blockchainUpdated() {};
  virtual void poolUpdated() {};
};

}

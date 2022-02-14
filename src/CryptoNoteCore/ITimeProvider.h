// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <time.h>

namespace CryptoNote {

  struct ITimeProvider {
    virtual time_t now() = 0;
    virtual ~ITimeProvider() {}
  };

  struct RealTimeProvider : public ITimeProvider {
    virtual time_t now() override {
      return time(nullptr);
    }
  };

}

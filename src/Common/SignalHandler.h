// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once 

#include <functional>

namespace Tools {
  
  class SignalHandler
  {
  public:
    static bool install(std::function<void(void)> t);
  };
}

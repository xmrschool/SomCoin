// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <exception>

namespace System {

class InterruptedException : public std::exception {
  public:
    virtual const char* what() const throw() override {
      return "interrupted";
    }
};

}

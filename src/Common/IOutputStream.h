// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <cstddef>

namespace Common {

class IOutputStream {
public:
  virtual ~IOutputStream() { }
  virtual size_t writeSome(const void* data, size_t size) = 0;
};

}

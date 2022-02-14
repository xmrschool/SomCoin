// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <cstdint>
#include <vector>
#include "IOutputStream.h"

namespace Common {

class VectorOutputStream : public IOutputStream {
public:
  VectorOutputStream(std::vector<uint8_t>& out);
  VectorOutputStream& operator=(const VectorOutputStream&) = delete;
  size_t writeSome(const void* data, size_t size) override;

private:
  std::vector<uint8_t>& out;
};

}

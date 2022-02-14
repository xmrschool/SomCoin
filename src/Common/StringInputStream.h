// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <string>
#include "IInputStream.h"

namespace Common {

class StringInputStream : public IInputStream {
public:
  StringInputStream(const std::string& in);
  size_t readSome(void* data, size_t size) override;

private:
  const std::string& in;
  size_t offset;
};

}

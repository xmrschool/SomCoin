// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <string>
#include "IOutputStream.h"

namespace Common {

class StringOutputStream : public IOutputStream {
public:
  StringOutputStream(std::string& out);
  size_t writeSome(const void* data, size_t size) override;

private:
  std::string& out;
};

}

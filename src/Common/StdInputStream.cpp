// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#include "StdInputStream.h"

namespace Common {

StdInputStream::StdInputStream(std::istream& in) : in(in) {
}

size_t StdInputStream::readSome(void* data, size_t size) {
  in.read(static_cast<char*>(data), size);
  return in.gcount();
}

}

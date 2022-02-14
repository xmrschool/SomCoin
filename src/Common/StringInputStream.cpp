// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#include "StringInputStream.h"
#include <string.h>

namespace Common {

StringInputStream::StringInputStream(const std::string& in) : in(in), offset(0) {
}

size_t StringInputStream::readSome(void* data, size_t size) {
  if (size > in.size() - offset) {
    size = in.size() - offset;
  }

  memcpy(data, in.data() + offset, size);
  offset += size;
  return size;
}

}

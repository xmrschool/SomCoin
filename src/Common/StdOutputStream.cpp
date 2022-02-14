// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#include "StdOutputStream.h"

namespace Common {

StdOutputStream::StdOutputStream(std::ostream& out) : out(out) {
}

size_t StdOutputStream::writeSome(const void* data, size_t size) {
  out.write(static_cast<const char*>(data), size);
  if (out.bad()) {
    return 0;
  }

  return size;
}

}

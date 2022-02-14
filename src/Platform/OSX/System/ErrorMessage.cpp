// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#include "ErrorMessage.h"
#include <cerrno>
#include <cstring>

namespace System {

std::string lastErrorMessage() {
  return errorMessage(errno);
}

std::string errorMessage(int err) {
  return "result=" + std::to_string(err) + ", " + std::strerror(err);
}

}

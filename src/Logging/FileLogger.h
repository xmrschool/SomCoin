// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <fstream>
#include "StreamLogger.h"

namespace Logging {

class FileLogger : public StreamLogger {
public:
  FileLogger(Level level = DEBUGGING);
  void init(const std::string& filename);

private:
  std::ofstream fileStream;
};

}

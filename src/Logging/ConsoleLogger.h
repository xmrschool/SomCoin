// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <mutex>
#include "CommonLogger.h"

namespace Logging {

class ConsoleLogger : public CommonLogger {
public:
  ConsoleLogger(Level level = DEBUGGING);

protected:
  virtual void doLogString(const std::string& message) override;

private:
  std::mutex mutex;
};

}

// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <set>
#include "ILogger.h"

namespace Logging {

class CommonLogger : public ILogger {
public:

  virtual void operator()(const std::string& category, Level level, boost::posix_time::ptime time, const std::string& body) override;
  virtual void enableCategory(const std::string& category);
  virtual void disableCategory(const std::string& category);
  virtual void setMaxLevel(Level level);

  void setPattern(const std::string& pattern);

protected:
  std::set<std::string> disabledCategories;
  Level logLevel;
  std::string pattern;

  CommonLogger(Level level);
  virtual void doLogString(const std::string& message);
};

}

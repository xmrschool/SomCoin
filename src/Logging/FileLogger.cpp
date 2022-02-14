// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#include "FileLogger.h"

namespace Logging {

FileLogger::FileLogger(Level level) : StreamLogger(level) {
}

void FileLogger::init(const std::string& fileName) {
  fileStream.open(fileName, std::ios::app);
  StreamLogger::attachToStream(fileStream);
}

}

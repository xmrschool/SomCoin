// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once 

#include <string>
#include <system_error>

namespace Tools
{
  std::string getDefaultDataDirectory();
  std::string get_os_version_string();
  bool create_directories_if_necessary(const std::string& path);
  std::error_code replace_file(const std::string& replacement_name, const std::string& replaced_name);
  bool directoryExists(const std::string& path);
}

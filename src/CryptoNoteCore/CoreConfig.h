// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// Copyright (c) 2016-2021, The SoM developers
// This file is part of SoM.

#pragma once

#include <string>

#include <boost/program_options.hpp>

namespace CryptoNote {

class CoreConfig {
public:
  CoreConfig();

  static void initOptions(boost::program_options::options_description& desc);
  void init(const boost::program_options::variables_map& options);

  std::string configFolder;
  bool configFolderDefaulted = true;
};

} //namespace CryptoNote

// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <string>
#include <ostream>

namespace CryptoNote {

void importLegacyKeys(const std::string& legacyKeysFilename, const std::string& password, std::ostream& destination);

} //namespace CryptoNote

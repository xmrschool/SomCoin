// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include "crypto/crypto.h"

#include <stdint.h>

namespace CryptoNote {

class ISerializer;

//This is DTO structure. Do not change it.
struct KeysStorage {
  uint64_t creationTimestamp;

  Crypto::PublicKey spendPublicKey;
  Crypto::SecretKey spendSecretKey;

  Crypto::PublicKey viewPublicKey;
  Crypto::SecretKey viewSecretKey;

  void serialize(ISerializer& serializer, const std::string& name);
};

} //namespace CryptoNote

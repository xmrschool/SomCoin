// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// Copyright (c) 2016-2021, The SoM developers
// This file is part of SoM.

#include "CryptoNoteBasic.h"
#include "crypto/crypto.h"

namespace CryptoNote {

KeyPair generateKeyPair() {
  KeyPair k;
  Crypto::generate_keys(k.publicKey, k.secretKey);
  return k;
}

}

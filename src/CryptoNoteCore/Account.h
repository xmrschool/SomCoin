// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "crypto/crypto.h"

namespace CryptoNote {

  class ISerializer;

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class AccountBase {
  public:
    AccountBase();
    void generate();
    void generateDeterministic();

    static void generateViewFromSpend(const Crypto::SecretKey&, Crypto::SecretKey&, Crypto::PublicKey&);
    static void generateViewFromSpend(const Crypto::SecretKey&, Crypto::SecretKey&);

    const AccountKeys& getAccountKeys() const;
    void setAccountKeys(const AccountKeys& keys);
    uint64_t get_createtime() const { return m_creation_timestamp; }
    void set_createtime(uint64_t val) { m_creation_timestamp = val; }
    void serialize(ISerializer& s);

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int /*ver*/) {
      a & m_keys;
      a & m_creation_timestamp;
    }

  private:
    void setNull();
    AccountKeys m_keys;
    uint64_t m_creation_timestamp;
  };
}

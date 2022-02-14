// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/Difficulty.h"

namespace CryptoNote {
  struct IMinerHandler {
    virtual bool handle_block_found(Block& b) = 0;
    virtual bool get_block_template(Block& b, const AccountKeys& acc, difficulty_type& diffic, uint32_t& height, const BinaryArray& ex_nonce) = 0;
    virtual bool getBlockLongHash(Crypto::cn_context &context, const Block& b, Crypto::Hash& res) = 0;

  protected:
    ~IMinerHandler(){};
  };
}

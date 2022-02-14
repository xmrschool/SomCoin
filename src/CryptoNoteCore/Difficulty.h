// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/hash.h"

namespace CryptoNote
{
    typedef std::uint64_t difficulty_type;

    bool check_hash(const Crypto::Hash &hash, difficulty_type difficulty);
}

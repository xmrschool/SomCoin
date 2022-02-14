// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#include <stddef.h>
#include <stdint.h>

#include "hash-ops.h"
#include "skein.h"

void hash_extra_skein(const void *data, size_t length, char *hash) {
  int r = skein_hash(8 * HASH_SIZE, data, 8 * length, (uint8_t*)hash);
  assert(SKEIN_SUCCESS == r);
}

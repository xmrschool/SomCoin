// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <stdexcept>
#include <algorithm>
#include <string>

#include "IWalletLegacy.h"

namespace CryptoNote {
class ISerializer;

struct UnconfirmedTransferDetails;
struct WalletLegacyTransaction;
struct WalletLegacyTransfer;

void serialize(UnconfirmedTransferDetails& utd, ISerializer& serializer);
void serialize(WalletLegacyTransaction& txi, ISerializer& serializer);
void serialize(WalletLegacyTransfer& tr, ISerializer& serializer);

}

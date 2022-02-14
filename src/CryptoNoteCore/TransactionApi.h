// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <memory>
#include "ITransaction.h"

namespace CryptoNote {
  std::unique_ptr<ITransaction> createTransaction();
  std::unique_ptr<ITransaction> createTransaction(const BinaryArray& transactionBlob);
  std::unique_ptr<ITransaction> createTransaction(const Transaction& tx);

  std::unique_ptr<ITransactionReader> createTransactionPrefix(const TransactionPrefix& prefix, const Crypto::Hash& transactionHash);
  std::unique_ptr<ITransactionReader> createTransactionPrefix(const Transaction& fullTransaction);
}

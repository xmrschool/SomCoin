// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, Karbo developers
//
// This file is part of SoM.

#pragma once

#include "crypto/hash.h"
#include "IWalletLegacy.h"
#include "ITransfersContainer.h"

#include "WalletLegacy/WalletLegacyEvent.h"
#include "WalletLegacy/WalletUnconfirmedTransactions.h"

namespace CryptoNote {
class ISerializer;
}

namespace CryptoNote {

class WalletUserTransactionsCache
{
public:
  explicit WalletUserTransactionsCache(uint64_t mempoolTxLiveTime = 60 * 60 * 24);

  bool serialize(CryptoNote::ISerializer& serializer);

  uint64_t unconfirmedTransactionsAmount() const;
  uint64_t unconfrimedOutsAmount() const;
  size_t getTransactionCount() const;
  size_t getTransferCount() const;

  TransactionId addNewTransaction(uint64_t amount, uint64_t fee, const std::string& extra, const std::vector<WalletLegacyTransfer>& transfers, uint64_t unlockTime);
  void updateTransaction(TransactionId transactionId, const CryptoNote::Transaction& tx, uint64_t amount, const std::list<TransactionOutputInformation>& usedOutputs, Crypto::SecretKey& tx_key);
  void updateTransactionSendingState(TransactionId transactionId, std::error_code ec);

  std::shared_ptr<WalletLegacyEvent> onTransactionUpdated(const TransactionInformation& txInfo, int64_t txBalance);
  std::shared_ptr<WalletLegacyEvent> onTransactionDeleted(const Crypto::Hash& transactionHash);

  TransactionId findTransactionByTransferId(TransferId transferId) const;

  bool getTransaction(TransactionId transactionId, WalletLegacyTransaction& transaction) const;
  WalletLegacyTransaction& getTransaction(TransactionId transactionId);
  TransactionId findTransactionByHash(const Crypto::Hash& hash);
  bool getTransfer(TransferId transferId, WalletLegacyTransfer& transfer) const;
  WalletLegacyTransfer& getTransfer(TransferId transferId);

  bool isUsed(const TransactionOutputInformation& out) const;
  void reset();

  std::vector<TransactionId> deleteOutdatedTransactions();

  std::vector<Payments> getTransactionsByPaymentIds(const std::vector<PaymentId>& paymentIds) const;

private:

  TransactionId insertTransaction(WalletLegacyTransaction&& Transaction);
  TransferId insertTransfers(const std::vector<WalletLegacyTransfer>& transfers);
  void updateUnconfirmedTransactions();

  typedef std::vector<WalletLegacyTransfer> UserTransfers;
  typedef std::vector<WalletLegacyTransaction> UserTransactions;
  using Offset = UserTransactions::size_type;
  using UserPaymentIndex = std::unordered_map<PaymentId, std::vector<Offset>, boost::hash<PaymentId>>;

  void getGoodItems(UserTransactions& transactions, UserTransfers& transfers);
  void getGoodTransaction(TransactionId txId, size_t offset, UserTransactions& transactions, UserTransfers& transfers);

  void getTransfersByTx(TransactionId id, UserTransfers& transfers);

  void rebuildPaymentsIndex();
  void pushToPaymentsIndex(const PaymentId& paymentId, Offset distance);
  void pushToPaymentsIndexInternal(Offset distance, const WalletLegacyTransaction& info, std::vector<uint8_t>& extra);
  void popFromPaymentsIndex(const PaymentId& paymentId, Offset distance);

  UserTransactions m_transactions;
  UserTransfers m_transfers;
  WalletUnconfirmedTransactions m_unconfirmedTransactions;
  UserPaymentIndex m_paymentsIndex;
};

} //namespace CryptoNote

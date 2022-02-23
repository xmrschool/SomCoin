// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2016, The Forknote developers
// Copyright (c) 2016-2020, The Karbo developers
//
// This file is part of SoM.

#include "RpcServer.h"
#include "version.h"

#include <future>
#include <unordered_map>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>

// CryptoNote
#include <crypto/random.h>
#include "BlockchainExplorerData.h"
#include "Common/Base58.h"
#include "Common/DnsTools.h"
#include "Common/Math.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "P2p/ConnectionContext.h"
#include "P2p/NetNode.h"

#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"

#undef ERROR

const uint32_t MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST = 10000;
const uint64_t BLOCK_LIST_MAX_COUNT = 1000;

namespace CryptoNote {

namespace {

template <typename Command>
RpcServer::HandlerFunction binMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromBinaryKeyValue(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToBinaryKeyValue(res.data()));
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction jsonMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    std::string cors_domain = obj->getCorsDomain();
    if (!cors_domain.empty()) {
      response.addHeader("Access-Control-Allow-Origin", cors_domain);
      response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      response.addHeader("Access-Control-Allow-Methods", "POST, GET");
    }
    response.addHeader("Content-Type", "application/json");
    response.setBody(storeToJson(res.data()));
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction httpMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);

    std::string cors_domain = obj->getCorsDomain();
    if (!cors_domain.empty()) {
      response.addHeader("Access-Control-Allow-Origin", cors_domain);
      response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      response.addHeader("Access-Control-Allow-Methods", "POST, GET");
    }
    response.addHeader("Content-Type", "text/html; charset=UTF-8");
    response.addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response.addHeader("Expires", "0");
    response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);

    response.setBody(res);

    return result;
  };
}

}

std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers = {
  
  // binary handlers
  { "/getblocks.bin", { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), true } },
  { "/queryblocks.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), true } },
  { "/queryblockslite.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), true } },
  { "/get_o_indexes.bin", { binMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::on_get_indexes), true } },
  { "/getrandom_outs.bin", { binMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::on_get_random_outs), true } },
  { "/get_pool_changes.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::on_get_pool_changes), true } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::on_get_pool_changes_lite), true } },

  // plain text/html handlers
  { "/", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_index), true } },
  { "/supply", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_supply), false } },
  { "/paymentid", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_payment_id), true } },

  // get json handlers
  { "/getinfo", { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::on_get_info), true } },
  { "/getheight", { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::on_get_height), true } },
  { "/feeaddress", { jsonMethod<COMMAND_RPC_GET_FEE_ADDRESS>(&RpcServer::on_get_fee_address), true } },
  { "/gettransactionspool", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT>(&RpcServer::on_get_transactions_pool_short), true } },
  { "/gettransactionsinpool", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_POOL>(&RpcServer::on_get_transactions_pool), true } },
  { "/getrawtransactionspool", { jsonMethod<COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL>(&RpcServer::on_get_transactions_pool_raw), true } },

  // post json handlers
  { "/gettransactions", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::on_get_transactions), false } },
  { "/sendrawtransaction", { jsonMethod<COMMAND_RPC_SEND_RAW_TRANSACTION>(&RpcServer::on_send_raw_transaction), false } },
  { "/getblocks", { jsonMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), false } },
  { "/queryblocks", { jsonMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), false } },
  { "/queryblockslite", { jsonMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), false } },
  { "/get_o_indexes", { jsonMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::on_get_indexes), false } },
  { "/getrandom_outs", { jsonMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::on_get_random_outs), false } },
  { "/get_pool_changes", { jsonMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::on_get_pool_changes), true } },
  { "/get_pool_changes_lite", { jsonMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::on_get_pool_changes_lite), true } },
  { "/get_block_details_by_height", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT>(&RpcServer::on_get_block_details_by_height), true } },
  { "/get_block_details_by_hash", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH>(&RpcServer::on_get_block_details_by_hash), true } },
  { "/get_blocks_details_by_heights", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS>(&RpcServer::on_get_blocks_details_by_heights), true } },
  { "/get_blocks_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES>(&RpcServer::on_get_blocks_details_by_hashes), true } },
  { "/get_blocks_hashes_by_timestamps", { jsonMethod<COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS>(&RpcServer::on_get_blocks_hashes_by_timestamps), true } },
  { "/get_transaction_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES>(&RpcServer::on_get_transactions_details_by_hashes), true } },
  { "/get_transaction_details_by_hash", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH>(&RpcServer::on_get_transaction_details_by_hash), true } },
  { "/get_transaction_details_by_heights", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS>(&RpcServer::on_get_transactions_details_by_heights), true } },
  { "/get_raw_transactions_by_heights", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_WITH_OUTPUT_GLOBAL_INDEXES_BY_HEIGHTS>(&RpcServer::on_get_transactions_with_output_global_indexes_by_heights), true } },
  { "/get_transaction_hashes_by_payment_id", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID>(&RpcServer::on_get_transaction_hashes_by_paymentid), true } },
  
  // disabled in restricted rpc mode
  { "/start_mining", { jsonMethod<COMMAND_RPC_START_MINING>(&RpcServer::on_start_mining), false } },
  { "/stop_mining", { jsonMethod<COMMAND_RPC_STOP_MINING>(&RpcServer::on_stop_mining), false } },
  { "/stop_daemon", { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::on_stop_daemon), true } },
  { "/getconnections", { jsonMethod<COMMAND_RPC_GET_CONNECTIONS>(&RpcServer::on_get_connections), true } },
  { "/getpeers", { jsonMethod<COMMAND_RPC_GET_PEER_LIST>(&RpcServer::on_get_peer_list), true } },


  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, CryptoNote::Core& core, NodeServer& p2p, ICryptoNoteProtocolQuery& protocolQuery) :
  HttpServer(dispatcher, log), logger(log, "RpcServer"), m_core(core), m_p2p(p2p), m_protocolQuery(protocolQuery), blockchainExplorerDataBuilder(core, protocolQuery) {
}

void RpcServer::processRequest(const HttpRequest& request, HttpResponse& response) {
  //logger(Logging::TRACE) << "RPC request came: \n" << request << std::endl;

  try {

  auto url = request.getUrl();

  auto it = s_handlers.find(url);
  if (it == s_handlers.end()) {
    if (Common::starts_with(url, "/api/")) {

      std::string block_height_method = "/api/block/height/";
      std::string block_hash_method = "/api/block/hash/";
      std::string tx_hash_method = "/api/transaction/";
      std::string payment_id_method = "/api/payment_id/";
      std::string tx_mempool_method = "/api/mempool/";

      if (Common::starts_with(url, block_height_method)) {

        std::string height_str = url.substr(block_height_method.size());
        uint32_t height = Common::integer_cast<uint32_t>(height_str);
        auto it = s_handlers.find("/get_block_details_by_height");
        if (!it->second.allowBusyCore && !isCoreReady()) {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }
        COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request req;
        req.blockHeight = height;
        COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response rsp;
        bool r = on_get_block_details_by_height(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        } else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        return;

      } else if (Common::starts_with(url, block_hash_method)) {

        std::string hash_str = url.substr(block_hash_method.size());
        auto it = s_handlers.find("/get_block_details_by_hash");
        if (!it->second.allowBusyCore && !isCoreReady()) {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }
        COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request req;
        req.hash = hash_str;
        COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response rsp;
        bool r = on_get_block_details_by_hash(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        } else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        return;

      } else if (Common::starts_with(url, tx_hash_method)) {

        std::string hash_str = url.substr(tx_hash_method.size());
        auto it = s_handlers.find("/get_transaction_details_by_hash");
        if (!it->second.allowBusyCore && !isCoreReady()) {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }
        COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request req;
        req.hash = hash_str;
        COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response rsp;
        bool r = on_get_transaction_details_by_hash(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        }
        else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        return;

      } else if (Common::starts_with(url, payment_id_method)) {

        std::string pid_str = url.substr(payment_id_method.size());
        auto it = s_handlers.find("/get_transaction_hashes_by_payment_id");
        if (!it->second.allowBusyCore && !isCoreReady()) {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }
        COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request req;
        req.paymentId = pid_str;
        COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response rsp;
        bool r = on_get_transaction_hashes_by_paymentid(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        }
        else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        return;

      } else if (Common::starts_with(url, tx_mempool_method)) {

        auto it = s_handlers.find("/gettransactionsinpool");
        if (!it->second.allowBusyCore && !isCoreReady())
        {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }

        COMMAND_RPC_GET_TRANSACTIONS_POOL::request req;
        COMMAND_RPC_GET_TRANSACTIONS_POOL::response rsp;
        bool r = on_get_transactions_pool(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        }
        else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }

        return;

      }

      response.setStatus(HttpResponse::STATUS_404);
      return;
    }
    else {
      response.setStatus(HttpResponse::STATUS_404);
      return;
    }
  }

  if (!it->second.allowBusyCore && !isCoreReady()) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody("Core is busy");
    return;
  }

  it->second.handler(this, request, response);

  }
  catch (const JsonRpc::JsonRpcError& err) {
    response.addHeader("Content-Type", "application/json");
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody(storeToJsonValue(err).toString());
  }
  catch (const std::exception& e) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody(e.what());
  }
}

bool RpcServer::processJsonRpcRequest(const HttpRequest& request, HttpResponse& response) {

  using namespace JsonRpc;

  response.addHeader("Content-Type", "application/json");
  if (!m_cors_domain.empty()) {
    response.addHeader("Access-Control-Allow-Origin", m_cors_domain);
    response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    response.addHeader("Access-Control-Allow-Methods", "POST, GET");
  }  

  JsonRpcRequest jsonRequest;
  JsonRpcResponse jsonResponse;

  try {
    //logger(Logging::TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.getBody());
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonMemberMethod>> jsonRpcHandlers = {
  
      { "getblockcount", { makeMemberMethod(&RpcServer::on_getblockcount), true } },
      { "getblockhash", { makeMemberMethod(&RpcServer::on_getblockhash), true } },
      { "getblocktemplate", { makeMemberMethod(&RpcServer::on_getblocktemplate), true } },
      { "getblockheaderbyhash", { makeMemberMethod(&RpcServer::on_get_block_header_by_hash), true } },
      { "getblockheaderbyheight", { makeMemberMethod(&RpcServer::on_get_block_header_by_height), true } },
      { "getblocktimestamp", { makeMemberMethod(&RpcServer::on_get_block_timestamp_by_height), true } },
      { "getblockbyheight", { makeMemberMethod(&RpcServer::on_get_block_details_by_height), true } },
      { "getblockbyhash", { makeMemberMethod(&RpcServer::on_get_block_details_by_hash), true } },
      { "getblocksbyheights", { makeMemberMethod(&RpcServer::on_get_blocks_details_by_heights), true } },
      { "getblocksbyhashes", { makeMemberMethod(&RpcServer::on_get_blocks_details_by_hashes), true } },
      { "getblockshashesbytimestamps", { makeMemberMethod(&RpcServer::on_get_blocks_hashes_by_timestamps), true } },
      { "getblockslist", { makeMemberMethod(&RpcServer::on_blocks_list_json), true } },
      { "getaltblockslist", { makeMemberMethod(&RpcServer::on_alt_blocks_list_json), true } },
      { "getlastblockheader", { makeMemberMethod(&RpcServer::on_get_last_block_header), true } },
      { "gettransaction", { makeMemberMethod(&RpcServer::on_get_transaction_details_by_hash), true } },
      { "gettransactionspool", { makeMemberMethod(&RpcServer::on_get_transactions_pool_short), true } },
      { "getrawtransactionspool", { makeMemberMethod(&RpcServer::on_get_transactions_pool_raw), true } },
      { "gettransactionsinpool", { makeMemberMethod(&RpcServer::on_get_transactions_pool), true } },
      { "gettransactionsbypaymentid", { makeMemberMethod(&RpcServer::on_get_transactions_by_payment_id), true } },
      { "gettransactionhashesbypaymentid", { makeMemberMethod(&RpcServer::on_get_transaction_hashes_by_paymentid), true } },
      { "gettransactionsbyhashes", { makeMemberMethod(&RpcServer::on_get_transactions_details_by_hashes), true } },
      { "gettransactionsbyheights", { makeMemberMethod(&RpcServer::on_get_transactions_details_by_heights), true } },
      { "getrawtransactionsbyheights", { makeMemberMethod(&RpcServer::on_get_transactions_with_output_global_indexes_by_heights), true } },
      { "getcurrencyid", { makeMemberMethod(&RpcServer::on_get_currency_id), true } },
      { "getstatsbyheights", { makeMemberMethod(&RpcServer::on_get_stats_by_heights), false } },
      { "getstatsinrange", { makeMemberMethod(&RpcServer::on_get_stats_by_heights_range), false } },
      { "checktransactionkey", { makeMemberMethod(&RpcServer::on_check_transaction_key), true } },
      { "checktransactionbyviewkey", { makeMemberMethod(&RpcServer::on_check_transaction_with_view_key), true } },
      { "checktransactionproof", { makeMemberMethod(&RpcServer::on_check_transaction_proof), true } },
      { "checkreserveproof", { makeMemberMethod(&RpcServer::on_check_reserve_proof), true } },
      { "checkpayment", { makeMemberMethod(&RpcServer::on_check_payment), true } },
      { "validateaddress", { makeMemberMethod(&RpcServer::on_validate_address), true } },
      { "verifymessage", { makeMemberMethod(&RpcServer::on_verify_message), true } },
      { "submitblock", { makeMemberMethod(&RpcServer::on_submitblock), false } },
      { "resolveopenalias", { makeMemberMethod(&RpcServer::on_resolve_open_alias), true } },

    };

    auto it = jsonRpcHandlers.find(jsonRequest.getMethod());
    if (it == jsonRpcHandlers.end()) {
      throw JsonRpcError(JsonRpc::errMethodNotFound);
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      throw JsonRpcError(CORE_RPC_ERROR_CODE_CORE_BUSY, "Core is busy");
    }

    it->second.handler(this, jsonRequest, jsonResponse);

  } catch (const JsonRpcError& err) {
    jsonResponse.setError(err);
  } catch (const std::exception& e) {
    jsonResponse.setError(JsonRpcError(JsonRpc::errInternalError, e.what()));
  }

  response.setBody(jsonResponse.getBody());
  //logger(Logging::TRACE) << "JSON-RPC response: " << jsonResponse.getBody();
  return true;
}

bool RpcServer::restrictRpc(const bool is_restricted) {
  m_restricted_rpc = is_restricted;
  return true;
}

bool RpcServer::enableCors(const std::string domain) {
  m_cors_domain = domain;
  return true;
}

std::string RpcServer::getCorsDomain() {
  return m_cors_domain;
}

bool RpcServer::setFeeAddress(const std::string& fee_address, const AccountPublicAddress& fee_acc) {
  m_fee_address = fee_address;
  m_fee_acc = fee_acc;
  return true;
}

bool RpcServer::setFeeAmount(const uint64_t fee_amount) {
  m_fee_amount = fee_amount;
  return true;
}

bool RpcServer::setViewKey(const std::string& view_key) {
  Crypto::Hash private_view_key_hash;
  size_t size;
  if (!Common::fromHex(view_key, &private_view_key_hash, sizeof(private_view_key_hash), size) || size != sizeof(private_view_key_hash)) {
    logger(Logging::INFO) << "Could not parse private view key";
    return false;
  }
  m_view_key = *(struct Crypto::SecretKey *) &private_view_key_hash;
  return true;
}

bool RpcServer::setContactInfo(const std::string& contact) {
  m_contact_info = contact;
  return true;
}

bool RpcServer::isCoreReady() {
  return m_core.currency().isTestnet() || m_p2p.get_payload_object().isSynchronized();
}

bool RpcServer::checkIncomingTransactionForFee(const BinaryArray& tx_blob) {
  Crypto::Hash tx_hash = NULL_HASH;
  Crypto::Hash tx_prefixt_hash = NULL_HASH;
  Transaction tx;
  if (!parseAndValidateTransactionFromBinaryArray(tx_blob, tx, tx_hash, tx_prefixt_hash)) {
    logger(Logging::INFO) << "Could not parse tx from blob";
    return false;
  }

  // always relay fusion transactions
  uint64_t inputs_amount = 0;
  get_inputs_money_amount(tx, inputs_amount);
  uint64_t outputs_amount = get_outs_money_amount(tx);

  const uint64_t fee = inputs_amount - outputs_amount;
  if (fee == 0 && m_core.currency().isFusionTransaction(tx, tx_blob.size(), m_core.getCurrentBlockchainHeight() - 1)) {
    logger(Logging::DEBUGGING) << "Masternode received fusion transaction, relaying with no fee check";
    return true;
  }

  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  std::vector<uint32_t> out;
  uint64_t amount;

  CryptoNote::findOutputsToAccount(transaction, m_fee_acc, m_view_key, out, amount);

  if (amount < m_fee_amount)
    return false;

  logger(Logging::INFO) << "Masternode received relayed transaction fee: " << m_core.currency().formatAmount(amount) << " KRB";

  return true;
}

//
// Binary handlers
//

bool RpcServer::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res) {
  // TODO code duplication see InProcessNode::doGetNewBlocks()
  if (req.block_ids.empty()) {
    res.status = "Failed";
    return false;
  }

  if (req.block_ids.back() != m_core.getBlockIdByHeight(0)) {
    res.status = "Failed";
    return false;
  }

  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  std::vector<Crypto::Hash> supplement = m_core.findBlockchainSupplement(req.block_ids, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT, totalBlockCount, startBlockIndex);

  res.current_height = totalBlockCount;
  res.start_height = startBlockIndex;

  for (const auto& blockId : supplement) {
    assert(m_core.have_block(blockId));
    auto completeBlock = m_core.getBlock(blockId);
    assert(completeBlock != nullptr);

    res.blocks.resize(res.blocks.size() + 1);
    res.blocks.back().block = Common::asString(toBinaryArray(completeBlock->getBlock()));

    res.blocks.back().txs.reserve(completeBlock->getTransactionCount());
    for (size_t i = 0; i < completeBlock->getTransactionCount(); ++i) {
      res.blocks.back().txs.push_back(Common::asString(toBinaryArray(completeBlock->getTransaction(i))));
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;

  if (!m_core.queryBlocks(req.block_ids, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.start_height = startHeight;
  res.current_height = currentHeight;
  res.full_offset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;
  if (!m_core.queryBlocksLite(req.blockIds, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.startHeight = startHeight;
  res.currentHeight = currentHeight;
  res.fullOffset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res) {
  std::vector<uint32_t> outputIndexes;
  if (!m_core.get_tx_outputs_gindexs(req.txid, outputIndexes)) {
    res.status = "Failed";
    return true;
  }

  res.o_indexes.assign(outputIndexes.begin(), outputIndexes.end());
  res.status = CORE_RPC_STATUS_OK;
  //logger(Logging::TRACE) << "COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << res.o_indexes.size() << "]";
  return true;
}

bool RpcServer::on_get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) {
  res.status = "Failed";
  if (!m_core.get_random_outs_for_amounts(req, res)) {
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;

  std::stringstream ss;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;

  std::for_each(res.outs.begin(), res.outs.end(), [&](outs_for_amount& ofa)  {
    ss << "[" << ofa.amount << "]:";

    assert(ofa.outs.size() && "internal error: ofa.outs.size() is empty");

    std::for_each(ofa.outs.begin(), ofa.outs.end(), [&](out_entry& oe)
    {
      ss << oe.global_amount_index << " ";
    });
    ss << ENDL;
  });
  std::string s = ss.str();
  //logger(Logging::TRACE) << "COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS: " << ENDL << s;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_pool_changes(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  std::vector<CryptoNote::Transaction> addedTransactions;
  rsp.isTailBlockActual = m_core.getPoolChanges(req.tailBlockId, req.knownTxsIds, addedTransactions, rsp.deletedTxsIds);
  for (auto& tx : addedTransactions) {
    BinaryArray txBlob;
    if (!toBinaryArray(tx, txBlob)) {
      rsp.status = "Internal error";
      break;;
    }

    rsp.addedTxs.emplace_back(std::move(txBlob));
  }
  return true;
}


bool RpcServer::on_get_pool_changes_lite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  rsp.isTailBlockActual = m_core.getPoolChangesLite(req.tailBlockId, req.knownTxsIds, rsp.addedTxs, rsp.deletedTxsIds);

  return true;
}

bool RpcServer::on_get_blocks_details_by_heights(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::response& rsp) {
  try {
    if (req.blockHeights.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.blockHeights.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }
    std::vector<BlockDetails> blockDetails;
    for (const uint32_t& height : req.blockHeights) {
      if (m_core.getCurrentBlockchainHeight() <= height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
          std::string("To big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
      }
      Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
      Block blk;
      if (!m_core.getBlockByHash(block_hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by height " + std::to_string(height) + '.' };
      }
      BlockDetails detail;
      if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, detail, false)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
      }
      blockDetails.push_back(detail);
    }
    rsp.blocks = std::move(blockDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_blocks_details_by_hashes(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::response& rsp) {
  try {
    if (req.blockHashes.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.blockHashes.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }
    std::vector<BlockDetails> blockDetails;
    for (const Crypto::Hash& hash : req.blockHashes) {
      Block blk;
      if (!m_core.getBlockByHash(hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by hash " + Common::podToHex(hash) + '.' };
      }
      BlockDetails detail;
      if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, detail, false)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
      }
      blockDetails.push_back(detail);
    }
    rsp.blocks = std::move(blockDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_details_by_height(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response& rsp) {
  try {
    BlockDetails blockDetails;
    if (m_core.getCurrentBlockchainHeight() <= req.blockHeight) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
        std::string("To big height: ") + std::to_string(req.blockHeight) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
    }
    Crypto::Hash block_hash = m_core.getBlockIdByHeight(req.blockHeight);
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height " + std::to_string(req.blockHeight) + '.' };
  }
    if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, blockDetails, true)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
    }
    rsp.block = blockDetails;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_details_by_hash(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response& rsp) {
  try {
    BlockDetails blockDetails;
    Crypto::Hash block_hash;
    if (!parse_hash256(req.hash, block_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
    }
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
    }
    if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, blockDetails, true)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
    }
    rsp.block = blockDetails;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_blocks_hashes_by_timestamps(const COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::request& req, COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::response& rsp) {
  try {
    uint32_t count;
    std::vector<Crypto::Hash> blockHashes;
    if (!m_core.get_blockchain_storage().getBlockIdsByTimestamp(req.timestampBegin, req.timestampEnd, req.limit, blockHashes, count)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get blocks within timestamps " + std::to_string(req.timestampBegin) + " - " + std::to_string(req.timestampEnd) + "." };
    }
    rsp.blockHashes = std::move(blockHashes);
    rsp.count = count;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_details_by_hashes(const COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES::response& rsp) {
  try {
    std::vector<TransactionDetails> transactionsDetails;
    transactionsDetails.reserve(req.transactionHashes.size());

    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    m_core.getTransactions(req.transactionHashes, txs, missed_txs, true);

    if (!txs.empty()) {
      for (const Transaction& tx : txs) {
        TransactionDetails txDetails;
        if (!blockchainExplorerDataBuilder.fillTransactionDetails(tx, txDetails)) {
          throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
            "Internal error: can't fill transaction details." };
        }
        transactionsDetails.push_back(txDetails);
      }

      rsp.transactions = std::move(transactionsDetails);
      rsp.status = CORE_RPC_STATUS_OK;
    }
    if (txs.empty() || !missed_txs.empty()) {
      std::ostringstream ss;
      std::string separator;
      for (auto h : missed_txs) {
        ss << separator << Common::podToHex(h);
        separator = ",";
      }
      rsp.status = "transaction(s) not found: " + ss.str() + ".";
    }
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  return true;
}

bool RpcServer::on_get_transaction_details_by_hash(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response& rsp) {
  try {
    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    std::vector<Crypto::Hash> hashes;
    Crypto::Hash tx_hash;
    if (!parse_hash256(req.hash, tx_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of transaction hash. Hex = " + req.hash + '.' };
    }
    hashes.push_back(tx_hash);
    m_core.getTransactions(hashes, txs, missed_txs, true);

    if (txs.empty() || !missed_txs.empty()) {
      std::string hash_str = Common::podToHex(missed_txs.back());
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "transaction wasn't found. Hash = " + hash_str + '.' };
    }

    TransactionDetails transactionsDetails;
    if (!blockchainExplorerDataBuilder.fillTransactionDetails(txs.back(), transactionsDetails)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't fill transaction details." };
    }

    rsp.transaction = std::move(transactionsDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_details_by_heights(const COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS::response& rsp) {
  try {
    if (req.heights.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.heights.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }

    std::vector<uint32_t> heights;

    if (req.range) {
      if (req.heights.size() != 2) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("The range is set to true but heights size is not equal to 2") };
      }
      uint32_t upperBound = std::min(req.heights[1], m_core.getCurrentBlockchainHeight());
      for (size_t i = 0; i < (upperBound - req.heights[0]); i++) {
        heights.push_back(req.heights[0] + i);
      }
    }
    else {
      heights = req.heights;
    }

    std::vector<TransactionDetails> transactions;

    for (const uint32_t& height : heights) {
      if (m_core.getCurrentBlockchainHeight() <= height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
          std::string("To big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
      }

      Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
      Block blk;
      if (!m_core.getBlockByHash(block_hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by height " + std::to_string(height) + '.' };
      }

      if (req.include_miner_txs) {
        transactions.reserve(blk.transactionHashes.size() + 1);

        TransactionDetails transactionDetails;
        if (!blockchainExplorerDataBuilder.fillTransactionDetails(blk.baseTransaction, transactionDetails, blk.timestamp)) {
          throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill miner's tx details." };
        }
        transactions.push_back(std::move(transactionDetails));
      }
      else {
        transactions.reserve(blk.transactionHashes.size());
      }

      std::list<Transaction> found;
      std::list<Crypto::Hash> missed;

      if (!blk.transactionHashes.empty()) {
        m_core.getTransactions(blk.transactionHashes, found, missed, false);
        //if (found.size() != blk.transactionHashes.size()) {
        //  throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: not all block's txs were found." };
        //}

        for (const Transaction& tx : found) {
          TransactionDetails transactionDetails;
          if (!blockchainExplorerDataBuilder.fillTransactionDetails(tx, transactionDetails, blk.timestamp)) {
            throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill tx details." };
          }
          if (req.exclude_signatures) {
            transactionDetails.signatures.clear();
          }
          transactions.push_back(std::move(transactionDetails));
        }

        for (const auto& miss_tx : missed) {
          rsp.missed_txs.push_back(Common::podToHex(miss_tx));
        }
      }
    }
    rsp.transactions = std::move(transactions);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_with_output_global_indexes_by_heights(const COMMAND_RPC_GET_TRANSACTIONS_WITH_OUTPUT_GLOBAL_INDEXES_BY_HEIGHTS::request& req, COMMAND_RPC_GET_TRANSACTIONS_WITH_OUTPUT_GLOBAL_INDEXES_BY_HEIGHTS::response& rsp) {
  try {
    std::vector<uint32_t> heights;
    
    if (req.range) {
      if (req.heights.size() != 2) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("The range is set to true but heights size is not equal to 2") };
      }
      std::vector<uint32_t> range = req.heights;

      if (range.back() - range.front() > BLOCK_LIST_MAX_COUNT) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("Requested blocks count: ") + std::to_string(range.back() - range.front()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
      }

      std::sort(range.begin(), range.end());
      uint32_t upperBound = std::min(range[1], m_core.getCurrentBlockchainHeight());
      for (size_t i = 0; i < (upperBound - range[0]); i++) {
        heights.push_back(range[0] + i);
      }
    }
    else {
      if (req.heights.size() > BLOCK_LIST_MAX_COUNT) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("Requested blocks count: ") + std::to_string(req.heights.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
      }

      heights = req.heights;
    }

    for (const uint32_t& height : heights) {
      if (m_core.getCurrentBlockchainHeight() <= height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
          std::string("To big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
      }

      Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
      Block blk;
      if (!m_core.getBlockByHash(block_hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by height " + std::to_string(height) + '.' };
      }

      std::vector<Crypto::Hash> txs_ids;

      if (req.include_miner_txs) {
        txs_ids.reserve(blk.transactionHashes.size() + 1);
        txs_ids.push_back(getObjectHash(blk.baseTransaction));
      }
      else {
        txs_ids.reserve(blk.transactionHashes.size());
      }
      if (!blk.transactionHashes.empty()) {
        txs_ids.insert(txs_ids.end(), blk.transactionHashes.begin(), blk.transactionHashes.end());
      }

      std::vector<Crypto::Hash>::const_iterator ti = txs_ids.begin();

      std::vector<std::pair<Transaction, std::vector<uint32_t>>> txs;
      std::list<Crypto::Hash> missed;

      if (!txs_ids.empty()) {
        if (!m_core.getTransactionsWithOutputGlobalIndexes(txs_ids, missed, txs)) {
          throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error getting transactions with output global indexes" };
        }

        for (const auto &txi : txs) {
          rsp.transactions.push_back(tx_with_output_global_indexes());
          tx_with_output_global_indexes &e = rsp.transactions.back();

          e.hash = *ti++;
          e.block_hash = block_hash;
          e.height = height;
          e.timestamp = blk.timestamp;
          e.transaction = *static_cast<const TransactionPrefix*>(&txi.first);
          e.output_indexes = txi.second;
          e.fee = is_coinbase(txi.first) ? 0 : getInputAmount(txi.first) - getOutputAmount(txi.first);
        }
      }

      for (const auto& miss_tx : missed) {
        rsp.missed_txs.push_back(Common::podToHex(miss_tx));
      }
    }
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transaction_hashes_by_paymentid(const COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response& rsp) {
  Crypto::Hash pid_hash;
  if (!parse_hash256(req.paymentId, pid_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of payment id. Hex = " + req.paymentId + '.' };
  }
  try {
    rsp.transactionHashes = m_core.getTransactionHashesByPaymentId(pid_hash);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_payment(const COMMAND_RPC_CHECK_PAYMENT_BY_PAYMENT_ID::request& req, COMMAND_RPC_CHECK_PAYMENT_BY_PAYMENT_ID::response& rsp) {
  // get txs with requested payment id
  std::vector<Crypto::Hash> transaction_hashes;
  Crypto::Hash pid_hash;
  if (!parse_hash256(req.payment_id, pid_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of payment id. Hex = " + req.payment_id + '.' };
  }
  try {
    transaction_hashes = m_core.getTransactionHashesByPaymentId(pid_hash);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }

  if (transaction_hashes.size() == 0) {
    rsp.status = "not_found";
    return true;
  }

  uint64_t received = 0;

  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  // parse view key
  Crypto::Hash view_key_hash;
  size_t size;
  if (!Common::fromHex(req.view_key, &view_key_hash, sizeof(view_key_hash), size) || size != sizeof(view_key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse private view key" };
  }
  Crypto::SecretKey viewKey = *(struct Crypto::SecretKey *) &view_key_hash;

  // fetch tx(s)
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(transaction_hashes, txs, missed_txs, true);

  if (missed_txs.size() != 0) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Couldn't get transaction with hash: " + Common::podToHex(missed_txs.front()) + '.' };
  }

  for (const auto& tx : txs) {
    // get tx pub key
    Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(tx.extra);

    // obtain key derivation
    Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(txPubKey, viewKey, derivation))
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
    }

    // look for outputs
    size_t keyIndex(0);
    std::vector<TransactionOutput> outputs;
    try {
      for (const TransactionOutput& o : tx.outputs) {
        if (o.target.type() == typeid(KeyOutput)) {
          const KeyOutput out_key = boost::get<KeyOutput>(o.target);
          Crypto::PublicKey pubkey;
          derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
          if (pubkey == out_key.key) {
            received += o.amount;

            // count confirmations only for actually paying tx
            // and include only their hashes in responce
            Crypto::Hash blockHash;
            uint32_t blockHeight;
            Crypto::Hash txHash = getObjectHash(tx);
            if (std::find(rsp.transaction_hashes.begin(), rsp.transaction_hashes.end(), txHash) == rsp.transaction_hashes.end()) {
              rsp.transaction_hashes.push_back(txHash);
            }
            if (m_core.getBlockContainingTx(txHash, blockHash, blockHeight)) {
              uint32_t confirmations = m_protocolQuery.getObservedHeight() - blockHeight;
              if  (rsp.confirmations < confirmations) {
                   rsp.confirmations = confirmations;
              }
            }
          }
        }
        ++keyIndex;
      }
    }
    catch (...)
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
    }  
  }

  rsp.received_amount = received;

  if (received >= req.amount && rsp.confirmations > 0) {
    rsp.status = "paid";
  }
  else if (received > 0 && received < req.amount) {
    rsp.status = "underpaid";
  }
  else if (rsp.confirmations == 0 && received >= req.amount) {
    rsp.status = "pending";
  }
  else {
    rsp.status = "unpaid";
  }

  return true;
}

//
// HTTP handlers
//

bool RpcServer::on_get_index(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  const std::string index_start =
    R"(<html><head><meta http-equiv='refresh' content='60'/></head><body><p><svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width="73px" height="64px" viewBox="0 0 73 64" enable-background="new 0 0 73 64" xml:space="preserve">  <image id="image0" width="73" height="64" x="0" y="0"
    href="data:image/png;base64,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
MGDf/0sAAAAASUVORK5CYII=" />
</svg></td><td>)" "SoM" R"(d &bull; version 
)";
  const std::string index_finish = " </p></body></html>";
  const std::time_t uptime = std::time(nullptr) - m_core.getStartTime();
  const std::string uptime_str = std::to_string((unsigned int)floor(uptime / 60.0 / 60.0 / 24.0)) + "d " + std::to_string((unsigned int)floor(fmod((uptime / 60.0 / 60.0), 24.0))) + "h "
    + std::to_string((unsigned int)floor(fmod((uptime / 60.0), 60.0))) + "m " + std::to_string((unsigned int)fmod(uptime, 60.0)) + "s";
  uint32_t top_block_index = m_core.getCurrentBlockchainHeight() - 1;
  uint32_t top_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  size_t outConn = m_p2p.get_outgoing_connections_count();
  size_t incConn = m_p2p.get_connections_count() - outConn;
  Crypto::Hash last_block_hash = m_core.getBlockIdByHeight(top_block_index);
  size_t white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  size_t grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  size_t alt_blocks_count = m_core.getAlternativeBlocksCount();
  size_t total_tx_count = m_core.getBlockchainTotalTransactions() - top_block_index + 1;
  size_t tx_pool_count = m_core.getPoolTransactionsCount();

  const std::string body = index_start + PROJECT_VERSION_LONG + " &bull; " + (m_core.currency().isTestnet() ? "testnet" : "mainnet") +
    "<ul>" +
      "<li>" + "Synchronization status: " + std::to_string(top_block_index) + "/" + std::to_string(top_known_block_index) +
      "<li>" + "Last block hash: " + Common::podToHex(last_block_hash) + "</li>" +
      "<li>" + "Difficulty: " + std::to_string(m_core.getNextBlockDifficulty()) + "</li>" +
      "<li>" + "Alt. blocks: " + std::to_string(alt_blocks_count) + "</li>" +
      "<li>" + "Total transactions in network: " + std::to_string(total_tx_count) + "</li>" +
      "<li>" + "Transactions in pool: " + std::to_string(tx_pool_count) + "</li>" +
      "<li>" + "Connections:" +
        "<ul>" +
          "<li>" + "RPC: " + std::to_string(get_connections_count()) + "</li>" +
          "<li>" + "OUT: " + std::to_string(outConn) + "</li>" +
          "<li>" + "INC: " + std::to_string(incConn) + "</li>" +
        "</ul>" +
      "</li>" +
      "<li>" + "Peers: " + std::to_string(white_peerlist_size) + " white, " + std::to_string(grey_peerlist_size) + " grey" + "</li>" +
      "<li>" + "Uptime: " + uptime_str + "</li>" +
    "</ul>" +
    index_finish;

  res = body;

  return true;
}


bool RpcServer::on_get_supply(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  std::string already_generated_coins = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  res = already_generated_coins;

  return true;
}

bool RpcServer::on_get_payment_id(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  Crypto::Hash result;
  Random::randomBytes(32, result.data);
  res = Common::podToHex(result);

  return true;
}

//
// JSON handlers
//

bool RpcServer::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res) {
  res.height = m_core.getCurrentBlockchainHeight();
  res.difficulty = m_core.getNextBlockDifficulty();
  res.transactions_count = m_core.getBlockchainTotalTransactions() - res.height; //without coinbase
  res.transactions_pool_size = m_core.getPoolTransactionsCount();
  res.alt_blocks_count = m_core.getAlternativeBlocksCount();
  uint64_t total_conn = m_p2p.get_connections_count();
  res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  res.incoming_connections_count = total_conn - res.outgoing_connections_count;
  res.rpc_connections_count = get_connections_count();
  res.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  res.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  res.last_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  Crypto::Hash last_block_hash = m_core.getBlockIdByHeight(res.height - 1);
  res.top_block_hash = Common::podToHex(last_block_hash);
  res.version = PROJECT_VERSION_LONG;
  res.contact = m_contact_info.empty() ? std::string() : m_contact_info;
  res.min_fee = m_core.getMinimalFee();
  res.start_time = (uint64_t)m_core.getStartTime();
  uint64_t alreadyGeneratedCoins = m_core.getTotalGeneratedAmount();
  // that large uint64_t number is unsafe in JavaScript environment and therefore as a JSON value so we display it as a formatted string
  res.already_generated_coins = m_core.currency().formatAmount(alreadyGeneratedCoins);
  res.block_major_version = m_core.getCurrentBlockMajorVersion();
  uint64_t nextReward = m_core.currency().calculateReward(alreadyGeneratedCoins);
  res.next_reward = nextReward;
  if (!m_core.getBlockCumulativeDifficulty(res.height - 1, res.cumulative_difficulty)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last cumulative difficulty." };
  }
  res.max_cumulative_block_size = (uint64_t)m_core.currency().maxBlockCumulativeSize(res.height);

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_stats_by_heights(const COMMAND_RPC_GET_STATS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_STATS_BY_HEIGHTS::response& res) {
  if (m_restricted_rpc)
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_RESTRICTED, std::string("Method disabled") };

  std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();

  std::vector<block_stats_entry> stats;
  for (const uint32_t& height : req.heights) {
    if (m_core.getCurrentBlockchainHeight() <= height) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
        std::string("To big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
    }

    block_stats_entry entry;
    entry.height = height;
    if (!m_core.getblockEntry(height, entry.block_size, entry.difficulty, entry.already_generated_coins, entry.reward, entry.transactions_count, entry.timestamp)) {
      throw JsonRpc::JsonRpcError{
            CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get stats for height" + std::to_string(height) };
    }
    stats.push_back(entry);
  }
  res.stats = std::move(stats);
  std::chrono::duration<double> duration = std::chrono::steady_clock::now() - timePoint;
  res.duration = duration.count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_stats_by_heights_range(const COMMAND_RPC_GET_STATS_BY_HEIGHTS_RANGE::request& req, COMMAND_RPC_GET_STATS_BY_HEIGHTS_RANGE::response& res) {
  std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();

  uint32_t min = std::max<uint32_t>(req.start_height, 1);
  uint32_t max = std::min<uint32_t>(req.end_height, m_core.getCurrentBlockchainHeight() - 1);
  if (min >= max) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong start and end heights" };
  }

  std::vector<block_stats_entry> stats;

  if (m_restricted_rpc) {
    uint32_t count = std::min<uint32_t>(std::min<uint32_t>(MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST, max - min), m_core.getCurrentBlockchainHeight() - 1);
    std::vector<uint32_t> selected_heights(count);
    double delta = (max - min) / static_cast<double>(count - 1);
    std::vector<uint32_t>::iterator i;
    double val;
    for (i = selected_heights.begin(), val = min; i != selected_heights.end(); ++i, val += delta) {
      *i = static_cast<uint32_t>(val);
    }

    for (const uint32_t& height : selected_heights) {
      block_stats_entry entry;
      entry.height = height;
      if (!m_core.getblockEntry(height, entry.block_size, entry.difficulty, entry.already_generated_coins, entry.reward, entry.transactions_count, entry.timestamp)) {
        throw JsonRpc::JsonRpcError{
              CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get stats for height" + std::to_string(height) };
      }
      stats.push_back(entry);
    }
  } else {
    for (uint32_t height = min; height <= max; height++) {
      block_stats_entry entry;
      entry.height = height;
      if (!m_core.getblockEntry(height, entry.block_size, entry.difficulty, entry.already_generated_coins, entry.reward, entry.transactions_count, entry.timestamp)) {
        throw JsonRpc::JsonRpcError{
              CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get stats for height" + std::to_string(height) };
      }
      stats.push_back(entry);
    }
  }

  res.stats = std::move(stats);

  std::chrono::duration<double> duration = std::chrono::steady_clock::now() - timePoint;
  res.duration = duration.count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res) {
  res.height = m_core.getCurrentBlockchainHeight();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res) {
  std::vector<Crypto::Hash> vh;
  for (const auto& tx_hex_str : req.txs_hashes) {
    BinaryArray b;
    if (!Common::fromHex(tx_hex_str, b))
    {
      res.status = "Failed to parse hex representation of transaction hash";
      return true;
    }
    if (b.size() != sizeof(Crypto::Hash))
    {
      res.status = "Failed, size of data mismatch";
    }
    vh.push_back(*reinterpret_cast<const Crypto::Hash*>(b.data()));
  }
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(vh, txs, missed_txs);

  for (auto& tx : txs) {
    res.txs_as_hex.push_back(Common::toHex(toBinaryArray(tx)));
  }

  for (const auto& miss_tx : missed_txs) {
    res.missed_txs.push_back(Common::podToHex(miss_tx));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_send_raw_transaction(const COMMAND_RPC_SEND_RAW_TRANSACTION::request& req, COMMAND_RPC_SEND_RAW_TRANSACTION::response& res) {
  BinaryArray tx_blob;
  if (!Common::fromHex(req.tx_as_hex, tx_blob))
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: Failed to parse transaction from hexbuff: " << req.tx_as_hex;
    res.status = "Failed";
    return true;
  }

  Crypto::Hash transactionHash = Crypto::cn_fast_hash(tx_blob.data(), tx_blob.size());
  logger(Logging::DEBUGGING) << "transaction " << transactionHash << " came in on_send_raw_tx";

  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  if (!m_core.handle_incoming_tx(tx_blob, tvc, false))
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: Failed to process tx";
    res.status = "Failed";
    return true;
  }

  if (tvc.m_verification_failed)
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: transaction verification failed";
    res.status = "Failed";
    return true;
  }

  if (!tvc.m_should_be_relayed)
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: transaction accepted, but not relayed";
    res.status = "Not relayed";
    return true;
  }

  if (!m_fee_address.empty() && m_view_key != NULL_SECRET_KEY) {
    if (!checkIncomingTransactionForFee(tx_blob)) {
      logger(Logging::INFO) << "Transaction not relayed due to lack of node fee";
      res.status = "Not relayed due to lack of node fee";
      return true;
    }
  }

  NOTIFY_NEW_TRANSACTIONS::request r;
  r.stem = true;
  r.txs.push_back(Common::asString(tx_blob));
  m_core.get_protocol()->relay_transactions(r);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }
  
  AccountKeys keys = boost::value_initialized<AccountKeys>();

  Crypto::Hash key_hash;
  size_t size;
  if (!Common::fromHex(req.miner_spend_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner spend key" };
  }
  keys.spendSecretKey = *(struct Crypto::SecretKey *) &key_hash;

  if (!Common::fromHex(req.miner_view_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner view key" };
  }
  keys.viewSecretKey = *(struct Crypto::SecretKey *) &key_hash;

  Crypto::secret_key_to_public_key(keys.spendSecretKey, keys.address.spendPublicKey);
  Crypto::secret_key_to_public_key(keys.viewSecretKey, keys.address.viewPublicKey);

  if (!m_core.get_miner().start(keys, static_cast<size_t>(req.threads_count))) {
    res.status = "Failed, mining not started";
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  if (!m_core.get_miner().stop()) {
    res.status = "Failed, mining not stopped";
    return true;
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  if (m_core.currency().isTestnet()) {
    m_p2p.sendStopSignal();
    res.status = CORE_RPC_STATUS_OK;
  } else {
    res.status = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    return false;
  }
  return true;
}

bool RpcServer::on_get_fee_address(const COMMAND_RPC_GET_FEE_ADDRESS::request& req, COMMAND_RPC_GET_FEE_ADDRESS::response& res) {
  if (m_fee_address.empty()) {
    res.status = CORE_RPC_STATUS_OK;
    return false; 
  }
  res.fee_address = m_fee_address;
  res.fee_amount = m_fee_amount;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  std::list<AnchorPeerlistEntry> pl_anchor;
  std::vector<PeerlistEntry> pl_wite;
  std::vector<PeerlistEntry> pl_gray;
  m_p2p.getPeerlistManager().get_peerlist_full(pl_anchor, pl_gray, pl_wite);
  for (const auto& pe : pl_anchor) {
    std::stringstream ss;
    ss << pe.adr;
    res.anchor_peers.push_back(ss.str());
  }
  for (const auto& pe : pl_wite) {
    std::stringstream ss;
    ss << pe.adr;
    res.white_peers.push_back(ss.str());
  }
  for (const auto& pe : pl_gray) {
    std::stringstream ss;
    ss << pe.adr;
    res.gray_peers.push_back(ss.str());
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  std::vector<CryptoNoteConnectionContext> peers;
  if(!m_protocolQuery.getConnections(peers)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get connections" };
  }

  for (const auto& p : peers) {
    p2p_connection_entry c;

    c.version = p.version;
    c.state = get_protocol_state_string(p.m_state);
    c.connection_id = boost::lexical_cast<std::string>(p.m_connection_id);
    c.remote_ip = Common::ipAddressToString(p.m_remote_ip);
    c.remote_port = p.m_remote_port;
    c.is_incoming = p.m_is_income;
    c.started = static_cast<uint64_t>(p.m_started);
    c.remote_blockchain_height = p.m_remote_blockchain_height;
    c.last_response_height = p.m_last_response_height;

    res.connections.push_back(c);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
// JSON RPC methods
//------------------------------------------------------------------------------------------------------------------------------

bool RpcServer::on_blocks_list_json(const COMMAND_RPC_GET_BLOCKS_LIST::request& req, COMMAND_RPC_GET_BLOCKS_LIST::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  uint32_t print_blocks_count = 10;
  if(req.count <= BLOCK_LIST_MAX_COUNT)
    print_blocks_count = req.count;
  
  uint32_t last_height = req.height - print_blocks_count;
  if (req.height <= print_blocks_count)  {
    last_height = 0;
  }

  for (uint32_t i = req.height; i >= last_height; i--) {
    Crypto::Hash block_hash = m_core.getBlockIdByHeight(i);
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height. Height = " + std::to_string(i) + '.' };
    }

    size_t tx_cumulative_block_size;
    m_core.getBlockSize(block_hash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
    difficulty_type blockDiff;
    m_core.getBlockDifficulty(static_cast<uint32_t>(i), blockDiff);

    block_short_response block_short;
    block_short.timestamp = blk.timestamp;
    block_short.height = i;
    block_short.hash = Common::podToHex(block_hash);
    block_short.cumulative_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    block_short.transactions_count = blk.transactionHashes.size() + 1;
    block_short.difficulty = blockDiff;

    res.blocks.push_back(block_short);

    if (i == 0)
      break;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_alt_blocks_list_json(const COMMAND_RPC_GET_ALT_BLOCKS_LIST::request& req, COMMAND_RPC_GET_ALT_BLOCKS_LIST::response& res) {
  std::list<Block> alt_blocks;

  if (m_core.get_alternative_blocks(alt_blocks) && !alt_blocks.empty()) {
    for (const auto & b : alt_blocks) {
      Crypto::Hash block_hash = get_block_hash(b);
      uint32_t block_height = boost::get<BaseInput>(b.baseTransaction.inputs.front()).blockIndex;
      size_t tx_cumulative_block_size;
      m_core.getBlockSize(block_hash, tx_cumulative_block_size);
      size_t blokBlobSize = getObjectBinarySize(b);
      size_t minerTxBlobSize = getObjectBinarySize(b.baseTransaction);
      difficulty_type blockDiff;
      m_core.getBlockDifficulty(static_cast<uint32_t>(block_height), blockDiff);

      block_short_response block_short;
      block_short.timestamp = b.timestamp;
      block_short.height = block_height;
      block_short.hash = Common::podToHex(block_hash);
      block_short.cumulative_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
      block_short.transactions_count = b.transactionHashes.size() + 1;
      block_short.difficulty = blockDiff;

      res.alt_blocks.push_back(block_short);
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool_short(const COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT::response& res) {
  auto pool = m_core.getMemoryPool();
  for (const CryptoNote::tx_memory_pool::TransactionDetails txd : pool) {
    transaction_pool_response mempool_transaction;
    mempool_transaction.hash = Common::podToHex(txd.id);
    mempool_transaction.fee = txd.fee;
    mempool_transaction.amount_out = getOutputAmount(txd.tx);;
    mempool_transaction.size = txd.blobSize;
    mempool_transaction.receive_time = txd.receiveTime;
    res.transactions.push_back(mempool_transaction);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool(const COMMAND_RPC_GET_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL::response& res) {
  auto pool = m_core.getMemoryPool();

  for (const auto& txd : pool) {
    TransactionDetails transactionDetails;
    if (!blockchainExplorerDataBuilder.fillTransactionDetails(txd.tx, transactionDetails, txd.receiveTime)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill mempool tx details." };
    }
    res.transactions.push_back(std::move(transactionDetails));
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool_raw(const COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL::response& res) {
  auto pool = m_core.getMemoryPool();

  for (const auto& txd : pool) {
    res.transactions.push_back(tx_with_output_global_indexes());
    tx_with_output_global_indexes &e = res.transactions.back();

    e.hash = txd.id;
    e.height = boost::value_initialized<uint32_t>();
    e.block_hash = boost::value_initialized<Crypto::Hash>();
    e.timestamp = txd.receiveTime;
    e.transaction = *static_cast<const TransactionPrefix*>(&txd.tx);
    e.fee = txd.fee;
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_by_payment_id(const COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res) {
  if (!req.payment_id.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected payment_id" };
  }

  Crypto::Hash paymentId;
  std::vector<Transaction> transactions;

  if (!parse_hash256(req.payment_id, paymentId)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse Payment ID: " + req.payment_id + '.' };
  }

  if (!m_core.getTransactionsByPaymentId(paymentId, transactions)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get transactions by Payment ID: " + req.payment_id + '.' };
  }

  for (const Transaction& tx : transactions) {
    transaction_short_response transaction_short;
    uint64_t amount_in = 0;
    get_inputs_money_amount(tx, amount_in);
    uint64_t amount_out = get_outs_money_amount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    res.transactions.push_back(transaction_short);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res) {
  res.count = m_core.getCurrentBlockchainHeight();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  }

  uint32_t h = static_cast<uint32_t>(req[0]);
  Crypto::Hash blockId = m_core.getBlockIdByHeight(h);
  if (blockId == NULL_HASH) {
    throw JsonRpc::JsonRpcError{ 
      CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(h) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight())
    };
  }

  res = Common::podToHex(blockId);
  return true;
}

namespace {
  uint64_t slow_memmem(void* start_buff, size_t buflen, void* pat, size_t patlen)
  {
    void* buf = start_buff;
    void* end = (char*)buf + buflen - patlen;
    while ((buf = memchr(buf, ((char*)pat)[0], buflen)))
    {
      if (buf>end)
        return 0;
      if (memcmp(buf, pat, patlen) == 0)
        return (char*)buf - (char*)start_buff;
      buf = (char*)buf + 1;
    }
    return 0;
  }
}

bool RpcServer::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res) {
  if (req.reserve_size > TX_EXTRA_NONCE_MAX_COUNT) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE, "To big reserved size, maximum 255" };
  }

  AccountKeys keys = boost::value_initialized<AccountKeys>();

  Crypto::Hash key_hash;
  size_t size;
  if (!Common::fromHex(req.miner_spend_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner spend key" };
  }
  keys.spendSecretKey = *(struct Crypto::SecretKey *) &key_hash;

  if (!Common::fromHex(req.miner_view_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner view key" };
  }
  keys.viewSecretKey = *(struct Crypto::SecretKey *) &key_hash;

  Crypto::secret_key_to_public_key(keys.spendSecretKey, keys.address.spendPublicKey);
  Crypto::secret_key_to_public_key(keys.viewSecretKey, keys.address.viewPublicKey);

  Block b = boost::value_initialized<Block>();
  CryptoNote::BinaryArray blob_reserve;
  blob_reserve.resize(req.reserve_size, 0);
  if (!m_core.get_block_template(b, keys, res.difficulty, res.height, blob_reserve)) {
    logger(Logging::ERROR) << "Failed to create block template";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
  }

  BinaryArray block_blob = toBinaryArray(b);
  Crypto::PublicKey tx_pub_key = CryptoNote::getTransactionPublicKeyFromExtra(b.baseTransaction.extra);
  if (tx_pub_key == NULL_PUBLIC_KEY) {
    logger(Logging::ERROR) << "Failed to find tx pub key in coinbase extra";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to find tx pub key in coinbase extra" };
  }

  if (0 < req.reserve_size) {
    res.reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if (!res.reserved_offset) {
      logger(Logging::ERROR) << "Failed to find tx pub key in blockblob";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
    res.reserved_offset += sizeof(tx_pub_key) + 3; //3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if (res.reserved_offset + req.reserve_size > block_blob.size()) {
      logger(Logging::ERROR) << "Failed to calculate offset for reserved bytes";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
  } else {
    res.reserved_offset = 0;
  }

  BinaryArray hashing_blob;
  if (!get_block_hashing_blob(b, hashing_blob)) {
    logger(Logging::ERROR) << "Failed to get blockhashing_blob";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to get blockhashing_blob" };
  }

  res.blocktemplate_blob = Common::toHex(block_blob);
  res.blockhashing_blob = Common::toHex(hashing_blob);
  res.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& /*req*/, COMMAND_RPC_GET_CURRENCY_ID::response& res) {
  Crypto::Hash currencyId = m_core.currency().genesisBlockHash();
  res.currency_id_blob = Common::podToHex(currencyId);
  return true;
}

bool RpcServer::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong param" };
  }

  BinaryArray blockblob;
  if (!Common::fromHex(req[0], blockblob)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, "Wrong block blob" };
  }

  block_verification_context bvc = boost::value_initialized<block_verification_context>();

  m_core.handle_incoming_block_blob(blockblob, bvc, true, true);

  if (!bvc.m_added_to_main_chain) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED, "Block not accepted" };
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}


namespace {
  uint64_t get_block_reward(const Block& blk) {
    uint64_t reward = 0;
    for (const TransactionOutput& out : blk.baseTransaction.outputs) {
      reward += out.amount;
    }
    return reward;
  }
}

void RpcServer::fill_block_header_response(const Block& blk, bool orphan_status, uint32_t height, const Crypto::Hash& hash, block_header_response& responce) {
  responce.major_version = blk.majorVersion;
  responce.minor_version = blk.minorVersion;
  responce.timestamp = blk.timestamp;
  responce.prev_hash = Common::podToHex(blk.previousBlockHash);
  responce.nonce = blk.nonce;
  responce.orphan_status = orphan_status;
  responce.height = height;
  responce.depth = m_core.getCurrentBlockchainHeight() - height - 1;
  responce.hash = Common::podToHex(hash);
  m_core.getBlockDifficulty(static_cast<uint32_t>(height), responce.difficulty);
  responce.reward = get_block_reward(blk);
}

bool RpcServer::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res) {
  uint32_t last_block_height;
  Crypto::Hash last_block_hash;
  
  m_core.get_blockchain_top(last_block_height, last_block_hash);

  Block last_block;
  if (!m_core.getBlockByHash(last_block_hash, last_block)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last block hash." };
  }
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(last_block_height);
  bool is_orphaned = last_block_hash != tmp_hash;
  fill_block_header_response(last_block, is_orphaned, last_block_height, last_block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res) {
  Crypto::Hash block_hash;

  if (!parse_hash256(req.hash, block_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
  }

  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
  }

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint32_t block_height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(block_height);
  bool is_orphaned = block_hash != tmp_hash;
  fill_block_header_response(blk, is_orphaned, block_height, block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  Crypto::Hash block_hash = m_core.getBlockIdByHeight(static_cast<uint32_t>(req.height));
  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.' };
  }
  
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(req.height);
  bool is_orphaned = block_hash != tmp_hash;
  fill_block_header_response(blk, is_orphaned, req.height, block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_timestamp_by_height(const COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  res.status = CORE_RPC_STATUS_OK;

  m_core.getBlockTimestamp(req.height, res.timestamp);

  return true;
}

bool RpcServer::on_check_transaction_key(const COMMAND_RPC_CHECK_TRANSACTION_KEY::request& req, COMMAND_RPC_CHECK_TRANSACTION_KEY::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  // parse txkey
  Crypto::Hash tx_key_hash;
  size_t size;
  if (!Common::fromHex(req.transaction_key, &tx_key_hash, sizeof(tx_key_hash), size) || size != sizeof(tx_key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txkey" };
  }
  Crypto::SecretKey tx_key = *(struct Crypto::SecretKey *) &tx_key_hash;

  // fetch tx
  Transaction tx;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs, true);

  if (1 == txs.size()) {
    tx = txs.front();
  }
  else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Couldn't find transaction with hash: " + req.transaction_id + '.' };
  }
  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  // obtain key derivation
  Crypto::KeyDerivation derivation;
  if (!Crypto::generate_key_derivation(address.viewPublicKey, tx_key, derivation))
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
  }
  
  // look for outputs
  uint64_t received(0);
  size_t keyIndex(0);
  std::vector<TransactionOutput> outputs;
  try {
    for (const TransactionOutput& o : transaction.outputs) {
      if (o.target.type() == typeid(KeyOutput)) {
        const KeyOutput out_key = boost::get<KeyOutput>(o.target);
        Crypto::PublicKey pubkey;
        derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
        if (pubkey == out_key.key) {
          received += o.amount;
          outputs.push_back(o);
        }
      }
      ++keyIndex;
    }
  }
  catch (...)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
  }
  res.amount = received;
  res.outputs = outputs;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_transaction_with_view_key(const COMMAND_RPC_CHECK_TRANSACTION_WITH_PRIVATE_VIEW_KEY::request& req, COMMAND_RPC_CHECK_TRANSACTION_WITH_PRIVATE_VIEW_KEY::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  // parse view key
  Crypto::Hash view_key_hash;
  size_t size;
  if (!Common::fromHex(req.view_key, &view_key_hash, sizeof(view_key_hash), size) || size != sizeof(view_key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse private view key" };
  }
  Crypto::SecretKey viewKey = *(struct Crypto::SecretKey *) &view_key_hash;

  // fetch tx
  Transaction tx;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs, true);

  if (1 == txs.size()) {
    tx = txs.front();
  }
  else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Couldn't find transaction with hash: " + req.transaction_id + '.' };
  }
  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);
  
  // get tx pub key
  Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(transaction.extra);

  // obtain key derivation
  Crypto::KeyDerivation derivation;
  if (!Crypto::generate_key_derivation(txPubKey, viewKey, derivation))
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
  }

  // look for outputs
  uint64_t received(0);
  size_t keyIndex(0);
  std::vector<TransactionOutput> outputs;
  try {
    for (const TransactionOutput& o : transaction.outputs) {
      if (o.target.type() == typeid(KeyOutput)) {
        const KeyOutput out_key = boost::get<KeyOutput>(o.target);
        Crypto::PublicKey pubkey;
        derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
        if (pubkey == out_key.key) {
          received += o.amount;
          outputs.push_back(o);
        }
      }
      ++keyIndex;
    }
  }
  catch (...)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
  }
  res.amount = received;
  res.outputs = outputs;
  
  Crypto::Hash blockHash;
  uint32_t blockHeight;
  if (m_core.getBlockContainingTx(txid, blockHash, blockHeight)) {
    res.confirmations = m_protocolQuery.getObservedHeight() - blockHeight;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_transaction_proof(const COMMAND_RPC_CHECK_TRANSACTION_PROOF::request& req, COMMAND_RPC_CHECK_TRANSACTION_PROOF::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.destination_address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.destination_address + '.' };
  }
  // parse pubkey r*A & signature
  std::string decoded_data;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded_data) || prefix != CryptoNote::parameters::CRYPTONOTE_TX_PROOF_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Transaction proof decoding error" };
  }
  Crypto::PublicKey rA;
  Crypto::Signature sig;
  std::string rA_decoded = decoded_data.substr(0, sizeof(Crypto::PublicKey));
  std::string sig_decoded = decoded_data.substr(sizeof(Crypto::PublicKey), sizeof(Crypto::Signature));

  memcpy(&rA, rA_decoded.data(), sizeof(Crypto::PublicKey));
  memcpy(&sig, sig_decoded.data(), sizeof(Crypto::Signature));

  // fetch tx pubkey
  Transaction tx;

  std::vector<uint32_t> out;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs, true);

  if (1 == txs.size()) {
    tx = txs.front();
  }
  else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "transaction wasn't found. Hash = " + req.transaction_id + '.' };
  }
  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  Crypto::PublicKey R = getTransactionPublicKeyFromExtra(transaction.extra);
  if (R == NULL_PUBLIC_KEY)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Tx pubkey was not found" };
  }

  // check signature
  bool r = Crypto::check_tx_proof(txid, R, address.viewPublicKey, rA, sig);
  res.signature_valid = r;

  if (r) {

    // obtain key derivation by multiplying scalar 1 to the pubkey r*A included in the signature
    Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(rA, Crypto::EllipticCurveScalar2SecretKey(Crypto::I), derivation)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }

    // look for outputs
    uint64_t received(0);
    size_t keyIndex(0);
    std::vector<TransactionOutput> outputs;
    try {
      for (const TransactionOutput& o : transaction.outputs) {
        if (o.target.type() == typeid(KeyOutput)) {
          const KeyOutput out_key = boost::get<KeyOutput>(o.target);
          Crypto::PublicKey pubkey;
          derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
          if (pubkey == out_key.key) {
            received += o.amount;
            outputs.push_back(o);
          }
        }
        ++keyIndex;
      }
    }
    catch (...)
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
    }
    res.received_amount = received;
    res.outputs = outputs;

    Crypto::Hash blockHash;
    uint32_t blockHeight;
    if (m_core.getBlockContainingTx(txid, blockHash, blockHeight)) {
      res.confirmations = m_protocolQuery.getObservedHeight() - blockHeight;
    }
  }
  else {
    res.received_amount = 0;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_reserve_proof(const COMMAND_RPC_CHECK_RESERVE_PROOF::request& req, COMMAND_RPC_CHECK_RESERVE_PROOF::response& res) {
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  
  // parse sugnature
  std::string decoded_data;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded_data) || prefix != CryptoNote::parameters::CRYPTONOTE_RESERVE_PROOF_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Reserve proof decoding error" };
  }
  BinaryArray ba(decoded_data.begin(), decoded_data.end());
  reserve_proof proof_decoded;
  if (!fromBinaryArray(proof_decoded, ba)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Reserve proof BinaryArray decoding error" };
  }

  std::vector<reserve_proof_entry>& proofs = proof_decoded.proofs;
  
  // compute signature prefix hash
  std::string prefix_data = req.message;
  prefix_data.append((const char*)&address, sizeof(CryptoNote::AccountPublicAddress));
  for (size_t i = 0; i < proofs.size(); ++i) {
    prefix_data.append((const char*)&proofs[i].key_image, sizeof(Crypto::PublicKey));
  }
  Crypto::Hash prefix_hash;
  Crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // fetch txes
  std::vector<Crypto::Hash> transactionHashes;
  for (size_t i = 0; i < proofs.size(); ++i) {
    transactionHashes.push_back(proofs[i].transaction_id);
  }

  // first check against height if provided to spare further checks
  // in case request is to check proof of funds that didn't exist yet at this height
  if (req.height != 0) {
    for (const auto& h : transactionHashes) {
      uint32_t tx_height;
      if (!m_core.getTransactionHeight(h, tx_height)) {
        throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("Couldn't find block index containing transaction ") + Common::podToHex(h) + std::string(" of reserve proof"));
      }

      if (req.height < tx_height) {
        throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Funds from transaction ")
          + Common::podToHex(h) + std::string(" in block ") + std::to_string(tx_height) + std::string(" didn't exist at requested height"));
      }
    }
  }

  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(transactionHashes, txs, missed_txs);
  if (!missed_txs.empty()) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Couldn't find some transactions of reserve proof"));
  }
  std::vector<Transaction> transactions;
  std::copy(txs.begin(), txs.end(), std::inserter(transactions, transactions.end()));

  // check spent status
  res.total = 0;
  res.spent = 0;
  res.locked = 0;
  for (size_t i = 0; i < proofs.size(); ++i) {
    const reserve_proof_entry& proof = proofs[i];

    CryptoNote::TransactionPrefix tx = *static_cast<const TransactionPrefix*>(&transactions[i]);
    
    bool unlocked = m_core.is_tx_spendtime_unlocked(tx.unlockTime, req.height);

    if (proof.index_in_transaction >= tx.outputs.size()) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "index_in_tx is out of bound" };
    }

    const KeyOutput out_key = boost::get<KeyOutput>(tx.outputs[proof.index_in_transaction].target);

    // get tx pub key
    Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(tx.extra);

    // check singature for shared secret
    if (!Crypto::check_tx_proof(prefix_hash, address.viewPublicKey, txPubKey, proof.shared_secret, proof.shared_secret_sig)) {
      //throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to check singature for shared secret" };
      res.good = false;
      return true;
    }

    // check signature for key image
    const std::vector<const Crypto::PublicKey *>& pubs = { &out_key.key };
    if (!Crypto::check_ring_signature(prefix_hash, proof.key_image, &pubs[0], 1, &proof.key_image_sig)) {
      //throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to check signature for key image" };
      res.good = false;
      return true;
    }

    // check if the address really received the fund
    Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(proof.shared_secret, Crypto::EllipticCurveScalar2SecretKey(Crypto::I), derivation)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }
    try {
      Crypto::PublicKey pubkey;
      derive_public_key(derivation, proof.index_in_transaction, address.spendPublicKey, pubkey);
      if (pubkey == out_key.key) {
        uint64_t amount = tx.outputs[proof.index_in_transaction].amount;
        res.total += amount;

        if (!unlocked) {
          res.locked += amount;
        }

        if (req.height != 0) {
          if (m_core.is_key_image_spent(proof.key_image, req.height)) {
            res.spent += amount;
          }
        } else {
          if (m_core.is_key_image_spent(proof.key_image)) {
            res.spent += amount;
          }
        }
      }
    }
    catch (...)
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
    }  
  }

  // check signature for address spend keys
  Crypto::Signature sig = proof_decoded.signature;
  if (!Crypto::check_signature(prefix_hash, address.spendPublicKey, sig)) {
    res.good = false;
    return true;
  }

  res.good = true;

  return true;
}

bool RpcServer::on_validate_address(const COMMAND_RPC_VALIDATE_ADDRESS::request& req, COMMAND_RPC_VALIDATE_ADDRESS::response& res) {
  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
  bool r = m_core.currency().parseAccountAddressString(req.address, acc);
  res.is_valid = r;
  if (r) {
    res.address = m_core.currency().accountAddressAsString(acc);
    res.spend_public_key = Common::podToHex(acc.spendPublicKey);
    res.view_public_key = Common::podToHex(acc.viewPublicKey);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_verify_message(const COMMAND_RPC_VERIFY_MESSAGE::request& req, COMMAND_RPC_VERIFY_MESSAGE::response& res) {
  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
  if (!m_core.currency().parseAccountAddressString(req.address, acc)) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Failed to parse address"));
  }

  // could just've used this but detailed errors might be more handy
  //res.sig_valid = CryptoNote::verifyMessage(req.message, acc, req.signature, logger.getLogger());

  std::string decoded;
  Crypto::Signature s;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded) || prefix != CryptoNote::parameters::CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Signature decoding error"));
  }

  if (sizeof(s) != decoded.size()) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Signature size wrong"));
    return false;
  }

  Crypto::Hash hash;
  Crypto::cn_fast_hash(req.message.data(), req.message.size(), hash);

  memcpy(&s, decoded.data(), sizeof(s));
  res.sig_valid = Crypto::check_signature(hash, acc.spendPublicKey, s);

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_resolve_open_alias(const COMMAND_RPC_RESOLVE_OPEN_ALIAS::request& req, COMMAND_RPC_RESOLVE_OPEN_ALIAS::response& res) {
  try {
    res.address = Common::resolveAlias(req.url);

    AccountPublicAddress ignore;
    if (!m_core.currency().parseAccountAddressString(res.address, ignore)) {
          throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Address \"" + res.address + "\" is invalid");
    }
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't resolve alias: " + std::string(e.what()));
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

}

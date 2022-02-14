// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2022, The Karbo developers
// Copyright (c) 2016-2021, The SoM developers
//
// This file is part of SoM.

#include "MinerConfig.h"

#include "Common/CommandLine.h"

namespace CryptoNote {

namespace {
const command_line::arg_descriptor<std::string> arg_extra_messages   = { "extra-messages-file", "Specify file for extra messages to include into coinbase transactions", "", true };
const command_line::arg_descriptor<std::string> arg_mining_spend_key = { "mining-spend-key", "Specify secret spend key to sign the mined block", "", true };
const command_line::arg_descriptor<std::string> arg_mining_view_key  = { "mining-view-key", "Specify secret view key of miner address", "", true };
const command_line::arg_descriptor<uint32_t>    arg_mining_threads   = { "mining-threads", "Specify mining threads count", 0, true };
const command_line::arg_descriptor<bool>        arg_print_hashrate   = { "print-hashrate", "Show hashrate", true };
}

MinerConfig::MinerConfig() {
  miningThreads = 0;
}

void MinerConfig::initOptions(boost::program_options::options_description& desc) {
  command_line::add_arg(desc, arg_extra_messages);
  command_line::add_arg(desc, arg_mining_spend_key);
  command_line::add_arg(desc, arg_mining_view_key);
  command_line::add_arg(desc, arg_mining_threads);
  command_line::add_arg(desc, arg_print_hashrate);
}

void MinerConfig::init(const boost::program_options::variables_map& options) {
  if(command_line::has_arg(options, arg_extra_messages)) {
    extraMessages = command_line::get_arg(options, arg_extra_messages);
  }

  if (command_line::has_arg(options, arg_mining_spend_key)) {
    miningSpendKey = command_line::get_arg(options, arg_mining_spend_key);
  }

  if (command_line::has_arg(options, arg_mining_view_key)) {
    miningViewKey = command_line::get_arg(options, arg_mining_view_key);
  }

  if (command_line::has_arg(options, arg_mining_threads)) {
    miningThreads = command_line::get_arg(options, arg_mining_threads);
  }

  if (command_line::has_arg(options, arg_print_hashrate)) {
    printHashrate = true;
  }
}

} //namespace CryptoNote

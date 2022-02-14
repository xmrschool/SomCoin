// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The TurtleCoin developers
// Copyright (c) 2016-2021, The Karbo developers
//
// This file is part of SoM.

#pragma once

#include <map>
#include <mutex>

#include <CryptoNoteCore/CryptoNoteBasicImpl.h>
#include <Logging/LoggerRef.h>

namespace CryptoNote
{
  class Checkpoints
  {
  public:
    Checkpoints(Logging::ILogger& log, bool is_deep_reorg_allowed = false);

    Checkpoints& operator=(Checkpoints const& other)
    {
      if (&other != this)
      {
        // lock both objects
        std::unique_lock<std::mutex> lock_this(m_mutex, std::defer_lock);
        std::unique_lock<std::mutex> lock_other(other.m_mutex, std::defer_lock);
        std::lock(lock_this, lock_other); // ensure no deadlock
        m_points = other.m_points;
        logger = other.logger;
      }

      return *this;
    }

    bool add_checkpoint(uint32_t height, const std::string& hash_str);
    bool load_checkpoints_from_file(const std::string& fileName);
    bool is_in_checkpoint_zone(uint32_t height) const;
    bool check_block(uint32_t height, const Crypto::Hash& h) const;
    bool check_block(uint32_t height, const Crypto::Hash& h, bool& is_a_checkpoint) const;
    bool is_alternative_block_allowed(uint32_t blockchain_height, uint32_t block_height) const;
    std::vector<uint32_t> getCheckpointHeights() const;
#ifndef __ANDROID__
    bool load_checkpoints_from_dns();
#endif

  private:
    std::map<uint32_t, Crypto::Hash> m_points;
    Logging::LoggerRef logger;
    mutable std::mutex m_mutex;

    bool m_is_deep_reorg_allowed;
  };
}
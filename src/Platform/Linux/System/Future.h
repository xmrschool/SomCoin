// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <future>

namespace System {

namespace Detail {

template<class T> using Future = std::future<T>;

template<class T> Future<T> async(std::function<T()>&& operation) {
  return std::async(std::launch::async, std::move(operation));
}

}

}

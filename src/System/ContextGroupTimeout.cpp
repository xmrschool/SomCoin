// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#include "ContextGroupTimeout.h"
#include <System/InterruptedException.h>

using namespace System;

ContextGroupTimeout::ContextGroupTimeout(Dispatcher& dispatcher, ContextGroup& contextGroup, std::chrono::nanoseconds timeout) :
  workingContextGroup(dispatcher),
  timeoutTimer(dispatcher) {
  workingContextGroup.spawn([&, timeout] {
    try {
      timeoutTimer.sleep(timeout);
      contextGroup.interrupt();
    } catch (InterruptedException&) {
    }
  });
}

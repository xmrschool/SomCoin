// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

namespace System {

class Event;

class EventLock {
public:
  explicit EventLock(Event& event);
  ~EventLock();
  EventLock& operator=(const EventLock&) = delete;

private:
  Event& event;
};

}

// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

namespace System {

class Dispatcher;
class Event;

class RemoteEventLock {
public:
  RemoteEventLock(Dispatcher& dispatcher, Event& event);
  ~RemoteEventLock();

private:
  Dispatcher& dispatcher;
  Event& event;
};

}

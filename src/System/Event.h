// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

namespace System {

class Dispatcher;

class Event {
public:
  Event();
  explicit Event(Dispatcher& dispatcher);
  Event(const Event&) = delete;
  Event(Event&& other);
  ~Event();
  Event& operator=(const Event&) = delete;
  Event& operator=(Event&& other);
  bool get() const;
  void clear();
  void set();
  void wait();

private:
  Dispatcher* dispatcher;
  bool state;
  void* first;
  void* last;
};

}

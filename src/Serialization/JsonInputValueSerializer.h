// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, The Karbo developers
//
// This file is part of SoM.

#pragma once

#include <type_traits>

#include "Common/JsonValue.h"
#include "ISerializer.h"

namespace CryptoNote {

//deserialization
class JsonInputValueSerializer : public ISerializer {
public:
  JsonInputValueSerializer(const Common::JsonValue& value);
  JsonInputValueSerializer(Common::JsonValue&& value);
  virtual ~JsonInputValueSerializer();

  SerializerType type() const override;

  virtual bool beginObject(Common::StringView name) override;
  virtual void endObject() override;

  virtual bool beginArray(size_t& size, Common::StringView name) override;
  virtual void endArray() override;

  virtual bool operator()(uint8_t& value, Common::StringView name) override;
  virtual bool operator()(int16_t& value, Common::StringView name) override;
  virtual bool operator()(uint16_t& value, Common::StringView name) override;
  virtual bool operator()(int32_t& value, Common::StringView name) override;
  virtual bool operator()(uint32_t& value, Common::StringView name) override;
  virtual bool operator()(int64_t& value, Common::StringView name) override;
  virtual bool operator()(uint64_t& value, Common::StringView name) override;
  virtual bool operator()(double& value, Common::StringView name) override;
  virtual bool operator()(bool& value, Common::StringView name) override;
  virtual bool operator()(std::string& value, Common::StringView name) override;
  virtual bool binary(void* value, size_t size, Common::StringView name) override;
  virtual bool binary(std::string& value, Common::StringView name) override;

  template<typename T>
  bool operator()(T& value, Common::StringView name) {
    return ISerializer::operator()(value, name);
  }

private:
  Common::JsonValue value;
  std::vector<const Common::JsonValue*> chain;
  std::vector<size_t> idxs;

  const Common::JsonValue* getValue(Common::StringView name);

  template <typename T>
  bool getNumber(Common::StringView name, T& v) {
    auto ptr = getValue(name);

    if (!ptr) {
      return false;
    }

    if (std::is_integral<T>::value) {
      v = static_cast<T>(ptr->getInteger());
    }
    else if (std::is_floating_point<T>::value) {
      v = static_cast<T>(ptr->getReal());
    }
    return true;
  }
};

}

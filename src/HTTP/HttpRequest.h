// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of SoM.

#pragma once

#include <iostream>
#include <map>
#include <string>
#include "android.h"

namespace CryptoNote {
  class HttpRequest {
  public:
    typedef std::map<std::string, std::string> Headers;

    const std::string& getMethod() const;
    const std::string& getUrl() const;
    const Headers& getHeaders() const;
    const std::string& getBody() const;

    void addHeader(const std::string& name, const std::string& value);
    void setBody(const std::string& b);
    void setUrl(const std::string& uri);
    void setHost(const std::string& host);

  private:
    friend class HttpParser;

    std::string method;
    std::string url;
    std::string m_host;
    Headers headers;
    std::string body;

    friend std::ostream& operator<<(std::ostream& os, const HttpRequest& resp);
    std::ostream& printHttpRequest(std::ostream& os) const;
  };

  inline std::ostream& operator<<(std::ostream& os, const HttpRequest& resp) {
    return resp.printHttpRequest(os);
  }
}

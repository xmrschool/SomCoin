// Copyright (c) 2017-2019 The Karbowanec developers
//
// This file is part of SoM.


#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <streambuf>

namespace System {

class SocketStreambuf: public std::streambuf {
  public:
    SocketStreambuf(char *data, size_t lenght);
    ~SocketStreambuf();
    void getRespdata(std::vector<uint8_t> &data);
    void setRespdata(const std::vector<uint8_t> &data);
  private:
    size_t lenght;
    bool read_t;
    std::array<uint8_t, 1024> writeBuf;
    std::vector<uint8_t> readBuf;
    std::vector<uint8_t> resp_data;
    std::streambuf::int_type overflow(std::streambuf::int_type ch) override;
    std::streambuf::int_type underflow() override;
    int sync() override;
    bool dumpBuffer(bool finalize);
};

}


#pragma once

#include <algorithm>
#include <array>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace vault {

// Implementation of a secure_clear proposal
// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1315r3.html
// https://github.com/ojeda/secure_clear/blob/master/example-implementation/secure_clear.h
//
// See also an attempt at adding a cross platform memory clearing function to curl
// https://github.com/nico-abram/curl/blob/30a61f33905d64ceb67c3af08c8548dea3a22fb5/lib/curl_memory.h
void secure_clear(void* data, size_t size) noexcept;

// Constant time memory comparison
// https://github.com/AGWA/git-crypt/blob/master/util.cpp

bool leakless_equals(const unsigned char* a, const unsigned char* b, std::size_t len);
bool leakless_equals(const void* a, const void* b, std::size_t len);


inline uint8_t hexval(uint8_t c) noexcept
{
  if ('0' <= c && c <= '9')
    return c - '0';
  else if ('a' <= c && c <= 'f')
    return c - 'a' + 10;

  // Assume 'A'..'F'
  return c - 'A' + 10;
}

template <size_t N>
inline void BytesToHexString(const std::array<uint8_t, N>& buffer, size_t line_length, std::ostringstream& output)
{
  for (auto& b : buffer) {
    output<<std::setfill('0')<<std::setw(2)<<std::hex<<int(b);
  }

  std::cout<<"BytesToHexString Buffer length: "<<buffer.size()<<std::endl;

  // Reset the stream flags
  output<<std::dec;
}

template <size_t N>
inline void HexStringToBytes(std::string_view data, std::array<uint8_t, N>& out_bytes)
{
  out_bytes.fill(0);

  size_t i = 0;
  while ((data.length() >= 2) && (i < N)) {
    const char bytes[2] = {
      data.data()[0],
      data.data()[1]
    };
    if (isxdigit(bytes[0]) && isxdigit(bytes[1])) {
      uint8_t c = hexval(bytes[0]);
      c = (c << 4) + hexval(bytes[1]);

      out_bytes[i] = int(c);
      i++;

      data.remove_prefix(2);
    } else {
      // Just remove one byte and check the next one
      data.remove_prefix(1);
    }
  }
}

void BytesToHexString(const std::vector<uint8_t>& buffer, size_t line_length, std::ostringstream& output);
std::string BytesToHexString(const std::span<uint8_t>& data);
std::vector<uint8_t> HexStringToBytes(std::string_view data);

void EncodeStringToHexString(std::string_view view, std::ostringstream& output);
std::string DecodeHexStringToString(std::string_view& view);

}

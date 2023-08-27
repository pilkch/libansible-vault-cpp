#include <iomanip>

#include <cryptopp/hex.h>

#include "util.h"

namespace vault {

// Implementation of a secure_clear proposal
// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1315r3.html
// https://github.com/ojeda/secure_clear/blob/master/example-implementation/secure_clear.h
//
// See also an attempt at adding a cross platform memory clearing function to curl
// https://github.com/nico-abram/curl/blob/30a61f33905d64ceb67c3af08c8548dea3a22fb5/lib/curl_memory.h
void secure_clear(void* data, size_t size) noexcept
{
	if (data == nullptr) return;

#ifdef _WIN32
	SecureZeroMemory(data, size);
#elif defined(HAS_MEMSET_EXPLICIT)
	memset_explicit(data, 0, size);
#elif defined(HAS_MEMSET_S)
	memset_s(data, 0, size);
#elif defined(__linux__) || defined(__unix__)
  explicit_bzero(data, size);
#else
  // https://github.com/AGWA/git-crypt/blob/master/util.cpp
  volatile unsigned char* p = reinterpret_cast<unsigned char*>(data);

  // Set each byte to 0
  while (size--) {
    *p++ = 0;
  }
#endif
}

// Constant time memory comparison
// https://github.com/AGWA/git-crypt/blob/master/util.cpp

bool leakless_equals(const unsigned char* a, const unsigned char* b, std::size_t len)
{
  volatile int diff = 0;

  while (len > 0) {
    diff |= *a++ ^ *b++;
    --len;
  }

  return diff == 0;
}

bool leakless_equals(const void* a, const void* b, std::size_t len)
{
  return leakless_equals(reinterpret_cast<const unsigned char*>(a), reinterpret_cast<const unsigned char*>(b), len);
}


void EncodeStringToHexString(std::string_view view, std::ostringstream& output)
{
  for (char c : view) {
    output<<std::setfill('0')<<std::setw(2)<<std::hex<<int(c);
  }
}

std::string DecodeHexStringToString(std::string_view& view)
{
  std::ostringstream o;

  while (view.length() >= 2) {
    const char bytes[2] = {
      view.data()[0],
      view.data()[1]
    };
    if (isxdigit(bytes[0]) && isxdigit(bytes[1])) {
      uint8_t c = hexval(bytes[0]);
      c = (c << 4) + hexval(bytes[1]);
      o<<c;

      view.remove_prefix(2);
    } else {
      // Just skip the character and go to the next one
      view.remove_prefix(1);
    }
  }

  return o.str();
}

void BytesToHexString(const std::vector<uint8_t>& buffer, size_t line_length, std::ostringstream& output)
{
  for (auto& b : buffer) {
    output<<std::setfill('0')<<std::setw(2)<<std::hex<<int(b);
  }

  std::cout<<"BytesToHexString Buffer length: "<<buffer.size()<<std::endl;

  // Reset the stream flags
  output<<std::dec;
}

std::string BytesToHexString(const std::span<uint8_t>& data)
{
  std::string result;
  const bool uppercase = false;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result), uppercase);

  encoder.Put(data.data(), data.size());
  encoder.MessageEnd();

  return result;
}

std::vector<uint8_t> HexStringToBytes(std::string_view data)
{
  std::vector<uint8_t> output;

  while (data.length() >= 2) {
    const char bytes[2] = {
      data.data()[0],
      data.data()[1]
    };
    if (isxdigit(bytes[0]) && isxdigit(bytes[1])) {
      uint8_t c = hexval(bytes[0]);
      c = (c << 4) + hexval(bytes[1]);
      output.push_back(int(c));

      data.remove_prefix(2);
    } else {
      // Just remove one byte and check the next one
      data.remove_prefix(1);
    }
  }

  return output;
}

}

#include <iomanip>

#include <cryptopp/hex.h>

#include "hex.h"

namespace vault {

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

std::string DebugBytesToHexString(const std::span<uint8_t>& data)
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

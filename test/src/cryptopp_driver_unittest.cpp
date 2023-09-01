#include <gtest/gtest.h>

#include "cryptopp_driver.h"
#include "hex.h"

namespace {

template <size_t N>
void CopyStringToBytes(std::string_view value, vault::SecureArray<uint8_t, N>& out_bytes)
{
  // Clear the bytes in the output
  out_bytes.fill(0);

  // Copy at most N or the input length bytes to the output (If we are short we have filled with zero bytes above, if we are too long we truncate)
  memcpy((char*)out_bytes.data(), value.data(), std::min<size_t>(N, value.length()));
}

std::vector<uint8_t> CopyStringToBytes(std::string_view value)
{
  return std::vector<uint8_t>(value.begin(), value.end());
}

}


TEST(CryptoPPDriver, TestCalculateHMAC)
{
  vault::SecureArray<uint8_t, 32> key;
  CopyStringToBytes("686edb9e07863f0b2f4a6ae42c33f903", key);
  const std::vector<uint8_t> data = CopyStringToBytes("Science fiction books explore futuristic concepts in an imaginative way, dealing with advanced science that may or may not be possible, along with the consequences of how such creations would impact society. Popular subject matter includes alien-human interactions, intergalactic exploration and time travel.");
  vault::SecureArray<uint8_t, 32> out_hmac;
  EXPECT_TRUE(vault::cryptopp_driver::calculateHMAC(key, data, out_hmac));

  EXPECT_EQ(32, out_hmac.size());
  const std::string output_hmac(vault::DebugBytesToHexString(out_hmac));
  EXPECT_STREQ("571dbe5f777f71b5975ed28211a99a6a07d00a5f42eb6f5b956048e4e659dbf1", output_hmac.c_str());

  // And check that verifyHMAC also works with this data
  vault::SecureArray<uint8_t, 32> as_bytes;
  vault::HexStringToBytes("571dbe5f777f71b5975ed28211a99a6a07d00a5f42eb6f5b956048e4e659dbf1", as_bytes);
  EXPECT_TRUE(vault::cryptopp_driver::verifyHMAC(as_bytes, key, data));
}

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

TEST(CryptoPPDriver, TestPadding)
{
  // Basically we round up to the nearest 16 byte boundary, so check the behaviour as cross the boundary at 16 bytes
  const std::vector<uint8_t> padded0 = vault::cryptopp_driver::PKCS7::pad("");
  EXPECT_EQ(16, padded0.size());
  const std::vector<uint8_t> padded1 = vault::cryptopp_driver::PKCS7::pad("1");
  EXPECT_EQ(16, padded1.size());
  const std::vector<uint8_t> padded2 = vault::cryptopp_driver::PKCS7::pad("12");
  EXPECT_EQ(16, padded2.size());
  const std::vector<uint8_t> padded3 = vault::cryptopp_driver::PKCS7::pad("123");
  EXPECT_EQ(16, padded3.size());
  const std::vector<uint8_t> padded4 = vault::cryptopp_driver::PKCS7::pad("1234");
  EXPECT_EQ(16, padded4.size());
  const std::vector<uint8_t> padded5 = vault::cryptopp_driver::PKCS7::pad("12345");
  EXPECT_EQ(16, padded5.size());
  const std::vector<uint8_t> padded6 = vault::cryptopp_driver::PKCS7::pad("123456");
  EXPECT_EQ(16, padded6.size());
  const std::vector<uint8_t> padded7 = vault::cryptopp_driver::PKCS7::pad("1234567");
  EXPECT_EQ(16, padded7.size());
  const std::vector<uint8_t> padded8 = vault::cryptopp_driver::PKCS7::pad("12345678");
  EXPECT_EQ(16, padded8.size());
  const std::vector<uint8_t> padded9 = vault::cryptopp_driver::PKCS7::pad("123456789");
  EXPECT_EQ(16, padded9.size());
  const std::vector<uint8_t> padded10 = vault::cryptopp_driver::PKCS7::pad("1234567890");
  EXPECT_EQ(16, padded10.size());
  const std::vector<uint8_t> padded11 = vault::cryptopp_driver::PKCS7::pad("12345678901");
  EXPECT_EQ(16, padded11.size());
  const std::vector<uint8_t> padded12 = vault::cryptopp_driver::PKCS7::pad("123456789012");
  EXPECT_EQ(16, padded12.size());
  const std::vector<uint8_t> padded13 = vault::cryptopp_driver::PKCS7::pad("1234567890123");
  EXPECT_EQ(16, padded13.size());
  const std::vector<uint8_t> padded14 = vault::cryptopp_driver::PKCS7::pad("12345678901234");
  EXPECT_EQ(16, padded14.size());
  const std::vector<uint8_t> padded15 = vault::cryptopp_driver::PKCS7::pad("123456789012345");
  EXPECT_EQ(16, padded15.size());
  const std::vector<uint8_t> padded16 = vault::cryptopp_driver::PKCS7::pad("1234567890123456");
  EXPECT_EQ(32, padded16.size());
  const std::vector<uint8_t> padded17 = vault::cryptopp_driver::PKCS7::pad("12345678901234567");
  EXPECT_EQ(32, padded17.size());
}

TEST(CryptoPPDriver, TestCalculateHMACAndVerifyHMAC)
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

TEST(CryptoPPDriver, TestEncryptAESDecryptAES)
{
  // Example generated on this web page https://angrytools.com/text-converter/aes/
  // NOTE: With the call to PKCS7::pad the plaintext string is slightly longer, without it the string gets truncated
  // The website can successfully decode without the padding, so, I dunno?
  const std::string plaintext_str = "Science fiction books explore futuristic concepts in an imaginative way, dealing with advanced science that may or may not be possible, along with the consequences of how such creations would impact society. Popular subject matter includes alien-human interactions, intergalactic exploration and time travel.";

  const std::vector<uint8_t> plaintext = vault::cryptopp_driver::PKCS7::pad(plaintext_str);

  vault::SecureArray<uint8_t, 32> key;
  CopyStringToBytes("686edb9e07863f0b2f4a6ae42c33f903", key);
  vault::SecureArray<uint8_t, 16> iv;
  CopyStringToBytes("7971827a70e1c7c43fa652bafe5c88a3", iv);

  std::vector<uint8_t> out_encrypted;
  EXPECT_TRUE(vault::cryptopp_driver::encryptAES(plaintext, key, iv, out_encrypted));

  const std::string encrypted_str(vault::DebugBytesToHexString(out_encrypted));
  EXPECT_STREQ("277a95c95f92d16d6eae2d5ee8afc4d147ed881f132a41377bab99488d84544a8e7331ac536d03c1a747ed2833095b02fc96712926653a0588fff3ad31e4cc89253b36facd485aecfb8736ef7f2e787dc99fd55d47397c1fd0c074f3994a2b3e2bbfb27b7a3acfc205b5e7eb09dfd6a404b18d25f41d1e6661d1865a65bbbe247b13d3804d5a3b52c7e94e0b50ea2abdc3b3122544f5072f21f0c38862d3df3382b9bf0dd4be1f7cdb5fe313902197aa8fdd6103c27b9ba12adc02323db60c72e971f91330969c18f36b1d8d1faa29e038413b7281c63e917dc3d61821696c847399621935708c1a66333dcb5f0683ff94131f6551bd95d0510570f73a4ac8906299602b557096a00d73c0c5c88b2657b3f9e2350ffb64297b0a5e8bcf81ef1a558aa7748e4d09271c913603b2d71f29f6a14125cf747d4ace42921b60843765", encrypted_str.c_str());

  std::vector<uint8_t> out_decrypted;
  EXPECT_TRUE(vault::cryptopp_driver::decryptAES(out_encrypted, key, iv, out_decrypted));

  const std::string plaintext_decrypted((const char*)out_decrypted.data(), out_decrypted.size());
  EXPECT_STREQ(plaintext_decrypted.c_str(), plaintext_str.c_str());
}

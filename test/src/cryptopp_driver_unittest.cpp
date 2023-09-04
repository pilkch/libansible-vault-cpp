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
  vault::SecureString padded0;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("", 0), padded0);
  EXPECT_EQ(16, padded0.length());
  vault::SecureString padded1;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("1", 1), padded1);
  EXPECT_EQ(16, padded1.length());
  vault::SecureString padded2;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("12", 2), padded2);
  EXPECT_EQ(16, padded2.length());
  vault::SecureString padded3;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("123", 3), padded3);
  EXPECT_EQ(16, padded3.length());
  vault::SecureString padded4;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("1234", 4), padded4);
  EXPECT_EQ(16, padded4.length());
  vault::SecureString padded5;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("12345", 5), padded5);
  EXPECT_EQ(16, padded5.length());
  vault::SecureString padded6;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("123456", 6), padded6);
  EXPECT_EQ(16, padded6.length());
  vault::SecureString padded7;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("1234567", 7), padded7);
  EXPECT_EQ(16, padded7.length());
  vault::SecureString padded8;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("12345678", 8), padded8);
  EXPECT_EQ(16, padded8.length());
  vault::SecureString padded9;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("123456789", 9), padded9);
  EXPECT_EQ(16, padded9.length());
  vault::SecureString padded10;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("1234567890", 10), padded10);
  EXPECT_EQ(16, padded10.length());
  vault::SecureString padded11;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("12345678901", 11), padded11);
  EXPECT_EQ(16, padded11.length());
  vault::SecureString padded12;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("123456789012", 12), padded12);
  EXPECT_EQ(16, padded12.length());
  vault::SecureString padded13;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("1234567890123", 13), padded13);
  EXPECT_EQ(16, padded13.length());
  vault::SecureString padded14;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("12345678901234", 14), padded14);
  EXPECT_EQ(16, padded14.length());
  vault::SecureString padded15;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("123456789012345", 15), padded15);
  EXPECT_EQ(16, padded15.length());
  vault::SecureString padded16;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("1234567890123456", 16), padded16);
  EXPECT_EQ(32, padded16.length());
  vault::SecureString padded17;
  vault::cryptopp_driver::PKCS7::pad(vault::SecureString("12345678901234567", 17), padded17);
  EXPECT_EQ(32, padded17.length());
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
  const std::string plaintext_str = "Science fiction books explore futuristic concepts in an imaginative way, dealing with advanced science that may or may not be possible, along with the consequences of how such creations would impact society. Popular subject matter includes alien-human interactions, intergalactic exploration and time travel.";
  vault::SecureString plaintext(plaintext_str.c_str(), plaintext_str.length());

  vault::SecureArray<uint8_t, 32> key;
  CopyStringToBytes("686edb9e07863f0b2f4a6ae42c33f903", key);
  vault::SecureArray<uint8_t, 16> iv;
  CopyStringToBytes("7971827a70e1c7c43fa652bafe5c88a3", iv);

  std::vector<uint8_t> out_encrypted;
  EXPECT_TRUE(vault::cryptopp_driver::encryptAES(plaintext, key, iv, out_encrypted));

  const std::string encrypted_str(vault::DebugBytesToHexString(out_encrypted));
  EXPECT_STREQ("277a95c95f92d16d6eae2d5ee8afc4d147ed881f132a41377bab99488d84544a8e7331ac536d03c1a747ed2833095b02fc96712926653a0588fff3ad31e4cc89253b36facd485aecfb8736ef7f2e787dc99fd55d47397c1fd0c074f3994a2b3e2bbfb27b7a3acfc205b5e7eb09dfd6a404b18d25f41d1e6661d1865a65bbbe247b13d3804d5a3b52c7e94e0b50ea2abdc3b3122544f5072f21f0c38862d3df3382b9bf0dd4be1f7cdb5fe313902197aa8fdd6103c27b9ba12adc02323db60c72e971f91330969c18f36b1d8d1faa29e038413b7281c63e917dc3d61821696c847399621935708c1a66333dcb5f0683ff94131f6551bd95d0510570f73a4ac8906299602b557096a00d73c0c5c88b2657b3f9e2350ffb64297b0a5e8bcf81ef1a558aa7748e4d09271c913603b2d71f29f6a14125cf747d4ace42921b60843765", encrypted_str.c_str());

  vault::SecureString out_decrypted;
  EXPECT_TRUE(vault::cryptopp_driver::decryptAES(out_encrypted, key, iv, out_decrypted));

  const std::string plaintext_decrypted(out_decrypted.c_str(), out_decrypted.length());
  EXPECT_STREQ(plaintext_decrypted.c_str(), plaintext.c_str());
}

#include <gtest/gtest.h>

#include "hex.h"

TEST(Hex, TestBytesToHexToBytes)
{
  const std::vector<uint8_t> expected_bytes = {
    0xDF, 0x42, 0xe0, 0xcd, 0xdd, 0xea, 0xbb, 0xc1, 0x82, 0xe7, 0x29, 0x7f, 0xc4, 0xc0, 0x20, 0x6b
  };

  // Test lower case
  {
    const std::string lower = "df42e0cdddeabbc182e7297fc4c0206b";
    const std::vector<uint8_t> bytes = vault::HexStringToBytes(lower);
    ASSERT_EQ(expected_bytes, bytes);

    std::ostringstream output;
    vault::BytesToHexString(bytes, 100, output);
    ASSERT_STREQ("df42e0cdddeabbc182e7297fc4c0206b", output.str().c_str());
  }

  // Test upper case
  {
    const std::string upper = "DF42E0CDDDEABBC182E7297FC4C0206B";
    const std::vector<uint8_t> bytes = vault::HexStringToBytes(upper);
    ASSERT_EQ(expected_bytes, bytes);

    std::ostringstream output;
    vault::BytesToHexString(bytes, 100, output);
    ASSERT_STREQ("df42e0cdddeabbc182e7297fc4c0206b", output.str().c_str());
  }

  // Test converting back to a string
  {
    std::ostringstream output;
    vault::BytesToHexString(expected_bytes, 100, output);
    ASSERT_STREQ("df42e0cdddeabbc182e7297fc4c0206b", output.str().c_str());
  }
}

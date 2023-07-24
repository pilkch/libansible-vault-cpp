#include <fstream>

#include <gtest/gtest.h>

#include "ansible_vault.h"

namespace {

bool ReadFileAsText(const std::string& file_path, std::string& contents)
{
  contents.clear();

  std::ifstream file(file_path);
  if (!file.is_open()) {
    std::cerr<<"Error reading file \""<<file_path<<"\""<<std::endl;
    return false;
  }

  file.seekg(0, std::ios::end);
  contents.reserve(file.tellg());
  file.seekg(0, std::ios::beg);

  contents.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

  return true;
}

}

// TODO: Move this to a new test file
TEST(Utils, TestBytesToHexToBytes)
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

namespace {

std::vector<uint8_t> CopyStringToBytes(std::string_view value)
{
  return std::vector<uint8_t>(value.begin(), value.end());
}

}

// TODO: Move this to a new test file
TEST(HMAC, TestCalculateHMAC)
{
  const std::vector<uint8_t> key = CopyStringToBytes("686edb9e07863f0b2f4a6ae42c33f903");
  const std::vector<uint8_t> data = CopyStringToBytes("Science fiction books explore futuristic concepts in an imaginative way, dealing with advanced science that may or may not be possible, along with the consequences of how such creations would impact society. Popular subject matter includes alien-human interactions, intergalactic exploration and time travel.");
  std::vector<uint8_t> out_hmac;
  EXPECT_TRUE(vault::calculateHMAC(key, data, out_hmac));

  EXPECT_EQ(32, out_hmac.size());
  std::ostringstream output;
  vault::BytesToHexString(out_hmac, 100, output);
  EXPECT_STREQ("571dbe5f777f71b5975ed28211a99a6a07d00a5f42eb6f5b956048e4e659dbf1", output.str().c_str());
}


/*TEST(AnsibleVault, TestEncryptDecryptAES256Simple)
{
  const std::string plain_text = "My encrypted text.\nAnd another line.\n";
  const std::string password = "mytestpassword";
  std::ostringstream encrypted;
  const vault::ENCRYPT_RESULT encryption_result = vault::encrypt(plain_text, password, encrypted);
  ASSERT_EQ(vault::ENCRYPT_RESULT::OK, encryption_result);

  const std::string expected_vaulttext = "$ANSIBLE_VAULT;1.1;AES256\n"
"33363965326261303234626463623963633531343539616138316433353830356566396130353436\n"
"3562643163366231316662386565383735653432386435610a306664636137376132643732393835\n"
"63383038383730306639353234326630666539346233376330303938323639306661313032396437\n"
"6233623062366136310a633866373936313238333730653739323461656662303864663666653563\n"
"3138";
  ASSERT_STREQ(expected_vaulttext.c_str(), encrypted.str().c_str());

  std::ostringstream decrypted;
  const vault::DECRYPT_RESULT decryption_result = vault::decrypt(encrypted.str(), password, decrypted);
  ASSERT_EQ(vault::DECRYPT_RESULT::OK, decryption_result);

  ASSERT_STREQ(decrypted.str().c_str(), plain_text.c_str());
}*/

/*TEST(AnsibleVault, TestEncryptDecryptAES256)
{
  const std::string original_plaintext = "Setec Astronomy";
  const std::string password = "default";
  std::ostringstream encrypted;
  const vault::ENCRYPT_RESULT encryption_result = vault::encrypt(original_plaintext, vault::ENCRYPTION_METHOD::AES256, password, std::nullopt, std::nullopt, encrypted);
  ASSERT_EQ(vault::ENCRYPT_RESULT::OK, encryption_result);

  const std::string expected_vaulttext = "$ANSIBLE_VAULT;1.1;AES256\n"
"33363965326261303234626463623963633531343539616138316433353830356566396130353436\n"
"3562643163366231316662386565383735653432386435610a306664636137376132643732393835\n"
"63383038383730306639353234326630666539346233376330303938323639306661313032396437\n"
"6233623062366136310a633866373936313238333730653739323461656662303864663666653563\n"
"3138";
  ASSERT_STREQ(expected_vaulttext.c_str(), encrypted.str().c_str());

  std::string output_vault_id_utf8;
  std::ostringstream output_plaintext_result;
  const vault::DECRYPT_RESULT decryption_result = vault::decrypt(encrypted.str(), password, std::nullopt, output_vault_id_utf8, output_plaintext_result);
  ASSERT_EQ(vault::DECRYPT_RESULT::OK, decryption_result);

  ASSERT_STREQ(output_plaintext_result.str().c_str(), original_plaintext.c_str());
}*/


// Tests from: https://github.com/vermut/intellij-encryption/blob/c0999f0dc857dd7449bcefa385e31a2536272097/src/test/java/com/ansible/parsing/vault/VaultLibTest.kt

TEST(AnsibleVault, TestDecryptAES256SampleTxt)
{
  std::string encrypted;
  ASSERT_TRUE(ReadFileAsText("test/data/sample.txt", encrypted));

  const std::string password = "ansible";

  std::ostringstream decrypted;
  const vault::DECRYPT_RESULT decryption_result = vault::decrypt(encrypted, password, decrypted);
  ASSERT_EQ(vault::DECRYPT_RESULT::OK, decryption_result);

  ASSERT_STREQ(decrypted.str().c_str(), "foobar");
}

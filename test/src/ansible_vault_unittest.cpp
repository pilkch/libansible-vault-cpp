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

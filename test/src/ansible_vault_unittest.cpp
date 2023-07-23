#include <gtest/gtest.h>

#include "ansible_vault.h"

TEST(AnsibleVault, TestEncryptDecryptAES256)
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
}

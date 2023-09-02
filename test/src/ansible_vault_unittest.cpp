#include <fstream>

#include <gtest/gtest.h>

#include "ansible_vault.h"
#include "hex.h"
#include "util.h"

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


template <size_t N>
void CopyStringToBytes(std::string_view value, vault::SecureArray<uint8_t, N>& out_bytes)
{
  // Clear the bytes in the output
  out_bytes.fill(0);

  // Copy at most N or the input length bytes to the output (If we are short we have filled with zero bytes above, if we are too long we truncate)
  memcpy((char*)out_bytes.data(), value.data(), std::min<size_t>(N, value.length()));
}

}


TEST(AnsibleVault, TestEncryptDecryptAES256Simple)
{
  const std::string plain_text = "My encrypted text.\nAnd another line.\n";
  const std::string password = "mytestpassword";
  const std::string salt_utf8 = "ed3496252ad601cf571ac38eab55544f";
  vault::SecureArray<uint8_t, 32> salt;
  CopyStringToBytes(salt_utf8, salt);

  std::ostringstream encrypted;
  const vault::ENCRYPT_RESULT encryption_result = vault::encrypt(plain_text, password, salt, encrypted);
  ASSERT_EQ(vault::ENCRYPT_RESULT::OK, encryption_result);

  const std::string expected_vaulttext =
"$ANSIBLE_VAULT;1.1;AES256\n"
"36353634333333343339333633323335333236313634333633303331363336363335333733313631\n"
"3633333333383635363136323335333533353334333436360a333266623333313331613638363063\n"
"30366162363836633266623664323038303831636235313339306564383862376639656330313538\n"
"6532616335656265390a316331663036366636343261366563353430366637303734356162306432\n"
"38306536623464383462326539333838333930326337326338666666306164663636623335643839\n"
"3237306533653535633032323038313661623166386632333735";

  EXPECT_STREQ(expected_vaulttext.c_str(), encrypted.str().c_str());

  //std::cout<<"encrypted.str(): "<<encrypted.str()<<std::endl;

  std::ostringstream decrypted;
  const vault::DECRYPT_RESULT decryption_result = vault::decrypt(encrypted.str(), password, decrypted);
  ASSERT_EQ(vault::DECRYPT_RESULT::OK, decryption_result);

  ASSERT_STREQ(decrypted.str().c_str(), plain_text.c_str());
}

TEST(AnsibleVault, TestEncryptDecryptAES256)
{
  const std::string original_plaintext = "Setec Astronomy";
  const std::string password = "default";
  std::ostringstream encrypted;
  const vault::ENCRYPT_RESULT encryption_result = vault::encrypt(original_plaintext, password, encrypted);
  ASSERT_EQ(vault::ENCRYPT_RESULT::OK, encryption_result);

  std::ostringstream output_plaintext_result;
  const vault::DECRYPT_RESULT decryption_result = vault::decrypt(encrypted.str(), password, output_plaintext_result);
  ASSERT_EQ(vault::DECRYPT_RESULT::OK, decryption_result);

  ASSERT_STREQ(output_plaintext_result.str().c_str(), original_plaintext.c_str());
}

TEST(AnsibleVault, TestParseBadVaultFileNoSignature)
{
  const std::string encrypted = "Random Garbage\nsjksdfsdjkflsdjkl\nsdfjsdfjisdfjo\nsdfsdfdssdsdfsdfjksdfjksdfj\nsdfsdsddfssdfsdf";

  std::string_view view(encrypted);

  vault::VaultInfo vault_info;
  EXPECT_EQ(vault::DECRYPT_RESULT::ERROR_PARSING_ENVELOPE_ANSIBLE_VAULT_SIGNATURE, vault::ParseVaultInfoString(view, vault_info));
}

TEST(AnsibleVault, TestParseBadVaultFileUnsupportedEnvelopeVersion)
{
  const std::string encrypted = "$ANSIBLE_VAULT;1.0;AES256\nsjksdfsdjkflsdjkl\nsdfjsdfjisdfjo\nsdfsdfdssdsdfsdfjksdfjksdfj\nsdfsdsddfssdfsdf";

  std::string_view view(encrypted);

  vault::VaultInfo vault_info;
  EXPECT_EQ(vault::DECRYPT_RESULT::ERROR_UNSUPPORTED_ENVELOPE_VERSION, vault::ParseVaultInfoString(view, vault_info));
}

TEST(AnsibleVault, TestParseBadVaultFileUnsupportedEncryptionMethod)
{
  const std::string encrypted = "$ANSIBLE_VAULT;1.1;AES512\nsjksdfsdjkflsdjkl\nsdfjsdfjisdfjo\nsdfsdfdssdsdfsdfjksdfjksdfj\nsdfsdsddfssdfsdf";

  std::string_view view(encrypted);

  vault::VaultInfo vault_info;
  EXPECT_EQ(vault::DECRYPT_RESULT::ERROR_UNSUPPORED_ENCRYPTION_METHOD, vault::ParseVaultInfoString(view, vault_info));
}

TEST(AnsibleVault, TestParseBadVaultFileUnsupportedErrorParsingSalt)
{
  const std::string encrypted = "$ANSIBLE_VAULT;1.1;AES256\nsjksdfsdjkflsdjkl";

  std::string_view view(encrypted);

  vault::VaultInfo vault_info;
  EXPECT_EQ(vault::DECRYPT_RESULT::OK, vault::ParseVaultInfoString(view, vault_info));

  vault::VaultContent vault_content;
  EXPECT_EQ(vault::DECRYPT_RESULT::ERROR_PARSING_VAULT_CONTENT_SALT, vault::ParseVaultContent(view, vault_content));
}

TEST(AnsibleVault, TestParseBadVaultFileUnsupportedErrorParsingHMAC)
{
  // This string has a valid salt, but no HMAC
  const std::string encrypted = "$ANSIBLE_VAULT;1.1;AES256\n34363666386533643832343235623034623131343631376365363864323931303064316139626539\n6266306430383133643966343763613937626566646238650a616232363462343162346331393837\nsdfsdfsdfsdfjk";

  std::string_view view(encrypted);

  vault::VaultInfo vault_info;
  EXPECT_EQ(vault::DECRYPT_RESULT::OK, vault::ParseVaultInfoString(view, vault_info));

  vault::VaultContent vault_content;
  EXPECT_EQ(vault::DECRYPT_RESULT::ERROR_PARSING_VAULT_CONTENT_HMAC, vault::ParseVaultContent(view, vault_content));
}

// Just check that we can parse the basic headers and strip new lines
TEST(AnsibleVault, TestParseSampleTxt)
{
  std::string encrypted;
  ASSERT_TRUE(ReadFileAsText("test/data/sample.txt", encrypted));

  std::string_view view(encrypted);

  vault::VaultInfo vault_info;
  EXPECT_EQ(vault::DECRYPT_RESULT::OK, vault::ParseVaultInfoString(view, vault_info));

  vault::VaultContent vault_content;
  EXPECT_EQ(vault::DECRYPT_RESULT::OK, vault::ParseVaultContent(view, vault_content));

  const std::string result_salt(vault::DebugBytesToHexString(vault_content.salt));
  EXPECT_STREQ("ed3496252ad601cf571ac38eab55544fd9de4fc160e0053e688e1da1fbb98f40", result_salt.c_str());
  const std::string result_hmac(vault::DebugBytesToHexString(vault_content.hmac));
  EXPECT_STREQ("c329dee4cbc4412294e077aca91d23c471b0cc8473967fe81dbc0c1832db0f88", result_hmac.c_str());
  const std::string result_data(vault::DebugBytesToHexString(vault_content.data));
  EXPECT_STREQ("2812bc157abaa53f7a86e22f9ed253dd", result_data.c_str());
}


// Tests from: https://github.com/vermut/intellij-encryption/blob/c0999f0dc857dd7449bcefa385e31a2536272097/src/test/java/com/ansible/parsing/vault/VaultLibTest.kt

TEST(AnsibleVault, TestDecryptAES256SampleTxt)
{
  std::string encrypted;
  ASSERT_TRUE(ReadFileAsText("test/data/sample.txt", encrypted));

  const std::string password = "ansible";

  std::ostringstream decrypted;
  const vault::DECRYPT_RESULT decryption_result = vault::decrypt(encrypted, password, decrypted);
  ASSERT_EQ(vault::DECRYPT_RESULT::OK, decryption_result);

  ASSERT_STREQ(decrypted.str().c_str(), "foobar\n");
}


// Tests from: https://github.com/tweedegolf/ansible-vault-rs/blob/master/src/lib.rs

TEST(AnsibleVault, TestDecryptAES256LargerTxt)
{
  std::string encrypted;
  ASSERT_TRUE(ReadFileAsText("test/data/larger.txt", encrypted));

  const std::string password = "shibboleet";

  std::ostringstream decrypted;
  const vault::DECRYPT_RESULT decryption_result = vault::decrypt(encrypted, password, decrypted);
  ASSERT_EQ(vault::DECRYPT_RESULT::OK, decryption_result);

  ASSERT_STREQ(decrypted.str().c_str(), "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ornare ullamcorper odio a lacinia. Duis eget placerat nunc. Cras vel sollicitudin sapien. Donec ac elit in felis pulvinar posuere. Sed laoreet sagittis nunc et commodo. Nulla posuere euismod enim nec ornare. Aliquam sed metus sed mauris eleifend sollicitudin. Praesent et eros elit. Suspendisse blandit sagittis mi, id efficitur tellus. Nunc at aliquam metus, ut euismod risus.\n");
}

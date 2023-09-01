#include <algorithm>
#include <iomanip>
#include <iostream>
#include <optional>
#include <ranges>
#include <string_view>

#include <climits>
#include <algorithm>
#include <functional>

#include "ansible_vault.h"
#include "common.h"
#include "cryptopp_driver.h"
#include "hex.h"
#include "util.h"

namespace {

void output_to_string_wrap_80_characters(std::string_view input, std::ostringstream& output)
{
  const size_t max_line_length = 80;

  while (!input.empty()) {
    // Get up to 32 more characters from the string
    const size_t line_length = std::min<size_t>(input.length(), max_line_length);
    if (input.length() > max_line_length) output<<input.substr(0, line_length)<<"\n";
    else {
      // This is the last line
      output<<input.substr(0, line_length);
    }
    input.remove_prefix(line_length);
  }
}

}

namespace vault {

// Vault implementation using AES-CTR with an HMAC-SHA256 authentication code.
// Keys are derived using PBKDF2
// http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html

const std::string VAULT_MAGIC = "$ANSIBLE_VAULT";
const std::string VAULT_VERSION = "1.1";
const std::string VAULT_CIPHER_AES256 = "AES256";

bool is_encrypted(const std::string_view& content)
{
  return content.starts_with(VAULT_MAGIC);
}


VaultInfo::VaultInfo() :
  vault_version(VAULT_VERSION),
  encryption_method(ENCRYPTION_METHOD::AES256)
{
}

void VaultInfo::clear()
{
  vault_version = VAULT_VERSION;
  encryption_method = ENCRYPTION_METHOD::AES256;
}


std::string GenerateVaultInfoString()
{
  return VAULT_MAGIC + ";" + VAULT_VERSION + ";" + VAULT_CIPHER_AES256;
}

DECRYPT_RESULT ParseVaultInfoString(std::string_view& info_line, VaultInfo& out_vault_info)
{
  out_vault_info.clear();

  // Signature
  size_t found = info_line.find(';');
  if (found == std::string::npos) return DECRYPT_RESULT::ERROR_PARSING_ENVELOPE_ANSIBLE_VAULT_SIGNATURE;

  std::string value(info_line.substr(0, found));
  if (value != VAULT_MAGIC) return DECRYPT_RESULT::ERROR_PARSING_ENVELOPE_ANSIBLE_VAULT_SIGNATURE;

  info_line.remove_prefix(found + 1);


  // Version
  found = info_line.find(';');
  if (found == std::string::npos) return DECRYPT_RESULT::ERROR_UNSUPPORTED_ENVELOPE_VERSION;

  value = info_line.substr(0, found);
  if (value != VAULT_VERSION) return DECRYPT_RESULT::ERROR_UNSUPPORTED_ENVELOPE_VERSION;

  info_line.remove_prefix(found + 1);

  out_vault_info.vault_version = VAULT_VERSION;


  // Version
  found = info_line.find('\n');
  if (found == std::string::npos) return DECRYPT_RESULT::ERROR_UNSUPPORED_ENCRYPTION_METHOD;

  value = info_line.substr(0, found);
  if (value != VAULT_CIPHER_AES256) return DECRYPT_RESULT::ERROR_UNSUPPORED_ENCRYPTION_METHOD;

  info_line.remove_prefix(found + 1);

  out_vault_info.encryption_method = ENCRYPTION_METHOD::AES256;

  return DECRYPT_RESULT::OK;
}

DECRYPT_RESULT ParseVaultContent(std::string_view& original_encrypted_data, VaultContent& out_vault_content)
{
  out_vault_content.clear();

  std::cout<<"ParseVaultContent Original vault text: "<<original_encrypted_data<<std::endl;
  const std::string decrypted_once_data(DecodeHexStringToString(original_encrypted_data));
  std::cout<<"ParseVaultContent Decrypted once: "<<decrypted_once_data<<std::endl;
  std::string_view encrypted_data(decrypted_once_data);

  // Salt
  size_t found = encrypted_data.find('\n');
  if (found == std::string::npos) return DECRYPT_RESULT::ERROR_PARSING_VAULT_CONTENT_SALT;

  const std::string_view salt_hex(encrypted_data.substr(0, found));

  encrypted_data.remove_prefix(found + 1);


  // HMAC
  found = encrypted_data.find('\n');
  if (found == std::string::npos) return DECRYPT_RESULT::ERROR_PARSING_VAULT_CONTENT_HMAC;

  const std::string_view hmac_hex(encrypted_data.substr(0, found));

  encrypted_data.remove_prefix(found + 1);


  // Data
  const std::string_view data_hex(encrypted_data);

  encrypted_data.remove_prefix(found + 1);


  std::cout<<"ParseVaultContent salt: \""<<salt_hex<<"\", hmac: \""<<hmac_hex<<"\", data: \""<<data_hex<<"\""<<std::endl;

  // Get the actual values
  HexStringToBytes(salt_hex, out_vault_content.salt);
  HexStringToBytes(hmac_hex, out_vault_content.hmac);
  out_vault_content.data = HexStringToBytes(data_hex);

  return DECRYPT_RESULT::OK;
}






ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, const PasswordAndSalt& password_and_salt, std::optional<std::string_view> vault_id_utf8, std::ostringstream& output_utf8)
{
  output_utf8.clear();

  if (is_encrypted(plain_text_utf8)) {
    return ENCRYPT_RESULT::ERROR_ALREADY_ENCRYPTED;
  }

  // Encrypt the content
  EncryptionKeyHMACKeyAndIV out_keys;
  cryptopp_driver::PKCS5_PBKDF2_HMAC::CreateKeys(password_and_salt, out_keys);

  std::cout<<"Key 1: "<<out_keys.encryption_key.size()<<", "<<DebugBytesToHexString(out_keys.encryption_key)<<std::endl;
  std::cout<<"Key 2: "<<out_keys.hmac_key.size()<<", "<<DebugBytesToHexString(out_keys.hmac_key)<<std::endl;
  std::cout<<"IV: "<<out_keys.iv.size()<<", "<<DebugBytesToHexString(out_keys.iv)<<std::endl;

  std::cout<<"Original plain_text_utf8 length: "<<plain_text_utf8.length()<<std::endl;
  const std::vector<uint8_t> data_padded = cryptopp_driver::PKCS7::pad(plain_text_utf8);
  std::cout<<"Padded data length: "<<data_padded.size()<<std::endl;

  std::vector<uint8_t> encrypted;
  if (!cryptopp_driver::encryptAES(data_padded, out_keys.encryption_key, out_keys.iv, encrypted)) {
    std::cerr<<"encrypt Error encrypting with AES"<<std::endl;
    return ENCRYPT_RESULT::ERROR_AES_ENCRYPTION_FAILED;
  }

  SecureArray<uint8_t, 32> hmacHash;
  if (!cryptopp_driver::calculateHMAC(out_keys.hmac_key, encrypted, hmacHash)) {
    std::cerr<<"encrypt Error calculating HMAC"<<std::endl;
    return ENCRYPT_RESULT::ERROR_CALCULATING_HMAC;
  }

  std::cout<<"Original plain text length: "<<plain_text_utf8.length()<<", padded length: "<<data_padded.size()<<std::endl;
  std::cout<<"Creating content salt len: "<<password_and_salt.salt.size()<<", hmacHash len: "<<hmacHash.size()<<", encrypted len: "<<encrypted.size()<<std::endl;

  std::ostringstream content_hex;
  BytesToHexString(password_and_salt.salt, content_hex);
  content_hex<<'\n';
  BytesToHexString(hmacHash, content_hex);
  content_hex<<'\n';
  BytesToHexString(encrypted, content_hex);

  // Write the header
  output_utf8<<VAULT_MAGIC<<";"<<VAULT_VERSION<<";"<<VAULT_CIPHER_AES256<<"\n";

  std::ostringstream content_double_hex;
  EncodeStringToHexString(content_hex.str(), content_double_hex);

  // Write the content
  output_to_string_wrap_80_characters(content_double_hex.str(), output_utf8);

  return ENCRYPT_RESULT::OK;
}

ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, const SecureArray<uint8_t, 32>& salt, std::ostringstream& output_utf8)
{
  const PasswordAndSalt password_and_salt(password_utf8, salt);
  return encrypt(plain_text_utf8, password_and_salt, std::nullopt, output_utf8);
}

ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::ostringstream& output_utf8)
{
  PasswordAndSalt password_and_salt(password_utf8);

  cryptopp_driver::fill_random(password_and_salt.salt);

  return encrypt(plain_text_utf8, password_and_salt, std::nullopt, output_utf8);
}

DECRYPT_RESULT decrypt(std::string_view encrypted_utf8, std::string_view password_utf8, std::ostringstream& output_utf8)
{
  output_utf8.clear();

  VaultInfo vault_info;
  DECRYPT_RESULT result = ParseVaultInfoString(encrypted_utf8, vault_info);
  if (result != DECRYPT_RESULT::OK) {
    return result;
  }

  VaultContent vault_content;
  result = ParseVaultContent(encrypted_utf8, vault_content);
  if (result != DECRYPT_RESULT::OK) {
    return result;
  }

  std::cout<<"decrypt vault_content.data length: "<<vault_content.data.size()<<std::endl;

  std::cout<<"salt "<<DebugBytesToHexString(vault_content.salt)<<std::endl;
  std::cout<<"hmac: "<<DebugBytesToHexString(vault_content.hmac)<<std::endl;
  std::cout<<"data: "<<DebugBytesToHexString(vault_content.data)<<std::endl;

  const PasswordAndSalt password_and_salt(password_utf8, vault_content.salt);

  EncryptionKeyHMACKeyAndIV out_keys;
  cryptopp_driver::PKCS5_PBKDF2_HMAC::CreateKeys(password_and_salt, out_keys);

  // key1, key2, and iv
  std::cout<<"Key 1 length: "<<out_keys.encryption_key.size()<<", value: "<<DebugBytesToHexString(out_keys.encryption_key)<<std::endl;
  std::cout<<"Key 2 length: "<<out_keys.hmac_key.size()<<", value: "<<DebugBytesToHexString(out_keys.hmac_key)<<std::endl;
  std::cout<<"IV length: "<<out_keys.iv.size()<<", value: "<<DebugBytesToHexString(out_keys.iv)<<std::endl;

  const std::vector<uint8_t>& cypher = vault_content.data;
  std::cout<<"decrypt cyper.size: "<<cypher.size()<<std::endl;

  // expected, key, data
  const SecureArray<uint8_t, 32>& expected_hmac_trimmed = vault_content.hmac;
  if (!cryptopp_driver::verifyHMAC(expected_hmac_trimmed, out_keys.hmac_key, cypher)) {
    std::cerr<<"Error verifying hmac"<<std::endl;
    return DECRYPT_RESULT::ERROR_VERIFYING_HMAC;
  }

  std::cout<<"Signature matches - decrypting"<<std::endl;
  std::vector<uint8_t> decrypted;
  if (!cryptopp_driver::decryptAES(cypher, out_keys.encryption_key, out_keys.iv, decrypted)) {
    std::cerr<<"Error decrypting"<<std::endl;
    return DECRYPT_RESULT::ERROR_DECRYPTING_CONTENT;
  }

  output_utf8<<std::string((const char*)decrypted.data(), decrypted.size());
  std::cout<<"Decoded: \""<<output_utf8.str()<<"\""<<std::endl;

  return DECRYPT_RESULT::OK;
}

}

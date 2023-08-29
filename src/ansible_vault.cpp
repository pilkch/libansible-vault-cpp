#include <algorithm>
#include <iomanip>
#include <iostream>
#include <optional>
#include <ranges>
#include <string_view>

#include <climits>
#include <algorithm>
#include <functional>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include "ansible_vault.h"
#include "hex.h"
#include "util.h"

namespace {

template <size_t N>
void CopyStringToBytes(std::string_view value, std::array<uint8_t, N>& out_bytes)
{
  out_bytes.fill(0);

  for (size_t i = 0;(i < value.length()) && (i < N); i++) {
    out_bytes[i] = value.data()[i];
  }
}

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

const size_t SALT_LENGTH = 32;
const size_t KEYLEN = 32;
const size_t IVLEN = 16;
const size_t ITERATIONS = 10000;

const size_t DERIVED_KEY_LENGTH = (2 * KEYLEN) + IVLEN;

class PasswordAndSalt {
public:
  explicit PasswordAndSalt(std::string_view _password) :
    password(_password)
  {
    salt.fill(0);
  }

  PasswordAndSalt(std::string_view _password, const std::array<uint8_t, SALT_LENGTH>& _salt) :
    password(_password),
    salt(_salt)
  {
  }

  std::string_view password;
  std::array<uint8_t, SALT_LENGTH> salt;
};


class EncryptionKeyHMACKeyAndIV {
public:
  EncryptionKeyHMACKeyAndIV()
  {
    clear();
  }

  void clear()
  {
    encryption_key.fill(0);
    hmac_key.fill(0);
    iv.fill(0);
  }

  std::array<uint8_t, KEYLEN> encryption_key;
  std::array<uint8_t, KEYLEN> hmac_key;
  std::array<uint8_t, IVLEN> iv;
};




namespace cryptopp_driver {

void fill_random(std::array<uint8_t, 32>& buffer)
{
  CryptoPP::AutoSeededRandomPool prng;
  prng.GenerateBlock(buffer.data(), buffer.size());
}


namespace PKCS5_PBKDF2_HMAC {

void CreateKeys(const PasswordAndSalt& password_and_salt, EncryptionKeyHMACKeyAndIV& out_keys)
{
  std::cout<<"CreateKeys with password: "<<password_and_salt.password<<", password len="<<password_and_salt.password.length()<<", salt len="<<password_and_salt.salt.size()<<std::endl;

  out_keys.clear();

  // Derive key material with PKCS5 PBKDF2 HMAC
  // https://cryptopp.com/wiki/PKCS5_PBKDF2_HMAC

  //CryptoPP::byte derived_bytes[CryptoPP::SHA256::DIGESTSIZE]; // 32 bytes, 256 bits
  std::array<CryptoPP::byte, DERIVED_KEY_LENGTH> derived_bytes;

  CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
  CryptoPP::byte unused = 0;
  pbkdf.DeriveKey(derived_bytes.data(), DERIVED_KEY_LENGTH, unused, (const CryptoPP::byte*)password_and_salt.password.data(), password_and_salt.password.length(), (const CryptoPP::byte*)password_and_salt.salt.data(), password_and_salt.salt.size(), ITERATIONS);

  std::cout<<"Derived: "<<DebugBytesToHexString(derived_bytes)<<std::endl;

  // Get the parts from the derived key material
  // [0..keylen-1]: encryption key
  // [keylen..(keylen * 2) - 1]: hmac key
  // [(keylen * 2) - 1..(keylen * 2) + ivlen) - 1]: ivlen
  const uint8_t* pDerived = static_cast<const uint8_t*>(derived_bytes.data());
  std::copy_n(pDerived, KEYLEN, out_keys.encryption_key.begin());
  std::copy_n(pDerived + KEYLEN, KEYLEN, out_keys.hmac_key.begin());
  std::copy_n(pDerived + KEYLEN + KEYLEN, IVLEN, out_keys.iv.begin());
}

}

namespace PKCS7 {

// 128 bit or 16 bytes
const size_t BLOCK_SIZE_BYTES = 16;

size_t GetPadLength(size_t cipher_length)
{
  size_t padding_length = (BLOCK_SIZE_BYTES - (cipher_length % BLOCK_SIZE_BYTES));

  if (padding_length == 0)
  {
    padding_length = BLOCK_SIZE_BYTES;
  }

  return padding_length;
}

size_t GetUnpaddedLength(const uint8_t* decrypted, size_t decrypted_length)
{
  const size_t pad_length = decrypted[decrypted_length - 1];

  if (pad_length > decrypted_length) {
    return 0;
  }

  return decrypted_length - pad_length;
}

std::vector<uint8_t> pad(std::string_view plain_text_utf8)
{
  const size_t padded_length = GetPadLength(plain_text_utf8.length());
  std::cout<<"pad padded_length: "<<padded_length<<std::endl;

  // Create an padded vector with all the bytes set to the padded length
  std::vector<uint8_t> padded(plain_text_utf8.length() + padded_length, uint8_t(padded_length));

  // Then copy our plain text data over the unpadded part at the start
  memcpy(padded.data(), plain_text_utf8.data(), plain_text_utf8.length());

  return padded;
}

}


bool calculateHMAC(const std::array<uint8_t, KEYLEN>& hmac_key, const std::vector<uint8_t>& data, std::array<uint8_t, 32>& out_hmac)
{
  out_hmac.fill(0);

  try {
    CryptoPP::HMAC<CryptoPP::SHA256> hmac((const CryptoPP::byte*)hmac_key.data(), hmac_key.size());

    const bool pumpAll = true;
    CryptoPP::ArraySource ss2((const CryptoPP::byte*)data.data(), data.size(), pumpAll,
      new CryptoPP::HashFilter(hmac,
        new CryptoPP::ArraySink(out_hmac.data(), out_hmac.size())
      )
    );
  } catch(const CryptoPP::Exception& e) {
    std::cerr<<e.what()<<std::endl;
    return false;
  }

  return true;
}

bool verifyHMAC(const std::array<uint8_t, 32>& expected_hmac, const std::array<uint8_t, KEYLEN>& hmac_key, const std::vector<uint8_t>& data)
{
  std::array<uint8_t, 32> calculated_hmac;
  if (!calculateHMAC(hmac_key, data, calculated_hmac)) {
    std::cerr<<"verifyHMAC Error calculating HMAC"<<std::endl;
    return false;
  }

  std::cout<<"verifyHMAC"<<std::endl;
  std::cout<<"Expected: "<<DebugBytesToHexString(expected_hmac)<<std::endl;
  std::cout<<"Calculated: "<<DebugBytesToHexString(calculated_hmac)<<std::endl;
  return (expected_hmac == calculated_hmac);
}


bool encryptAES(const std::vector<uint8_t>& plaintext, const std::array<uint8_t, 32>& key, const std::array<uint8_t, 16>& iv, std::vector<uint8_t>& out_encrypted)
{
  std::cout<<"encryptAES plaintext length: "<<plaintext.size()<<std::endl;

  out_encrypted.assign(plaintext.size(), 0);

  try {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV(static_cast<const CryptoPP::byte*>(key.data()), key.size(), static_cast<const CryptoPP::byte*>(iv.data()));

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    CryptoPP::ArraySource(static_cast<const CryptoPP::byte*>(plaintext.data()), plaintext.size(), true,
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::ArraySink(static_cast<CryptoPP::byte*>(out_encrypted.data()), out_encrypted.size())
      )
    );
  } catch(const CryptoPP::Exception& e) {
      std::cerr<<e.what()<<std::endl;
      return false;
  }

  std::cout<<"encryptAES Encoded length: "<<out_encrypted.size()<<", text: "<<std::string((const char*)out_encrypted.data(), out_encrypted.size())<<std::endl;
  return true;
}

bool decryptAES(const std::vector<uint8_t>& cypher, const std::array<uint8_t, 32>& key, const std::array<uint8_t, 16>& iv, std::vector<uint8_t>& out_decrypted)
{
  std::cout<<"decryptAES cypher length: "<<cypher.size()<<std::endl;

  out_decrypted.assign(cypher.size(), 0);

  try {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV(static_cast<const uint8_t*>(key.data()), key.size(), static_cast<const uint8_t*>(iv.data()));

    CryptoPP::ArraySource(static_cast<const uint8_t*>(cypher.data()), cypher.size(), true,
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::ArraySink(static_cast<CryptoPP::byte*>(out_decrypted.data()), out_decrypted.size())
      )
    );
  } catch(const CryptoPP::Exception& e) {
    std::cerr<<e.what()<<std::endl;
    return false;
  }

  // Handle the padding because CryptoPP kept complaining that the padding flags can't be used with AES CTR
  const size_t unpadded_length = PKCS7::GetUnpaddedLength((const uint8_t*)out_decrypted.data(), cypher.size());

  // Truncate the output to the correct size
  out_decrypted.resize(unpadded_length);

  std::cout<<"decryptAES Decoded length: "<<out_decrypted.size()<<", text: "<<std::string((const char*)out_decrypted.data(), out_decrypted.size())<<std::endl;
  return true;
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

  std::array<uint8_t, 32> hmacHash;
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

ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, const std::array<uint8_t, 32>& salt, std::ostringstream& output_utf8)
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
  std::array<uint8_t, 32> expected_hmac_trimmed;
  std::copy_n(vault_content.hmac.begin(), 32, expected_hmac_trimmed.begin());
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

#pragma once

#include <array>
#include <vector>

#include "common.h"

namespace vault {

namespace cryptopp_driver {

void fill_random(SecureArray<uint8_t, 32>& buffer);

namespace PKCS5_PBKDF2_HMAC {

void CreateKeys(const PasswordAndSalt& password_and_salt, EncryptionKeyHMACKeyAndIV& out_keys);

}

namespace PKCS7 {

std::vector<uint8_t> pad(std::string_view plaintext);

}

bool calculateHMAC(const SecureArray<uint8_t, 32>& hmac_key, const std::vector<uint8_t>& data, SecureArray<uint8_t, 32>& out_hmac);
bool verifyHMAC(const SecureArray<uint8_t, 32>& expected_hmac, const SecureArray<uint8_t, 32>& hmac_key, const std::vector<uint8_t>& data);

bool encryptAES(std::string_view plaintext, const SecureArray<uint8_t, 32>& key, const SecureArray<uint8_t, 16>& iv, std::vector<uint8_t>& out_encrypted);
bool decryptAES(const std::vector<uint8_t>& cypher, const SecureArray<uint8_t, 32>& key, const SecureArray<uint8_t, 16>& iv, std::vector<uint8_t>& out_decrypted);

}

}

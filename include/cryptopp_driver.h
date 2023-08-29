#pragma once

#include <array>
#include <vector>

#include "common.h"

namespace vault {

namespace cryptopp_driver {

void fill_random(std::array<uint8_t, 32>& buffer);

namespace PKCS5_PBKDF2_HMAC {

void CreateKeys(const PasswordAndSalt& password_and_salt, EncryptionKeyHMACKeyAndIV& out_keys);

}

namespace PKCS7 {

std::vector<uint8_t> pad(std::string_view plain_text_utf8);

}

bool calculateHMAC(const std::array<uint8_t, 32>& hmac_key, const std::vector<uint8_t>& data, std::array<uint8_t, 32>& out_hmac);
bool verifyHMAC(const std::array<uint8_t, 32>& expected_hmac, const std::array<uint8_t, 32>& hmac_key, const std::vector<uint8_t>& data);

bool encryptAES(const std::vector<uint8_t>& plaintext, const std::array<uint8_t, 32>& key, const std::array<uint8_t, 16>& iv, std::vector<uint8_t>& out_encrypted);
bool decryptAES(const std::vector<uint8_t>& cypher, const std::array<uint8_t, 32>& key, const std::array<uint8_t, 16>& iv, std::vector<uint8_t>& out_decrypted);

}

}

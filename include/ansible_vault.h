#pragma once

#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace vault {

enum class DECRYPT_RESULT {
    ERROR_PARSING_ENVELOPE_ANSIBLE_VAULT_SIGNATURE,
    ERROR_UNSUPPORTED_ENVELOPE_VERSION,
    ERROR_UNSUPPORED_ENCRYPTION_METHOD,
    ERROR_PARSING_VAULT_CONTENT_SALT,
    ERROR_PARSING_VAULT_CONTENT_HMAC,
    ERROR_VERIFYING_HMAC,
    ERROR_DECRYPTING_CONTENT,
    OK
};

enum class ENCRYPT_RESULT {
    ERROR_ALREADY_ENCRYPTED,
    ERROR_AES_ENCRYPTION_FAILED,
    ERROR_CALCULATING_HMAC,
    OK
};

enum class ENCRYPTION_METHOD {
    AES256
};



class VaultInfo {
public:
    VaultInfo();

    void clear();

    std::string vault_version;
    ENCRYPTION_METHOD encryption_method;
};

DECRYPT_RESULT ParseVaultInfoString(std::string_view& info_line, VaultInfo& out_vault_info);


class VaultContent {
public:
    void clear()
    {
        salt.fill(0);
        hmac.fill(0);
        data.clear();
    }

    std::array<uint8_t, 32> salt;
    std::array<uint8_t, 32> hmac;
    std::vector<uint8_t> data;
};

DECRYPT_RESULT ParseVaultContent(std::string_view& encrypted_data, VaultContent& out_vault_content);


bool is_encrypted(const std::string_view& content);

// Encrypt some plain text in the encrypted vault format
// https://github.com/ansible/ansible/blob/56b67cccc52312366b9ceed02a6906452864e04d/lib/ansible/parsing/vault/__init__.py#L587
//
// returns a UTF-8 encoded byte str of encrypted data.
// The string contains a header identifying this as vault encrypted data and formatted to newline terminated lines of 80 characters.
// This is suitable for dumping as is to a vault file.
ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, const std::array<uint8_t, 32>& salt, std::ostringstream& output_utf8);
ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::ostringstream& output_utf8);

DECRYPT_RESULT decrypt(std::string_view encrypted_utf8, std::string_view password_utf8, std::ostringstream& output_utf8);

bool calculateHMAC(const std::array<uint8_t, 32>& hmac_key, const std::vector<uint8_t>& data, std::array<uint8_t, 32>& out_hmac);
bool verifyHMAC(const std::array<uint8_t, 32>& expected_hmac, const std::array<uint8_t, 32>& hmac_key, const std::vector<uint8_t>& data);

}

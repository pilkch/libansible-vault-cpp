#pragma once

#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace vault {

enum class DECRYPT_RESULT {
    ERROR_PARSING_ENVELOPE_ANSIBLE_VAULT_SIGNATURE,
    ERROR_INVALID_ENVELOPE_VERSION,
    ERROR_UNSUPPORTED_ENVELOPE_VERSION,
    ERROR_UNSUPPORED_ENCRYPTION_METHOD,
    ERROR_DECRYPTING_CONTENT,
    OK
};

enum class ENCRYPT_RESULT {
    ERROR_ALREADY_ENCRYPTED,
    OK
};

enum class ENCRYPTION_METHOD {
    AES256
};

bool is_encrypted(const std::string_view& content);

// Encrypt some plain text in the encrypted vault format
// https://github.com/ansible/ansible/blob/56b67cccc52312366b9ceed02a6906452864e04d/lib/ansible/parsing/vault/__init__.py#L587
//
// returns a UTF-8 encoded byte str of encrypted data.
// The string contains a header identifying this as vault encrypted data and formatted to newline terminated lines of 80 characters.
// This is suitable for dumping as is to a vault file.
ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, ENCRYPTION_METHOD encryption_method, std::string_view password_utf8, std::optional<std::string_view> salt_utf8, std::optional<std::string_view> vault_id_utf8, std::ostringstream& output_utf8);

DECRYPT_RESULT parse_envelope();

DECRYPT_RESULT decrypt(std::string_view encrypted_utf8, std::string_view password_utf8, std::optional<std::string_view> salt_utf8, std::string& output_vault_id_utf8, std::ostringstream& output_utf8);

}

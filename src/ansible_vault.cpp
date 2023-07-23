#include <algorithm>
#include <iostream>
#include <optional>
#include <ranges>
#include <string_view>

#include "ansible_vault.h"


class SHA256 {
public:
    std::string encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::optional<std::string_view> salt);
    std::string decrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::optional<std::string_view> salt);
};

std::string SHA256::encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::optional<std::string_view> salt)
{
    ...
    return "";
}

std::string SHA256::decrypt(std::string_view encrypted_text_utf8, std::string_view password_utf8, std::optional<std::string_view> salt)
{
    ...
    return "";
}

namespace {

/*auto print = [](auto const& view)
{
    for (std::cout << "{ "; const auto element : view)
        std::cout << element;
    std::cout << " } ";
};

void split_new_lines(std::string_view input, std::ostringstream& output)
{
    constexpr std::string_view delim { " " };
    std::ranges::for_each(input | std::views::lazy_split(delim), print);
}*/

void output_to_string_wrap_80_characters(std::string_view input, std::ostringstream& output)
{
    const size_t max_line_length = 80;

    while (!input.empty()) {
        // Get up to 40 more characters from the string
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

const std::string VAULT_HEADER = "$ANSIBLE_VAULT";
const std::string VAULT_VERSION = "1.1";
const std::string CIPHER_AES256 = "AES256";

bool is_encrypted(const std::string_view& content)
{
  return content.starts_with(VAULT_HEADER);
}

ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, ENCRYPTION_METHOD encryption_method, std::string_view password_utf8, std::optional<std::string_view> salt_utf8, std::optional<std::string_view> vault_id_utf8, std::ostringstream& output_utf8)
{
    output_utf8.clear();

    if (is_encrypted(plain_text_utf8)) {
        return ENCRYPT_RESULT::ERROR_ALREADY_ENCRYPTED;
    }

    // Encrypt the content
    SHA256 sha256;
    const std::string plaintext_encrypted = sha256.encrypt(plain_text_utf8, password_utf8, salt_utf8);

    // Format the data for output to the file
    //output_utf8 = format_vaulttext_envelope(plaintext_encrypted, encryption_method, vault_id_utf8);

    output_utf8<<VAULT_HEADER<<";"<<VAULT_VERSION<<";"<<CIPHER_AES256<<"\n";

    output_to_string_wrap_80_characters(plaintext_encrypted, output_utf8);

    return ENCRYPT_RESULT::OK;
}


DECRYPT_RESULT decrypt(std::string_view encrypted_utf8, std::string_view password_utf8, std::optional<std::string_view> salt_utf8, std::string& output_vault_id_utf8, std::ostringstream& output_utf8)
{
    output_vault_id_utf8.clear();
    output_utf8.clear();

    return DECRYPT_RESULT::OK;
}

}

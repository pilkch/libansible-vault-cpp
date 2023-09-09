#include "ansible_vault.h"
#include "util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t data_length)
{
  const std::string original_plaintext_str = "Setec Astronomy";
  const vault::SecureString original_plaintext(original_plaintext_str.c_str(), original_plaintext_str.length());

  const vault::SecureString password((const char*)data, data_length);
  std::ostringstream encrypted;
  vault::encrypt(original_plaintext, password, encrypted);

  vault::SecureString output_plaintext_result;
  vault::decrypt(encrypted.str(), password, output_plaintext_result);

  return 0;
}

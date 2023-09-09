#include "ansible_vault.h"
#include "util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_length)
{
  const std::vector<std::string> passwords_str = {
    "ansible",
    "shibboleet"
  };

  // Brute force the password
  // The most likely passed in data is an invalid ansible vault, every attempt is super unlikely to work, but I don't really have any better ideas
  //
  // One this we could do is make the data a pair of "<password>\n<ansible vault>", then we know which password to try?
  // It would mean the corpus files aren't regular ansible vault files though...
  for (auto&& password_str : passwords_str) {
    const vault::SecureString password(password_str.c_str(), password_str.length());

    const std::string encrypted((const char*)data, data_length);

    vault::SecureString output_plaintext_result;
    if (vault::decrypt(encrypted, password, output_plaintext_result) == vault::DECRYPT_RESULT::OK) {
      // This was the right password
      break;
    }
  }

  return 0;
}

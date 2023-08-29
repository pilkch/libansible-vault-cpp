#pragma once

#include <array>
#include <string_view>

#include "util.h"

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

}

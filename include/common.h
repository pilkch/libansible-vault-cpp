#pragma once

#include <array>
#include <span>
#include <string_view>

#include "util.h"

namespace vault {

template <class T, size_t count>
class SecureArray {
public:
  ~SecureArray()
  {
    // Clear the buffer before it is released
    secure_clear(buffer.data(), buffer.size());
  }

  constexpr std::span<T> get_span() const
  {
    return std::span<T>((T*)buffer.begin(), buffer.end());
  }
  constexpr std::span<T> get_span()
  {
    return std::span<T>((T*)buffer.begin(), buffer.end());
  }

  constexpr const T* data() const { return buffer.data(); }
  constexpr T* data() { return buffer.data(); }
  constexpr size_t size() const { return buffer.size(); }

  void fill(const T& value)
  {
    buffer.fill(value);
  }


  typedef std::array<T, count>::iterator iterator;
  typedef std::array<T, count>::const_iterator const_iterator;

  constexpr iterator begin() noexcept { return buffer.begin(); }
  constexpr const_iterator begin() const noexcept { return buffer.begin(); }
  constexpr const_iterator cbegin() const noexcept { return buffer.cbegin(); }

  constexpr iterator end() noexcept { return buffer.end(); }
  constexpr const_iterator end() const noexcept { return buffer.end(); }
  constexpr const_iterator cend() const noexcept { return buffer.cend(); }

  constexpr bool operator==(const SecureArray<T, count>& rhs) const { return (buffer == rhs.buffer); }

private:
  std::array<T, count> buffer;
};


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

  PasswordAndSalt(std::string_view _password, const SecureArray<uint8_t, SALT_LENGTH>& _salt) :
    password(_password),
    salt(_salt)
  {
  }

  std::string_view password;
  SecureArray<uint8_t, SALT_LENGTH> salt;
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

  SecureArray<uint8_t, KEYLEN> encryption_key;
  SecureArray<uint8_t, KEYLEN> hmac_key;
  SecureArray<uint8_t, IVLEN> iv;
};

}

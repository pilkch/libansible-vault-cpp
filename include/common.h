#pragma once

#include <cstdint>
#include <cstring>

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


  typedef typename std::array<T, count>::iterator iterator;
  typedef typename std::array<T, count>::const_iterator const_iterator;

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


class SecureString {
public:
  SecureString() :
    value(nullptr),
    len(0),
    capacity(0)
  {
    // Default length
    const size_t DEFAULT_LENGTH = 4096;
    assign(DEFAULT_LENGTH, 0);
  }
  SecureString(const char* _value, size_t _length) :
    value(nullptr),
    len(0),
    capacity(0)
  {
    assign(_value, _length);
  }
  ~SecureString()
  {
    // Clear the value before it is released
    clear();

    if (value != nullptr) {
      delete[] value;
      value = nullptr;
      len = 0;
      capacity = 0;
    }
  }

  constexpr char* data() { return value; }
  constexpr const char* c_str() const { return value; }
  constexpr char* c_str() { return value; }
  constexpr size_t length() const { return len; }

  constexpr std::string_view get_string_view() const { return std::string_view(value, len); }

  void clear()
  {
    if (value != nullptr) {
      secure_clear(value, capacity);
    }

    len = 0;
  }

  void assign(size_t _length, char c)
  {
    clear_and_resize(_length);

    if (_length != 0) {
      for (size_t i = 0; i < _length; i++) {
        value[i] = c;
      }
      len = _length;
      value[len] = 0; // Set the null terminator
    }
  }

  void assign(const char* _value, size_t _length)
  {
    clear_and_resize(_length);

    if ((_value != nullptr) && (_length != 0)) {
      memcpy(value, _value, _length);
      len = _length;
      value[len] = 0; // Set the null terminator
    }
  }

  void shrink(size_t _length)
  {
    if ((value != nullptr) && (_length < len)) {
      // Clear the bytes at the end
      secure_clear(value + _length, (len - _length));

      // Now set our length to the shorter value
      len = _length;
    }
  }

  constexpr bool starts_with(std::string_view prefix) const
  {
    if ((value == nullptr) || (len == 0) || prefix.empty() || (prefix.size() > len)) {
      return false;
    }

    return (memcmp(prefix.data(), value, prefix.size()) == 0);
  }

private:
  void clear_and_resize(size_t _length)
  {
    clear();

    // If the new length is larger than the capacity then we need to reallocate
    if (_length + 1 > capacity) {
      if (value != nullptr) {
        delete[] value;
        value = nullptr;
        len = 0;
        capacity = 0;
      }
    }

    // If we destroyed the buffer then create a larger one here
    if (value == nullptr) {
      value = new char[_length + 1];
      capacity = _length + 1;
    }

    // Finally we can set our new length
    len = _length;
  }

  char* value;
  size_t len;
  size_t capacity;
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

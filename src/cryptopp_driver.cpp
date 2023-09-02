#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include "common.h"
#include "cryptopp_driver.h"
#include "hex.h"

namespace vault {

namespace cryptopp_driver {

void fill_random(SecureArray<uint8_t, 32>& buffer)
{
  CryptoPP::AutoSeededRandomPool prng;
  prng.GenerateBlock(buffer.data(), buffer.size());
}


namespace PKCS5_PBKDF2_HMAC {

void CreateKeys(const PasswordAndSalt& password_and_salt, EncryptionKeyHMACKeyAndIV& out_keys)
{
  //std::cout<<"CreateKeys with password: "<<password_and_salt.password<<", password len="<<password_and_salt.password.length()<<", salt len="<<password_and_salt.salt.size()<<std::endl;

  out_keys.clear();

  // Derive key material with PKCS5 PBKDF2 HMAC
  // https://cryptopp.com/wiki/PKCS5_PBKDF2_HMAC

  //CryptoPP::byte derived_bytes[CryptoPP::SHA256::DIGESTSIZE]; // 32 bytes, 256 bits
  std::array<CryptoPP::byte, DERIVED_KEY_LENGTH> derived_bytes;

  CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
  CryptoPP::byte unused = 0;
  pbkdf.DeriveKey(derived_bytes.data(), DERIVED_KEY_LENGTH, unused, (const CryptoPP::byte*)password_and_salt.password.data(), password_and_salt.password.length(), (const CryptoPP::byte*)password_and_salt.salt.data(), password_and_salt.salt.size(), ITERATIONS);

  //std::cout<<"Derived: "<<DebugBytesToHexString(derived_bytes)<<std::endl;

  // Get the parts from the derived key material
  // [0..keylen-1]: encryption key
  // [keylen..(keylen * 2) - 1]: hmac key
  // [(keylen * 2) - 1..(keylen * 2) + ivlen) - 1]: ivlen
  const uint8_t* pDerived = static_cast<const uint8_t*>(derived_bytes.data());
  std::copy_n(pDerived, KEYLEN, out_keys.encryption_key.begin());
  std::copy_n(pDerived + KEYLEN, KEYLEN, out_keys.hmac_key.begin());
  std::copy_n(pDerived + KEYLEN + KEYLEN, IVLEN, out_keys.iv.begin());
}

}

namespace PKCS7 {

// 128 bit or 16 bytes
const size_t BLOCK_SIZE_BYTES = 16;

size_t GetPadLength(size_t cipher_length)
{
  size_t padding_length = (BLOCK_SIZE_BYTES - (cipher_length % BLOCK_SIZE_BYTES));

  if (padding_length == 0)
  {
    padding_length = BLOCK_SIZE_BYTES;
  }

  return padding_length;
}

size_t GetUnpaddedLength(const uint8_t* decrypted, size_t decrypted_length)
{
  const size_t pad_length = decrypted[decrypted_length - 1];

  if (pad_length > decrypted_length) {
    return 0;
  }

  return decrypted_length - pad_length;
}

std::vector<uint8_t> pad(std::string_view plaintext)
{
  const size_t padded_length = GetPadLength(plaintext.length());
  //std::cout<<"pad padded_length: "<<padded_length<<std::endl;

  // Create an padded vector with all the bytes set to the padded length
  std::vector<uint8_t> padded(plaintext.length() + padded_length, uint8_t(padded_length));

  // Then copy our plain text data over the unpadded part at the start
  memcpy(padded.data(), plaintext.data(), plaintext.length());

  return padded;
}

}


bool calculateHMAC(const SecureArray<uint8_t, KEYLEN>& hmac_key, const std::vector<uint8_t>& data, SecureArray<uint8_t, 32>& out_hmac)
{
  out_hmac.fill(0);

  try {
    CryptoPP::HMAC<CryptoPP::SHA256> hmac((const CryptoPP::byte*)hmac_key.data(), hmac_key.size());

    const bool pumpAll = true;
    CryptoPP::ArraySource((const CryptoPP::byte*)data.data(), data.size(), pumpAll,
      new CryptoPP::HashFilter(hmac,
        new CryptoPP::ArraySink(out_hmac.data(), out_hmac.size())
      )
    );
  } catch(const CryptoPP::Exception& e) {
    std::cerr<<e.what()<<std::endl;
    return false;
  }

  return true;
}

bool verifyHMAC(const SecureArray<uint8_t, 32>& expected_hmac, const SecureArray<uint8_t, KEYLEN>& hmac_key, const std::vector<uint8_t>& data)
{
  SecureArray<uint8_t, 32> calculated_hmac;
  if (!calculateHMAC(hmac_key, data, calculated_hmac)) {
    std::cerr<<"verifyHMAC Error calculating HMAC"<<std::endl;
    return false;
  }

  //std::cout<<"verifyHMAC"<<std::endl;
  //std::cout<<"Expected: "<<DebugBytesToHexString(expected_hmac)<<std::endl;
  //std::cout<<"Calculated: "<<DebugBytesToHexString(calculated_hmac)<<std::endl;
  return (expected_hmac == calculated_hmac);
}


bool encryptAES(std::string_view plaintext, const SecureArray<uint8_t, 32>& key, const SecureArray<uint8_t, 16>& iv, std::vector<uint8_t>& out_encrypted)
{
  //std::cout<<"encryptAES plaintext length: "<<plaintext.size()<<std::endl;

  //std::cout<<"Original plaintext length: "<<plaintext.length()<<std::endl;
  const std::vector<uint8_t> plaintext_padded = PKCS7::pad(plaintext);
  //std::cout<<"Padded plaintext length: "<<plaintext_padded.size()<<std::endl;

  out_encrypted.assign(plaintext_padded.size(), 0);

  try {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV(static_cast<const CryptoPP::byte*>(key.data()), key.size(), static_cast<const CryptoPP::byte*>(iv.data()));

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    CryptoPP::ArraySource(static_cast<const CryptoPP::byte*>(plaintext_padded.data()), plaintext_padded.size(), true,
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::ArraySink(static_cast<CryptoPP::byte*>(out_encrypted.data()), out_encrypted.size())
      )
    );
  } catch(const CryptoPP::Exception& e) {
    std::cerr<<e.what()<<std::endl;
    return false;
  }

  //std::cout<<"encryptAES Encoded length: "<<out_encrypted.size()<<", text: "<<std::string((const char*)out_encrypted.data(), out_encrypted.size())<<std::endl;
  return true;
}

bool decryptAES(const std::vector<uint8_t>& cypher, const SecureArray<uint8_t, 32>& key, const SecureArray<uint8_t, 16>& iv, std::vector<uint8_t>& out_decrypted)
{
  //std::cout<<"decryptAES cypher length: "<<cypher.size()<<std::endl;

  out_decrypted.assign(cypher.size(), 0);

  try {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV(static_cast<const uint8_t*>(key.data()), key.size(), static_cast<const uint8_t*>(iv.data()));

    CryptoPP::ArraySource(static_cast<const uint8_t*>(cypher.data()), cypher.size(), true,
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::ArraySink(static_cast<CryptoPP::byte*>(out_decrypted.data()), out_decrypted.size())
      )
    );
  } catch(const CryptoPP::Exception& e) {
    std::cerr<<e.what()<<std::endl;
    return false;
  }

  // Handle the padding because CryptoPP kept complaining that the padding flags can't be used with AES CTR
  const size_t unpadded_length = PKCS7::GetUnpaddedLength((const uint8_t*)out_decrypted.data(), cypher.size());

  // Truncate the output to the correct size
  out_decrypted.resize(unpadded_length);

  //std::cout<<"decryptAES Decoded length: "<<out_decrypted.size()<<", text: "<<std::string((const char*)out_decrypted.data(), out_decrypted.size())<<std::endl;
  return true;
}

}

}

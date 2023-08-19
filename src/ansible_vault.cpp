#include <algorithm>
#include <iomanip>
#include <iostream>
#include <optional>
#include <ranges>
#include <string_view>

#include <random>
#include <climits>
#include <algorithm>
#include <functional>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include "ansible_vault.h"

// Explicit memset and constant time memory comparison
// https://github.com/AGWA/git-crypt/blob/master/util.cpp

void* explicit_memset(void* s, int c, std::size_t n)
{
  volatile unsigned char* p = reinterpret_cast<unsigned char*>(s);

  while (n--) {
    *p++ = c;
  }

  return s;
}

bool leakless_equals(const unsigned char* a, const unsigned char* b, std::size_t len)
{
  volatile int diff = 0;

  while (len > 0) {
    diff |= *a++ ^ *b++;
    --len;
  }

  return diff == 0;
}

bool leakless_equals(const void* a, const void* b, std::size_t len)
{
  return leakless_equals(reinterpret_cast<const unsigned char*>(a), reinterpret_cast<const unsigned char*>(b), len);
}

std::string strip_new_lines(std::string_view view)
{
    std::ostringstream o;

    for (auto& c : view) {
        if (c != '\n') {
            o<<c;
        }
    }

    return o.str();
}

// Decrypt
//
// Command line example
// https://stackoverflow.com/questions/43467180/how-to-decrypt-string-with-ansible-vault-2-3-0
// Password: 123
/*
echo '$ANSIBLE_VAULT;1.1;AES256
65333363656231663530393762613031336662613262326666386233643763636339366235626334
3236636366366131383962323463633861653061346538360a386566363337383133613761313566
31623761656437393862643936373564313565663633636366396231653131386364336534626338
3430343561626237660a333562616537623035396539343634656439356439616439376630396438
3730' | ansible-vault decrypt
*/

/*
echo '$ANSIBLE_VAULT;1.2;AES256;dev
30613233633461343837653833666333643061636561303338373661313838333565653635353162
3263363434623733343538653462613064333634333464660a663633623939393439316636633863
61636237636537333938306331383339353265363239643939666639386530626330633337633833
6664656334373166630a363736393262666465663432613932613036303963343263623137386239
6330' | ansible-vault decrypt
*/

#if 0

In place encrypt
ansible-vault encrypt vars/vault.yaml

In place decrypt
ansible-vault decrypt vars/vault.yaml




// Encrypt
echo "password" > password.txt
echo "My plain text file\nMultiple lines\n" > plaintext.txt
ansible-vault encrypt --vault-password-file password.txt --output output_encrypted.txt plaintext.txt

// Decrypt
ansible-vault decrypt --vault-password-file password.txt --output output_decrypted.txt output_encrypted.txt
OR
(Asks for password)
ansible-vault decrypt --output sample_decrypted.txt test/data/sample.txt

#endif

namespace vault {

class SHA256 {
public:
    std::string encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::optional<std::string_view> salt);
    std::string decrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::optional<std::string_view> salt);
};

std::string SHA256::encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::optional<std::string_view> salt)
{
    return "";
}

std::string SHA256::decrypt(std::string_view encrypted_text_utf8, std::string_view password_utf8, std::optional<std::string_view> salt)
{
    return "";
}

}

namespace vault {

void EncodeStringToHexString(std::string_view view, std::ostringstream& output)
{
  for (char c : view) {
    output<<std::setfill('0')<<std::setw(2)<<std::hex<<int(c);
  }
}

std::string DecodeHexStringToString(std::string_view& view)
{
    std::ostringstream o;

    while (view.length() >= 2) {
        const char bytes[2] = {
            view.data()[0],
            view.data()[1]
        };
        if (isxdigit(bytes[0]) && isxdigit(bytes[1])) {
            uint8_t c = hexval(bytes[0]);
            c = (c << 4) + hexval(bytes[1]);
            o<<c;

            view.remove_prefix(2);
        } else {
            // Just skip the character and go to the next one
            view.remove_prefix(1);
        }
    }

    return o.str();
}

void BytesToHexString(const std::vector<uint8_t>& buffer, size_t line_length, std::ostringstream& output)
{
    for (auto& b : buffer) {
        output<<std::setfill('0')<<std::setw(2)<<std::hex<<int(b);
    }

    std::cout<<"BytesToHexString Buffer length: "<<buffer.size()<<std::endl;

    // Reset the stream flags
    output<<std::dec;
}

std::string BytesToHexString(const CryptoPP::byte* value, size_t length)
{
    std::string result;
    const bool uppercase = false;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result), uppercase);

    encoder.Put(value, length);
    encoder.MessageEnd();

    return result;
}

std::vector<uint8_t> HexStringToBytes(std::string_view data)
{
    std::vector<uint8_t> output;

    while (data.length() >= 2) {
        const char bytes[2] = {
            data.data()[0],
            data.data()[1]
        };
        if (isxdigit(bytes[0]) && isxdigit(bytes[1])) {
            uint8_t c = hexval(bytes[0]);
            c = (c << 4) + hexval(bytes[1]);
            output.push_back(int(c));

            data.remove_prefix(2);
        } else {
            // Just remove one byte and check the next one
            data.remove_prefix(1);
        }
    }

    return output;
}

}

namespace vault {

const size_t SALT_LENGTH = 32;
const size_t KEYLEN = 32;
const size_t IVLEN = 16;
const size_t ITERATIONS = 10000;

const size_t DERIVED_KEY_LENGTH = (2 * KEYLEN) + IVLEN;

const std::string CHAR_ENCODING = "UTF-8";

class EncryptionKeychain {
public:
    std::array<uint8_t, 32> salt;
    std::string_view password_utf8;

    EncryptionKeychain(const std::array<uint8_t, 32>& _salt, std::string_view _password_utf8)
    {
        salt = _salt;
        password_utf8 = _password_utf8;
    }

    static std::array<uint8_t, 32> generateSalt(size_t length)
    {
        std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t> rbe;
        std::array<uint8_t, 32> salt;
        std::generate(begin(salt), end(salt), std::ref(rbe));

        return salt;
    }

    void createKeys()
    {
        // Returns a byte array:
        // [0..keylen-1]: encryption key
        // [keylen..(keylen * 2) - 1]: hmac key
        // [(keylen * 2) - 1..(keylen * 2) + ivlen) - 1]: ivlen
        const std::array<uint8_t, DERIVED_KEY_LENGTH> rawkeys = createRawKey();

        encryptionKey = getEncryptionKey(rawkeys);
        hmacKey = getHMACKey(rawkeys);
        iv = getIV(rawkeys);
    }

    const std::array<uint8_t, KEYLEN>& getEncryptionKey() const
    {
        return encryptionKey;
    }

    const std::array<uint8_t, KEYLEN>& getHMACKey() const
    {
        return hmacKey;
    }

    const std::array<uint8_t, IVLEN>& getIV() const
    {
        return iv;
    }

private:
    std::array<uint8_t, DERIVED_KEY_LENGTH> createRawKey() const
    {
        std::cout<<"createRawKey with password: "<<password_utf8<<", password len="<<password_utf8.length()<<", salt len="<<salt.size()<<std::endl;

        // https://cryptopp.com/wiki/PKCS5_PBKDF2_HMAC

        //CryptoPP::byte derived_bytes[CryptoPP::SHA256::DIGESTSIZE]; // 32 bytes, 256 bits
        CryptoPP::byte derived_bytes[DERIVED_KEY_LENGTH];

        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
        CryptoPP::byte unused = 0;
        pbkdf.DeriveKey(derived_bytes, DERIVED_KEY_LENGTH, unused, (const CryptoPP::byte*)password_utf8.data(), password_utf8.length(), (const CryptoPP::byte*)salt.data(), salt.size(), ITERATIONS);

        std::array<uint8_t, DERIVED_KEY_LENGTH> derived;
        size_t i = 0;
        for (auto& b : derived_bytes) {
            if (i < DERIVED_KEY_LENGTH) {
                derived[i] = b;
                i++;
        }
    }

        std::cout << "Derived: " << BytesToHexString(derived.data(), DERIVED_KEY_LENGTH) << std::endl;

        return derived;
        }

    static std::array<uint8_t, KEYLEN> getEncryptionKey(const std::array<uint8_t, DERIVED_KEY_LENGTH>& keys)
    {
        std::array<uint8_t, KEYLEN> result;
        std::copy_n(keys.begin(), KEYLEN, result.begin());
        return result;
    }

    static std::array<uint8_t, KEYLEN> getHMACKey(const std::array<uint8_t, DERIVED_KEY_LENGTH>& keys)
    {
        std::array<uint8_t, KEYLEN> result;
        std::copy_n(keys.begin() + KEYLEN, KEYLEN, result.begin());
        return result;
    }

    static std::array<uint8_t, IVLEN> getIV(const std::array<uint8_t, DERIVED_KEY_LENGTH>& keys)
    {
        std::array<uint8_t, IVLEN> result;
        std::copy_n(keys.begin() + KEYLEN + KEYLEN, IVLEN, result.begin());
        return result;
    }

    std::array<uint8_t, KEYLEN> encryptionKey;
    std::array<uint8_t, KEYLEN> hmacKey;
    std::array<uint8_t, IVLEN> iv;
};

}

namespace {

template <size_t N>
void CopyStringToBytes(std::string_view value, std::array<uint8_t, N>& out_bytes)
{
  out_bytes.fill(0);

  for (size_t i = 0; i < N && i < 32; i++) {
    out_bytes[i] = value.data()[i];
  }
}

void output_to_string_wrap_80_characters(std::string_view input, std::ostringstream& output)
{
    const size_t max_line_length = 80;

    while (!input.empty()) {
        // Get up to 32 more characters from the string
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

std::vector<uint8_t> pad(std::string_view plain_text_utf8)
{
  const size_t padded_length = GetPadLength(plain_text_utf8.length());
  std::cout<<"pad padded_length: "<<padded_length<<std::endl;

  // Create an padded vector with all the bytes set to the padded length
  std::vector<uint8_t> padded(plain_text_utf8.length() + padded_length, uint8_t(padded_length));

  // Then copy our plain text data over the unpadded part at the start
  memcpy(padded.data(), plain_text_utf8.data(), plain_text_utf8.length());

  return padded;
}

}

namespace vault {

// Vault implementation using AES-CTR with an HMAC-SHA256 authentication code.
// Keys are derived using PBKDF2
// http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html

const std::string VAULT_MAGIC = "$ANSIBLE_VAULT";
const std::string VAULT_VERSION = "1.1";
const std::string VAULT_CIPHER_AES256 = "AES256";

bool is_encrypted(const std::string_view& content)
{
  return content.starts_with(VAULT_MAGIC);
}


VaultInfo::VaultInfo() :
    vault_version("1.1"),
    encryption_method(ENCRYPTION_METHOD::AES256)
{
}

void VaultInfo::clear()
{
    vault_version = "1.1";
    encryption_method = ENCRYPTION_METHOD::AES256;
}


std::string GenerateVaultInfoString()
{
    return VAULT_MAGIC + ";" + VAULT_VERSION + ";" + VAULT_CIPHER_AES256;
}

DECRYPT_RESULT ParseVaultInfoString(std::string_view& info_line, VaultInfo& out_vault_info)
{
    out_vault_info.clear();

    // Signature
    size_t found = info_line.find(';');
    if (found == std::string::npos) return DECRYPT_RESULT::ERROR_PARSING_ENVELOPE_ANSIBLE_VAULT_SIGNATURE;

    std::string value(info_line.substr(0, found));
    if (value != VAULT_MAGIC) return DECRYPT_RESULT::ERROR_PARSING_ENVELOPE_ANSIBLE_VAULT_SIGNATURE;

    info_line.remove_prefix(found + 1);


    // Version
    found = info_line.find(';');
    if (found == std::string::npos) return DECRYPT_RESULT::ERROR_UNSUPPORTED_ENVELOPE_VERSION;

    value = info_line.substr(0, found);
    if (value != VAULT_VERSION) return DECRYPT_RESULT::ERROR_UNSUPPORTED_ENVELOPE_VERSION;

    info_line.remove_prefix(found + 1);

    out_vault_info.vault_version = VAULT_VERSION;


    // Version
    found = info_line.find('\n');
    if (found == std::string::npos) return DECRYPT_RESULT::ERROR_UNSUPPORED_ENCRYPTION_METHOD;

    value = info_line.substr(0, found);
    if (value != VAULT_CIPHER_AES256) return DECRYPT_RESULT::ERROR_UNSUPPORED_ENCRYPTION_METHOD;

    info_line.remove_prefix(found + 1);

    out_vault_info.encryption_method = ENCRYPTION_METHOD::AES256;

    return DECRYPT_RESULT::OK;
}

DECRYPT_RESULT ParseVaultContent(std::string_view& original_encrypted_data, VaultContent& out_vault_content)
{
    out_vault_content.clear();

    std::cout<<"ParseVaultContent Original vault text: "<<original_encrypted_data<<std::endl;
    const std::string decrypted_once_data(DecodeHexStringToString(original_encrypted_data));
    std::cout<<"ParseVaultContent Decrypted once: "<<decrypted_once_data<<std::endl;
    std::string_view encrypted_data(decrypted_once_data);

    // Salt
    size_t found = encrypted_data.find('\n');
    if (found == std::string::npos) return DECRYPT_RESULT::ERROR_PARSING_VAULT_CONTENT_SALT;

    const std::string_view salt_hex(encrypted_data.substr(0, found));

    encrypted_data.remove_prefix(found + 1);


    // HMAC
    found = encrypted_data.find('\n');
    if (found == std::string::npos) return DECRYPT_RESULT::ERROR_PARSING_VAULT_CONTENT_HMAC;

    const std::string_view hmac_hex(encrypted_data.substr(0, found));

    encrypted_data.remove_prefix(found + 1);


    // Data
    const std::string_view data_hex(encrypted_data);

    encrypted_data.remove_prefix(found + 1);


    std::cout<<"ParseVaultContent salt: \""<<salt_hex<<"\", hmac: \""<<hmac_hex<<"\", data: \""<<data_hex<<"\""<<std::endl;

    // Get the actual values
    HexStringToBytes(salt_hex, out_vault_content.salt);
    HexStringToBytes(hmac_hex, out_vault_content.hmac);
    out_vault_content.data = HexStringToBytes(data_hex);

    return DECRYPT_RESULT::OK;
}


DECRYPT_RESULT decrypt(std::string_view encrypted_utf8, std::string_view password_utf8, std::optional<std::string_view> salt_utf8, std::string& output_vault_id_utf8, std::ostringstream& output_utf8)
{
    output_vault_id_utf8.clear();
    output_utf8.clear();

    return DECRYPT_RESULT::OK;
}

bool calculateHMAC(const std::array<uint8_t, KEYLEN>& hmac_key, const std::vector<uint8_t>& data, std::array<uint8_t, 32>& out_hmac)
{
std::cout<<"calculateHMAC hmac_key length: "<<hmac_key.size()<<", data length: "<<data.size()<<std::endl;

    out_hmac.fill(0);

    try {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac((const CryptoPP::byte*)hmac_key.data(), hmac_key.size());

std::cout<<"calculateHMAC a"<<std::endl;

        const bool pumpAll = true;
        CryptoPP::ArraySource ss2((const CryptoPP::byte*)data.data(), data.size(), pumpAll, 
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::ArraySink(out_hmac.data(), out_hmac.size())
            )
        );

std::cout<<"calculateHMAC b"<<std::endl;
    } catch(const CryptoPP::Exception& e) {
        std::cerr<<e.what()<<std::endl;
        return false;
    }

std::cout<<"calculateHMAC returning true"<<std::endl;
    return true;
}

bool verifyHMAC(const std::array<uint8_t, 32>& expected_hmac, const std::array<uint8_t, KEYLEN>& hmac_key, const std::vector<uint8_t>& data)
{
    std::array<uint8_t, 32> calculated_hmac;
    if (!calculateHMAC(hmac_key, data, calculated_hmac)) {
        std::cerr<<"verifyHMAC Error calculating HMAC"<<std::endl;
        return false;
    }

    std::ostringstream o1;
    BytesToHexString(expected_hmac, 100, o1);
    std::ostringstream o2;
    BytesToHexString(calculated_hmac, 100, o2);
    std::cout<<"verifyHMAC"<<std::endl;
    std::cout<<"Expected: "<<o1.str()<<std::endl;
    std::cout<<"Calculated: "<<o2.str()<<std::endl;
    return (expected_hmac == calculated_hmac);
}


std::string string_to_hex(const char* text, size_t length)
{
  std::ostringstream o;
  for (size_t i = 0; i < length; i++) {
    o<<std::setfill('0')<<std::setw(2)<<std::hex<<int(text[i]);
}

  return o.str();
}

bool encryptAES(const std::vector<uint8_t>& _plaintext, const std::array<uint8_t, 32>& _key, const std::array<uint8_t, 16>& _iv, std::vector<uint8_t>& out_encrypted)
{
  std::cout<<"encryptAES _plaintext length: "<<_plaintext.size()<<std::endl;
  out_encrypted.clear();

  if (_key.size() != 32) {
    std::cerr<<"encryptAES Key is the wrong size"<<std::endl;
    return false;
  } else if (_iv.size() != CryptoPP::AES::BLOCKSIZE) {
    std::cerr<<"encryptAES IV is the wrong size"<<std::endl;
    return false;
  }

  CryptoPP::byte key[32];
  for (size_t i = 0; i < 32; i++) {
    key[i] = static_cast<CryptoPP::byte>(_key[i]);
}

  CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
  for (size_t i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) {
    iv[i] = static_cast<CryptoPP::byte>(_iv[i]);
}

  std::ostringstream plain;
  for (auto& c : _plaintext) {
    plain<<c;
  }

  std::cout<<"encryptAES plain length: "<<plain.str().length()<<std::endl;

  std::string cipher;

  try {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    CryptoPP::StringSource(plain.str(), true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(cipher)
      )      
    );
  } catch(const CryptoPP::Exception& e) {
      std::cerr<<e.what()<<std::endl;
      return false;
  }

  std::cout<<"encryptAES cipher length: "<<cipher.length()<<", text: "<<cipher<<std::endl;

  for (size_t i = 0; i < cipher.length(); i++) {
    out_encrypted.push_back(cipher[i]);
  }

  std::cout<<"encryptAES Encoded length: "<<out_encrypted.size()<<", text: "<<(const char*)(out_encrypted.data())<<std::endl;
  return true;
}

bool decryptAES(const std::vector<uint8_t>& _cypher, const std::array<uint8_t, 32>& _key, const std::array<uint8_t, 16>& _iv, std::vector<uint8_t>& out_decrypted)
{
    std::cout<<"decryptAES _cypher length: "<<_cypher.size()<<std::endl;
    out_decrypted.clear();

    if (_key.size() != 32) {
        std::cerr<<"decryptAES Key is the wrong size"<<std::endl;
        return false;
    } else if (_iv.size() != CryptoPP::AES::BLOCKSIZE) {
        std::cerr<<"decryptAES IV is the wrong size"<<std::endl;
        return false;
    }

  CryptoPP::byte key[32];
    for (size_t i = 0; i < 32; i++) {
        key[i] = static_cast<CryptoPP::byte>(_key[i]);
    }

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    for (size_t i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) {
        iv[i] = static_cast<CryptoPP::byte>(_iv[i]);
    }

    std::ostringstream cypher;
    for (auto& c : _cypher) {
        cypher<<c;
    }

    std::cout<<"decryptAES cypher length: "<<cypher.str().length()<<std::endl;

    CryptoPP::byte cbRecoveredText[ CryptoPP::AES::BLOCKSIZE ];
    ::memset(cbRecoveredText, 0, sizeof(cbRecoveredText));

    std::string recovered;

    try {
        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv);

#if 0
        d.ProcessData( cbRecoveredText, _cypher.data(), _cypher.size() );
        for (auto& c : cbRecoveredText) {
            out_decrypted.push_back(c);
        }
#elif 0
        CryptoPP::ArraySource(_cypher.data(), _cypher.size(), true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(recovered)
            )
        );
#elif 0
        // The StreamTransformationFilter removes
        //  padding as required.
        CryptoPP::StringSource s(cypher.str(), true, 
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(recovered)
            )
        );
#endif
    } catch(const CryptoPP::Exception& e) {
        std::cerr<<e.what()<<std::endl;
        return false;
    }

    std::cout<<"decryptAES Recovered length: "<<recovered.length()<<", text: "<<recovered<<std::endl;

    // Handle the padding because CryptoPP kept complaining that the padding flags can't be used with AES CTR
    const size_t unpadded_length = PKCS7::GetUnpaddedLength((const uint8_t*)recovered.data(), _cypher.size());

    for (size_t i = 0; i < unpadded_length; i++) {
        out_decrypted.push_back(recovered[i]);
    }

    std::cout<<"decryptAES Decoded length: "<<out_decrypted.size()<<", text: "<<(const char*)(out_decrypted.data())<<std::endl;
    return true;
}



ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, const std::array<uint8_t, 32>& salt, std::optional<std::string_view> vault_id_utf8, std::ostringstream& output_utf8)
{
    output_utf8.clear();

    if (is_encrypted(plain_text_utf8)) {
        return ENCRYPT_RESULT::ERROR_ALREADY_ENCRYPTED;
    }

    // Encrypt the content
    EncryptionKeychain keys(salt, password_utf8);
    keys.createKeys();

    const std::array<uint8_t, KEYLEN> cypherKey = keys.getEncryptionKey();
    std::ostringstream o1;
    BytesToHexString(cypherKey, 100, o1);
    std::cout<<"Key 1: "<<cypherKey.size()<<", "<<o1.str()<<std::endl;
    const std::array<uint8_t, KEYLEN> hmacKey = keys.getHMACKey();
    std::ostringstream o2;
    BytesToHexString(hmacKey, 100, o2);
    std::cout<<"Key 2: "<<hmacKey.size()<<", "<<o2.str()<<std::endl;
    const std::array<uint8_t, IVLEN> iv = keys.getIV();
    std::ostringstream o3;
    BytesToHexString(iv, 100, o3);
    std::cout<<"IV: "<<iv.size()<<", "<<o3.str()<<std::endl;

    std::cout<<"Original plain_text_utf8 length: "<<plain_text_utf8.length()<<std::endl;
    const std::vector<uint8_t> data_padded = PKCS7::pad(plain_text_utf8);
    std::cout<<"Padded data length: "<<data_padded.size()<<std::endl;

    std::vector<uint8_t> encrypted;
    if (!encryptAES(data_padded, keys.getEncryptionKey(), keys.getIV(), encrypted)) {
      std::cerr<<"encrypt Error encrypting with AES"<<std::endl;
      return ENCRYPT_RESULT::ERROR_AES_ENCRYPTION_FAILED;
    }

    std::array<uint8_t, 32> hmacHash;
    if (!calculateHMAC(keys.getHMACKey(), encrypted, hmacHash)) {
        std::cerr<<"encrypt Error calculating HMAC"<<std::endl;
        return ENCRYPT_RESULT::ERROR_CALCULATING_HMAC;
    }

    std::cout<<"Original plain text length: "<<plain_text_utf8.length()<<", padded length: "<<data_padded.size()<<std::endl;
    std::cout<<"Creating content salt len: "<<salt.size()<<", hmacHash len: "<<hmacHash.size()<<", encrypted len: "<<encrypted.size()<<std::endl;

    std::ostringstream content_hex;
    BytesToHexString(salt, 10000, content_hex);
    content_hex<<'\n';
    BytesToHexString(hmacHash, 10000, content_hex);
    content_hex<<'\n';
    BytesToHexString(encrypted, 10000, content_hex);
  

    // Write the header
    output_utf8<<VAULT_MAGIC<<";"<<VAULT_VERSION<<";"<<VAULT_CIPHER_AES256<<"\n";

    std::ostringstream content_double_hex;
    EncodeStringToHexString(content_hex.str(), content_double_hex);

    // Write the content
    output_to_string_wrap_80_characters(content_double_hex.str(), output_utf8);

    return ENCRYPT_RESULT::OK;
}

ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, const std::array<uint8_t, 32>& salt, std::ostringstream& output_utf8)
{
  return encrypt(plain_text_utf8, password_utf8, salt, std::nullopt, output_utf8);
}

ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::ostringstream& output_utf8)
{
  const std::array<uint8_t, 32> salt = EncryptionKeychain::generateSalt(SALT_LENGTH);
  return encrypt(plain_text_utf8, password_utf8, salt, std::nullopt, output_utf8);
}

DECRYPT_RESULT decrypt(std::string_view encrypted_utf8, std::string_view password_utf8, std::ostringstream& output_utf8)
{
    output_utf8.clear();

    VaultInfo vault_info;
    DECRYPT_RESULT result = ParseVaultInfoString(encrypted_utf8, vault_info);
    if (result != DECRYPT_RESULT::OK) {
        return result;
    }

    VaultContent vault_content;
    result = ParseVaultContent(encrypted_utf8, vault_content);
    if (result != DECRYPT_RESULT::OK) {
        return result;
    }

    std::cout<<"decrypt vault_content.data length: "<<vault_content.data.size()<<std::endl;

    std::ostringstream o1;
    BytesToHexString(vault_content.salt, 100, o1);
    std::cout<<"salt "<<o1.str()<<std::endl;
    std::ostringstream o2;
    BytesToHexString(vault_content.hmac, 100, o2);
    std::cout<<"hmac: "<<o2.str()<<std::endl;
    std::ostringstream o3;
    BytesToHexString(vault_content.data, 100, o3);
    std::cout<<"data: "<<o3.str()<<std::endl;


    EncryptionKeychain keys(vault_content.salt, password_utf8);
    keys.createKeys();

    // key1
    const std::array<uint8_t, KEYLEN> cypherKey = keys.getEncryptionKey();
    std::ostringstream o4;
    BytesToHexString(cypherKey, 100, o4);
    std::cout<<"Key 1 length: "<<cypherKey.size()<<", value: "<<o4.str()<<std::endl;

    // key2
    const std::array<uint8_t, KEYLEN> hmacKey = keys.getHMACKey();
    std::ostringstream o5;
    BytesToHexString(hmacKey, 100, o5);
    std::cout<<"Key 2 length: "<<hmacKey.size()<<", value: "<<o5.str()<<std::endl;

    // iv
    const std::array<uint8_t, IVLEN> iv = keys.getIV();
    std::ostringstream o6;
    BytesToHexString(iv, 100, o6);
    std::cout<<"IV length: "<<iv.size()<<", value: "<<o6.str()<<std::endl;

    const std::vector<uint8_t>& cypher = vault_content.data;
    std::cout<<"decrypt cyper.size: "<<cypher.size()<<std::endl;

    // expected, key, data
    std::array<uint8_t, 32> expected_hmac_trimmed;
    std::copy_n(vault_content.hmac.begin(), 32, expected_hmac_trimmed.begin());
    if (!verifyHMAC(expected_hmac_trimmed, hmacKey, cypher)) {
        std::cerr<<"Error verifying hmac"<<std::endl;
        return DECRYPT_RESULT::ERROR_VERIFYING_HMAC;
    }

    std::cout<<"Signature matches - decrypting"<<std::endl;
    std::vector<uint8_t> decrypted;
    if (!decryptAES(cypher, cypherKey, iv, decrypted)) {
        std::cerr<<"Error decrypting"<<std::endl;
        return DECRYPT_RESULT::ERROR_DECRYPTING_CONTENT;
    }

    output_utf8<<std::string((const char*)decrypted.data(), decrypted.size());
    std::cout<<"Decoded: \""<<output_utf8.str()<<"\""<<std::endl;

    return DECRYPT_RESULT::OK;
}

}

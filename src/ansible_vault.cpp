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


// In the cryptopp headers:
// typedef unsigned char byte;


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

namespace {

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

// C++98 guarantees that '0', '1', ... '9' are consecutive.
// It only guarantees that 'a' ... 'f' and 'A' ... 'F' are
// in increasing order, but the only two alternative encodings
// of the basic source character set that are still used by
// anyone today (ASCII and EBCDIC) make them consecutive.
inline uint8_t hexval(uint8_t c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 10;

    // Assume 'A'..'F'
    return c - 'A' + 10;
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

const std::string CHAR_ENCODING = "UTF-8";

class EncryptionKeychain {
public:
    std::vector<uint8_t> salt;
    std::string_view password_utf8;

    EncryptionKeychain(const std::vector<uint8_t>& _salt, std::string_view _password_utf8 /*, int keylen, int ivlen, int iterations*/)
    {
        salt = _salt;
        password_utf8 = _password_utf8;
    }

    void createKeys()
    {
        // Returns a byte array:
        // [0..keylen-1]: encryption key
        // [keylen..(keylen * 2) - 1]: hmac key
        // [(keylen * 2) - 1..(keylen * 2) + ivlen) - 1]: ivlen
        const std::vector<uint8_t> rawkeys = createRawKey();

        encryptionKey = getEncryptionKey(rawkeys);
        hmacKey = getHMACKey(rawkeys);
        iv = getIV(rawkeys);
    }

    const std::vector<uint8_t>& getEncryptionKey() const
    {
        return encryptionKey;
    }

    const std::vector<uint8_t>& getHMACKey() const
    {
        return hmacKey;
    }

    const std::vector<uint8_t>& getIV() const
    {
        return iv;
    }

private:
    std::vector<uint8_t> createRawKey() const
    {
        /*PBKDF2Parameters params = new PBKDF2Parameters(algo, CHAR_ENCODING, salt, iterations);
        int keylength = ivlen + 2 * keylen;
        PBKDF2Engine pbkdf2Engine = new PBKDF2Engine(params);
        std::vector<uint8_t> keys = pbkdf2Engine.deriveKey(password, keylength);
        return keys;*/


    /*def _gen_key_initctr(cls, b_password, b_salt):
        # 16 for AES 128, 32 for AES256
        keylength = 32

        # match the size used for counter.new to avoid extra work
        ivlength = 16

        if HAS_PBKDF2HMAC:
            kdf = PBKDF2HMAC(
                algorithm=c_SHA256(),
                length=2 * keylength + ivlength,
                salt=b_salt,
                iterations=10000)
            b_derivedkey = kdf.derive(b_password)
        else:
            b_derivedkey = cls._create_key(b_password, b_salt, keylength, ivlength)

        b_key1 = b_derivedkey[:keylength]
        b_key2 = b_derivedkey[keylength:(keylength * 2)]
        b_iv = b_derivedkey[(keylength * 2):(keylength * 2) + ivlength]

        return b_key1, b_key2, hexlify(b_iv)*/


        // https://cryptopp.com/wiki/PKCS5_PBKDF2_HMAC

        //CryptoPP::byte derived[CryptoPP::SHA256::DIGESTSIZE]; // 32 bytes, 256 bits
        const size_t derivedLength = IVLEN + (2 * KEYLEN);
        CryptoPP::byte derived[derivedLength];

        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
        CryptoPP::byte unused = 0;
        pbkdf.DeriveKey(derived, sizeof(derived), unused, (const CryptoPP::byte*)password_utf8.data(), password_utf8.length(), (const CryptoPP::byte*)salt.data(), salt.size(), ITERATIONS);

        std::cout << "Derived: " << BytesToHexString(derived, sizeof(derived)) << std::endl;

        std::vector<uint8_t> derived_vector;
        for (auto& b : derived) {
            derived_vector.push_back(b);
        }

        return derived_vector;
    }
/*

def _create_key_cryptography(b_password, b_salt, key_length, iv_length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=2 * key_length + iv_length,
        salt=b_salt,
        iterations=10000,
        backend=CRYPTOGRAPHY_BACKEND)
    b_derivedkey = kdf.derive(b_password)

    return b_derivedkey





        try {
            PBKDF2Parameters params = new PBKDF2Parameters(algo, CHAR_ENCODING, salt, iterations);
            int keylength = ivlen + 2 * keylen;
            PBKDF2Engine pbkdf2Engine = new PBKDF2Engine(params);
            std::vector<uint8_t> keys = pbkdf2Engine.deriveKey(password, keylength);
            return keys;
        } catch (Exception ex) {
            throw new IOException("Cryptofailure: " + ex.getMessage());
        }
    }
*/

    static std::vector<uint8_t> getEncryptionKey(const std::vector<uint8_t>& keys)
    {
        std::vector<uint8_t> result(keys.begin(), keys.begin() + KEYLEN);
        return result;
    }

    static std::vector<uint8_t> getHMACKey(const std::vector<uint8_t>& keys)
    {
        std::vector<uint8_t> result(keys.begin() + KEYLEN, keys.begin() + (KEYLEN * 2));
        return result;
    }

    static std::vector<uint8_t> getIV(const std::vector<uint8_t>& keys)
    {
        std::vector<uint8_t> result(keys.begin() + (KEYLEN * 2), keys.begin() + (KEYLEN * 2) + IVLEN);
        return result;
    }

    static std::vector<uint8_t> generateSalt(size_t length)
    {
        std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t> rbe;
        std::vector<uint8_t> salt(length);
        std::generate(begin(salt), end(salt), std::ref(rbe));

        return salt;
    }

    std::vector<uint8_t> encryptionKey;
    std::vector<uint8_t> hmacKey;
    std::vector<uint8_t> iv;
};

}

#if 0

public class CypherAES256 implements CypherInterface
{
    Logger logger = LoggerFactory.getLogger(CypherAES256.class);

    public final static String CYPHER_ID = "AES256";
    //public final static int AES_KEYLEN = 256;
    public final static String CHAR_ENCODING = "UTF-8";
    public final static String KEYGEN_ALGO = "HmacSHA256";
    public final static String CYPHER_KEY_ALGO = "AES";
    public static final String CYPHER_ALGO = "AES/CTR/NoPadding";

    public byte[] calculateHMAC(byte[] key, byte[] data) throws IOException
    {
        byte[] computedMac = null;

        try
        {
            SecretKeySpec hmacKey = new SecretKeySpec(key, KEYGEN_ALGO);
            Mac mac = Mac.getInstance(KEYGEN_ALGO);
            mac.init(hmacKey);
            computedMac = mac.doFinal(data);
        }
        catch (Exception ex)
        {
            throw new IOException("Error decrypting HMAC hash: " + ex.getMessage());
        }

        return computedMac;
    }

    public boolean verifyHMAC(byte[] hmac, byte[] key, byte[] data) throws IOException
    {
        boolean matches = false;
        byte[] calculated = calculateHMAC(key, data);
        return Arrays.equals(hmac, calculated);
    }

    public int paddingLength(byte[] decrypted)
    {
        if (decrypted.length == 0)
        {
            logger.debug("Empty decoded text has no padding.");
            return 0;
        }

        logger.debug("Padding length: {}", decrypted[decrypted.length - 1]);
        return decrypted[decrypted.length - 1];
    }

    public byte[] unpad(byte[] decrypted)
    {
        int length = decrypted.length - paddingLength(decrypted);
        return Arrays.copyOfRange(decrypted, 0, length);
    }

    public byte[] pad(byte[] cleartext) throws IOException
    {
        byte[] padded = null;

        try
        {
            int blockSize = Cipher.getInstance(CYPHER_ALGO).getBlockSize();
            logger.debug("Padding to block size: {}", blockSize);
            int padding_length = (blockSize - (cleartext.length % blockSize));
            if (padding_length == 0)
            {
                padding_length = blockSize;
            }
            padded = Arrays.copyOf(cleartext, cleartext.length + padding_length);
            padded[padded.length - 1] = (byte) padding_length;

        }
        catch (Exception ex)
        {
            new IOException("Error calculating padding for " + CYPHER_ALGO + ": " + ex.getMessage());
        }

        return padded;
    }

    public byte[] decryptAES(byte[] cypher, byte[] key, byte[] iv) throws IOException
    {

        SecretKeySpec keySpec = new SecretKeySpec(key, CYPHER_KEY_ALGO);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try
        {
            Cipher cipher = Cipher.getInstance(CYPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(cypher);
            return unpad(decrypted);
        }
        catch (Exception ex)
        {
            throw new IOException("Failed to decrypt data: " + ex.getMessage());
        }
    }

    public byte[] encryptAES(byte[] cleartext, byte[] key, byte[] iv) throws IOException
    {
        SecretKeySpec keySpec = new SecretKeySpec(key, CYPHER_KEY_ALGO);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try
        {
            Cipher cipher = Cipher.getInstance(CYPHER_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(cleartext);
            return encrypted;
        }
        catch (Exception ex)
        {
            throw new IOException("Failed to encrypt data: " + ex.getMessage());
        }
    }

    public byte[] decrypt(byte[] encryptedData, String password) throws IOException
    {
        byte[] decrypted = null;

        VaultContent vaultContent = new VaultContent(encryptedData);

        byte[] salt = vaultContent.getSalt();
        byte[] hmac = vaultContent.getHmac();
        byte[] cypher = vaultContent.getData();
        logger.debug("Salt: {} - {}", salt.length, Util.hexit(salt, 100));
        logger.debug("HMAC: {} - {}", hmac.length, Util.hexit(hmac, 100));
        logger.debug("Data: {} - {}", cypher.length, Util.hexit(cypher, 100));

        EncryptionKeychain keys = new EncryptionKeychain(salt, password);
        keys.createKeys();

        byte[] cypherKey = keys.getEncryptionKey();
        logger.debug("Key 1: {} - {}", cypherKey.length, Util.hexit(cypherKey, 100));
        byte[] hmacKey = keys.getHmacKey();
        logger.debug("Key 2: {} - {}", hmacKey.length, Util.hexit(hmacKey, 100));
        byte[] iv = keys.getIv();
        logger.debug("IV: {} - {}", iv.length, Util.hexit(iv, 100));

        if (verifyHMAC(hmac, hmacKey, cypher))
        {
            logger.debug("Signature matches - decrypting");
            decrypted = decryptAES(cypher, cypherKey, iv);
            logger.debug("Decoded:\n{}", new String(decrypted, CHAR_ENCODING));
        }
        else
        {
            throw new IOException("HMAC Digest doesn't match - possibly it's the wrong password.");
        }

        return decrypted;
    }

    public String infoLine()
    {
        return VaultInfo.vaultInfoForCypher(CYPHER_ID);
    }
}







public class Util
{

    private static final int DEFAULT_LINE_LENGTH = 80;

    private static Logger logger = LoggerFactory.getLogger(Util.class);

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    final protected static String LINE_BREAK = "\n";
    final protected static String CHAR_ENCODING = "UTF-8";

    public static String join(String [] datalines)
    {
        return String.join("", Arrays.asList(datalines));
    }

    public static byte[] unhex(String hexed)
    {
        int dataLen = hexed.length();
        byte[] output = new byte[dataLen/2];
        for (int charIdx = 0; charIdx < dataLen; charIdx+=2) {
            output[charIdx/2] = (byte) ((Character.digit(hexed.charAt(charIdx), 16) << 4)
                    + Character.digit(hexed.charAt(charIdx+1), 16));
        }
        return output;
    }

    public static String hexit(byte [] unhexed)
    {
        return hexit(unhexed, DEFAULT_LINE_LENGTH);
    }

    public static String hexit(byte [] unhexed, int lineLength)
    {
        String result = "";
        int colIdx = 0;
        for (byte val: unhexed)
        {
            result += String.format("%02x", val);
            colIdx++;
            if (lineLength > 0 && colIdx>=lineLength/2) {
                result += LINE_BREAK;
                colIdx=0;
            }
        }

        return result;
    }

    public static VaultInfo getVaultInfo(String vaultData)
    {
        String infoString =  vaultData.substring(0, vaultData.indexOf(LINE_BREAK));
        return new VaultInfo(infoString);
    }

    public static VaultInfo getVaultInfo(byte [] vaultData)
    {
        return getVaultInfo(new String(vaultData));
    }

    public static String cleanupData(String vaultData)
    {
        return vaultData.substring(vaultData.indexOf(LINE_BREAK) + 1);
    }

    public static byte[] getVaultData(String vaultData)
    {
        String rawData = join(cleanupData(vaultData).split(LINE_BREAK));
        return unhex(rawData);
    }

    public static byte[] getVaultData(byte [] vaultData)
    {
        String rawData = join(cleanupData(new String(vaultData)).split(LINE_BREAK));
        return unhex(rawData);
    }

}



public class VaultInfo
{
    Logger logger = LoggerFactory.getLogger(VaultInfo.class);

    public final static String INFO_SEPARATOR = ";";
    public final static int INFO_ELEMENTS = 3;
    public final static int MAGIC_PART = 0;
    public final static int VERSION_PART = 1;
    public final static int CYPHER_PART = 2;

    public final static String VAULT_MAGIC="$ANSIBLE_VAULT";
    public final static String VAULT_VERSION="1.1";

    private boolean validVault;
    private String vaultVersion;
    private String vaultCypher;

    public static String vaultInfoForCypher(String vaultCypher)
    {
        String infoLine = VAULT_MAGIC+";"+VAULT_VERSION+";"+vaultCypher;
        return infoLine;
    }

    public VaultInfo(String infoLine)
    {
        logger.debug("Ansible Vault info: {}", infoLine);

        String [] infoParts = infoLine.split(INFO_SEPARATOR);
        if (infoParts.length == INFO_ELEMENTS)
        {
            if ( infoParts[MAGIC_PART].equals(VAULT_MAGIC) ) {
                validVault = true;
                vaultVersion = infoParts[VERSION_PART];
                vaultCypher = infoParts[CYPHER_PART];
            }
        }
    }

    public boolean isEncryptedVault()
    {
        return validVault;
    }

    public CypherInterface getCypher()
    {
        return CypherFactory.getCypher(vaultCypher);
    }

    public String getVaultVersion()
    {
        return vaultVersion;
    }

    public boolean isValidVault()
    {
        return isEncryptedVault() && getCypher() != null;
    }

}






public class VaultHandler
{

    public final static String DEFAULT_CYPHER = CypherAES256.CYPHER_ID;

    public final static String CHAR_ENCODING = "UTF-8";


    public static byte [] encrypt(byte [] cleartext, String password, String cypher) throws IOException
    {
        CypherInterface cypherInstance = CypherFactory.getCypher(cypher);
        byte [] vaultData = cypherInstance.encrypt(cleartext, password);
        String vaultDataString = new String(vaultData);
        String vaultPackage = cypherInstance.infoLine() + "\n" + vaultDataString;
        return vaultPackage.getBytes();
    }

    public static byte [] encrypt(byte [] cleartext, String password) throws IOException
    {
        return encrypt(cleartext, password, DEFAULT_CYPHER);
    }

    public static void encrypt(InputStream clearText, OutputStream cipherText, String password, String cypher) throws IOException
    {
        String clearTextValue = IOUtils.toString(clearText, CHAR_ENCODING);
        cipherText.write(encrypt(clearTextValue.getBytes(), password, cypher));
    }

    public static void encrypt(InputStream clearText, OutputStream cipherText, String password) throws IOException
    {
        encrypt(clearText, cipherText, password, DEFAULT_CYPHER);
    }

    public static void decrypt(InputStream encryptedVault, OutputStream decryptedVault, String password) throws IOException
    {
        String encryptedValue = IOUtils.toString(encryptedVault, CHAR_ENCODING);
        decryptedVault.write(decrypt(encryptedValue.getBytes(), password));
    }

    public static byte[] decrypt(byte[] encrypted, String password) throws IOException
    {

        VaultInfo vaultInfo = Util.getVaultInfo(encrypted);
        if ( !vaultInfo.isEncryptedVault() ) {
            throw new IOException("File is not an Ansible Encrypted Vault");
        }

        if ( !vaultInfo.isValidVault() )
        {
            throw new IOException("The vault is not a format we can handle - check the cypher.");
        }

        byte [] encryptedData = Util.getVaultData(encrypted);

        return vaultInfo.getCypher().decrypt(encryptedData, password);
    }

}











public class Manager
{
    Logger logger = LoggerFactory.getLogger(Manager.class);

    public Manager()
    {

    }

    public Object getFromYaml(Class objectClass, String yaml) throws YamlException
    {
        YamlReader reader = new YamlReader(new StringReader(yaml));
        return reader.read(objectClass);
    }

    public String writeToYaml(Object object) throws YamlException
    {
        StringWriter resultWriter = new StringWriter();
        YamlWriter writer = new YamlWriter(resultWriter);
        writer.write(object);
        writer.close();
        return resultWriter.getBuffer().toString();
    }

    public Object getFromVault(Class objectClass, String yaml, String password) throws IOException
    {
        byte [] clearYaml = VaultHandler.decrypt(yaml.getBytes(), password);
        return getFromYaml(objectClass, new String(clearYaml));
    }

    public String writeToVault(Object object, String password) throws IOException
    {
        String clearYaml = writeToYaml(object);
        byte [] yamlVault = VaultHandler.encrypt(clearYaml.getBytes(), password);
        return new String(yamlVault);
    }

}

#endif






#if 0

def _unhexlify(b_data):
    try:
        return unhexlify(b_data)
    except (BinasciiError, TypeError) as exc:
        raise AnsibleVaultFormatError('Vault format unhexlify error: %s' % exc)


def _parse_vaulttext(b_vaulttext):
    b_vaulttext = _unhexlify(b_vaulttext)
    b_salt, b_crypted_hmac, b_ciphertext = b_vaulttext.split(b"\n", 2)
    b_salt = _unhexlify(b_salt)
    b_ciphertext = _unhexlify(b_ciphertext)

    return b_ciphertext, b_salt, b_crypted_hmac


def parse_vaulttext(b_vaulttext):
//Parse the vaulttext
//
//:arg b_vaulttext: byte str containing the vaulttext (ciphertext, salt, crypted_hmac)
//:returns: A tuple of byte str of the ciphertext suitable for passing to a
//    Cipher class's decrypt() function, a byte str of the salt,
//    and a byte str of the crypted_hmac
//:raises: AnsibleVaultFormatError: if the vaulttext format is invalid
# SPLIT SALT, DIGEST, AND DATA
try:
    return _parse_vaulttext(b_vaulttext)
except AnsibleVaultFormatError:
    raise
except Exception as exc:
    msg = "Vault vaulttext format error: %s" % exc
    raise AnsibleVaultFormatError(msg)



def _create_key_cryptography(b_password, b_salt, key_length, iv_length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=2 * key_length + iv_length,
        salt=b_salt,
        iterations=10000,
        backend=CRYPTOGRAPHY_BACKEND)
    b_derivedkey = kdf.derive(b_password)

    return b_derivedkey

@classmethod
def _gen_key_initctr(cls, b_password, b_salt):
    # 16 for AES 128, 32 for AES256
    key_length = 32

    if HAS_CRYPTOGRAPHY:
        # AES is a 128-bit block cipher, so IVs and counter nonces are 16 bytes
        iv_length = algorithms.AES.block_size // 8

        b_derivedkey = cls._create_key_cryptography(b_password, b_salt, key_length, iv_length)
        b_iv = b_derivedkey[(key_length * 2):(key_length * 2) + iv_length]
    else:
        raise AnsibleError(NEED_CRYPTO_LIBRARY + '(Detected in initctr)')

    b_key1 = b_derivedkey[:key_length]
    b_key2 = b_derivedkey[key_length:(key_length * 2)]

    return b_key1, b_key2, b_iv

@staticmethod
def _encrypt_cryptography(b_plaintext, b_key1, b_key2, b_iv):
    cipher = C_Cipher(algorithms.AES(b_key1), modes.CTR(b_iv), CRYPTOGRAPHY_BACKEND)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    b_ciphertext = encryptor.update(padder.update(b_plaintext) + padder.finalize())
    b_ciphertext += encryptor.finalize()

    # COMBINE SALT, DIGEST AND DATA
    hmac = HMAC(b_key2, hashes.SHA256(), CRYPTOGRAPHY_BACKEND)
    hmac.update(b_ciphertext)
    b_hmac = hmac.finalize()

    return to_bytes(hexlify(b_hmac), errors='surrogate_or_strict'), hexlify(b_ciphertext)

@classmethod
def encrypt(cls, b_plaintext, secret, salt=None):

    if secret is None:
        raise AnsibleVaultError('The secret passed to encrypt() was None')

    if salt is None:
        b_salt = os.urandom(32)
    elif not salt:
        raise AnsibleVaultError('Empty or invalid salt passed to encrypt()')
    else:
        b_salt = to_bytes(salt)

    b_password = secret.bytes
    b_key1, b_key2, b_iv = cls._gen_key_initctr(b_password, b_salt)

    if HAS_CRYPTOGRAPHY:
        b_hmac, b_ciphertext = cls._encrypt_cryptography(b_plaintext, b_key1, b_key2, b_iv)
    else:
        raise AnsibleError(NEED_CRYPTO_LIBRARY + '(Detected in encrypt)')

    b_vaulttext = b'\n'.join([hexlify(b_salt), b_hmac, b_ciphertext])
    # Unnecessary but getting rid of it is a backwards incompatible vault
    # format change
    b_vaulttext = hexlify(b_vaulttext)
    return b_vaulttext

@classmethod
def _decrypt_cryptography(cls, b_ciphertext, b_crypted_hmac, b_key1, b_key2, b_iv):
    // b_key1, b_key2, b_iv = self._gen_key_initctr(b_password, b_salt)
    // EXIT EARLY IF DIGEST DOESN'T MATCH
    hmac = HMAC(b_key2, hashes.SHA256(), CRYPTOGRAPHY_BACKEND)
    hmac.update(b_ciphertext)
    try:
        hmac.verify(_unhexlify(b_crypted_hmac))
    except InvalidSignature as e:
        raise AnsibleVaultError('HMAC verification failed: %s' % e)

    cipher = C_Cipher(algorithms.AES(b_key1), modes.CTR(b_iv), CRYPTOGRAPHY_BACKEND)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    b_plaintext = unpadder.update(
        decryptor.update(b_ciphertext) + decryptor.finalize()
    ) + unpadder.finalize()

    return b_plaintext

@staticmethod
def _is_equal(b_a, b_b):
    // Comparing 2 byte arrays in constant time to avoid timing attacks.
    //
    // It would be nice if there were a library for this but hey.
    // if not (isinstance(b_a, binary_type) and isinstance(b_b, binary_type)):
    //    raise TypeError('_is_equal can only be used to compare two byte strings')

    # http://codahale.com/a-lesson-in-timing-attacks/
    if len(b_a) != len(b_b):
        return False

    result = 0
    for b_x, b_y in zip(b_a, b_b):
        result |= b_x ^ b_y
    return result == 0

@classmethod
def decrypt(cls, b_vaulttext, secret):

    b_ciphertext, b_salt, b_crypted_hmac = parse_vaulttext(b_vaulttext)

    # TODO: would be nice if a VaultSecret could be passed directly to _decrypt_*
    #       (move _gen_key_initctr() to a AES256 VaultSecret or VaultContext impl?)
    # though, likely needs to be python cryptography specific impl that basically
    # creates a Cipher() with b_key1, a Mode.CTR() with b_iv, and a HMAC() with sign key b_key2
    b_password = secret.bytes

    b_key1, b_key2, b_iv = cls._gen_key_initctr(b_password, b_salt)

    if HAS_CRYPTOGRAPHY:
        b_plaintext = cls._decrypt_cryptography(b_ciphertext, b_crypted_hmac, b_key1, b_key2, b_iv)
    else:
        raise AnsibleError(NEED_CRYPTO_LIBRARY + '(Detected in decrypt)')

    return b_plaintext

#endif

namespace {

// Vault implementation using AES-CTR with an HMAC-SHA256 authentication code.
// Keys are derived using PBKDF2
// http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
class VaultAES256 {
public:

};


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

const std::string VAULT_MAGIC = "$ANSIBLE_VAULT";
const std::string VAULT_VERSION = "1.1";
const std::string VAULT_CIPHER_AES256 = "AES256";

bool is_encrypted(const std::string_view& content)
{
  return content.starts_with(VAULT_MAGIC);
}

ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, ENCRYPTION_METHOD encryption_method, std::string_view password_utf8, std::optional<std::string_view> salt_utf8, std::optional<std::string_view> vault_id_utf8, std::ostringstream& output_utf8)
{
    output_utf8.clear();

    if (is_encrypted(plain_text_utf8)) {
        return ENCRYPT_RESULT::ERROR_ALREADY_ENCRYPTED;
    }

    // Encrypt the content
    SHA256 sha256;
    const std::string encrypted = sha256.encrypt(plain_text_utf8, password_utf8, salt_utf8);

    #if 0
    std::string tempSalt;
    if (!salt_utf8.has_value()) {
        tempSalt = generateSalt(SALT_LENGTH);
        salt_utf8 = tempSalt;
    }
    EncryptionKeychain keys = new EncryptionKeychain(salt_utf8, password_utf8);
    keys.createKeys();
    byte[] cypherKey = keys.getEncryptionKey();
    logger.debug("Key 1: {} - {}", cypherKey.length, Util.hexit(cypherKey, 100));
    byte[] hmacKey = keys.getHmacKey();
    logger.debug("Key 2: {} - {}", hmacKey.length, Util.hexit(hmacKey, 100));
    byte[] iv = keys.getIv();
    logger.debug("IV: {} - {}", iv.length, Util.hexit(iv, 100));
    logger.debug("Original data length: {}", data.length);
    data = pad(data);
    logger.debug("Padded data length: {}", data.length);
    const std::string encrypted = encryptAES(data, keys.getEncryptionKey(), keys.getIv());
    byte[] hmacHash = calculateHMAC(keys.getHmacKey(), encrypted);
    VaultContent vaultContent = new VaultContent(keys.getSalt(), hmacHash, encrypted);
    return vaultContent.toByteArray();
    }
    #endif


    // Write the header
    output_utf8<<VAULT_MAGIC<<";"<<VAULT_VERSION<<";"<<VAULT_CIPHER_AES256<<"\n";

    // Write the encrypted data
    output_to_string_wrap_80_characters(encrypted, output_utf8);

    return ENCRYPT_RESULT::OK;
}

ENCRYPT_RESULT encrypt(std::string_view plain_text_utf8, std::string_view password_utf8, std::ostringstream& output_utf8)
{
    return encrypt(plain_text_utf8, ENCRYPTION_METHOD::AES256, password_utf8, std::nullopt, std::nullopt, output_utf8);
}

#if 0
/*
def format_vaulttext_envelope(b_ciphertext, cipher_name, version=None, vault_id=None):
    """ Add header and format to 80 columns

        :arg b_ciphertext: the encrypted and hexlified data as a byte string
        :arg cipher_name: unicode cipher name (for ex, u'AES256')
        :arg version: unicode vault version (for ex, '1.2'). Optional ('1.1' is default)
        :arg vault_id: unicode vault identifier. If provided, the version will be bumped to 1.2.
        :returns: a byte str that should be dumped into a file.  It's
            formatted to 80 char columns and has the header prepended
    """

    if not cipher_name:
        raise AnsibleError("the cipher must be set before adding a header")

    version = version or '1.1'

    # If we specify a vault_id, use format version 1.2. For no vault_id, stick to 1.1
    if vault_id and vault_id != u'default':
        version = '1.2'

    b_version = to_bytes(version, 'utf-8', errors='strict')
    b_vault_id = to_bytes(vault_id, 'utf-8', errors='strict')
    b_cipher_name = to_bytes(cipher_name, 'utf-8', errors='strict')

    header_parts = [b_HEADER,
                    b_version,
                    b_cipher_name]

    if b_version == b'1.2' and b_vault_id:
        header_parts.append(b_vault_id)

    header = b';'.join(header_parts)

    b_vaulttext = [header]
    b_vaulttext += [b_ciphertext[i:i + 80] for i in range(0, len(b_ciphertext), 80)]
    b_vaulttext += [b'']
    b_vaulttext = b'\n'.join(b_vaulttext)

    return b_vaulttext



def _parse_vaulttext_envelope(b_vaulttext_envelope, default_vault_id=None):

    b_tmpdata = b_vaulttext_envelope.splitlines()
    b_tmpheader = b_tmpdata[0].strip().split(b';')

    b_version = b_tmpheader[1].strip()
    cipher_name = to_text(b_tmpheader[2].strip())
    vault_id = default_vault_id

    # Only attempt to find vault_id if the vault file is version 1.2 or newer
    # if self.b_version == b'1.2':
    if len(b_tmpheader) >= 4:
        vault_id = to_text(b_tmpheader[3].strip())

    b_ciphertext = b''.join(b_tmpdata[1:])

    return b_ciphertext, b_version, cipher_name, vault_id


def parse_vaulttext_envelope(b_vaulttext_envelope, default_vault_id=None, filename=None):

    """Parse the vaulttext envelope

    When data is saved, it has a header prepended and is formatted into 80
    character lines.  This method extracts the information from the header
    and then removes the header and the inserted newlines.  The string returned
    is suitable for processing by the Cipher classes.

    :arg b_vaulttext: byte str containing the data from a save file
    :kwarg default_vault_id: The vault_id name to use if the vaulttext does not provide one.
    :kwarg filename: The filename that the data came from.  This is only
        used to make better error messages in case the data cannot be
        decrypted. This is optional.
    :returns: A tuple of byte str of the vaulttext suitable to pass to parse_vaultext,
        a byte str of the vault format version,
        the name of the cipher used, and the vault_id.
    :raises: AnsibleVaultFormatError: if the vaulttext_envelope format is invalid
    """
    # used by decrypt
    default_vault_id = default_vault_id or C.DEFAULT_VAULT_IDENTITY

    try:
        return _parse_vaulttext_envelope(b_vaulttext_envelope, default_vault_id)
    except Exception as exc:
        msg = "Vault envelope format error"
        if filename:
            msg += ' in %s' % (filename)
        msg += ': %s' % exc
        raise AnsibleVaultFormatError(msg)







    def test_format_vaulttext_envelope(self):
        cipher_name = "TEST"
        b_ciphertext = b"ansible"
        b_vaulttext = vault.format_vaulttext_envelope(b_ciphertext,
                                                      cipher_name,
                                                      version=self.v.b_version,
                                                      vault_id='default')
        b_lines = b_vaulttext.split(b'\n');
        self.assertGreater(len(b_lines), 1, msg="failed to properly add header")

        b_header = b_lines[0]
        # self.assertTrue(b_header.endswith(b';TEST'), msg="header does not end with cipher name")

        b_header_parts = b_header.split(b';')
        self.assertEqual(len(b_header_parts), 4, msg="header has the wrong number of parts")
        self.assertEqual(b_header_parts[0], b'$ANSIBLE_VAULT', msg="header does not start with $ANSIBLE_VAULT")
        self.assertEqual(b_header_parts[1], self.v.b_version, msg="header version is incorrect")
        self.assertEqual(b_header_parts[2], b'TEST', msg="header does not end with cipher name")

        # And just to verify, lets parse the results and compare
        b_ciphertext2, b_version2, cipher_name2, vault_id2 = \
            vault.parse_vaulttext_envelope(b_vaulttext)
        self.assertEqual(b_ciphertext, b_ciphertext2)
        self.assertEqual(self.v.b_version, b_version2)
        self.assertEqual(cipher_name, cipher_name2)
        self.assertEqual('default', vault_id2)

    def test_parse_vaulttext_envelope(self):
        b_vaulttext = b"$ANSIBLE_VAULT;9.9;TEST\nansible"
        b_ciphertext, b_version, cipher_name, vault_id = vault.parse_vaulttext_envelope(b_vaulttext)
        b_lines = b_ciphertext.split(b'\n')
        self.assertEqual(b_lines[0], b"ansible", msg="Payload was not properly split from the header")
        self.assertEqual(cipher_name, u'TEST', msg="cipher name was not properly set")
        self.assertEqual(b_version, b"9.9", msg="version was not properly set")

    def test_parse_vaulttext_envelope_crlf(self):
        b_vaulttext = b"$ANSIBLE_VAULT;9.9;TEST\r\nansible"
        b_ciphertext, b_version, cipher_name, vault_id = vault.parse_vaulttext_envelope(b_vaulttext)
        b_lines = b_ciphertext.split(b'\n')
        self.assertEqual(b_lines[0], b"ansible", msg="Payload was not properly split from the header")
        self.assertEqual(cipher_name, u'TEST', msg="cipher name was not properly set")
        self.assertEqual(b_version, b"9.9", msg="version was not properly set")
*/
#endif


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



DECRYPT_RESULT ParseVaultContent(std::string_view& encrypted_data, VaultContent& out_vault_content)
{
    out_vault_content.clear();

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
    out_vault_content.salt = HexStringToBytes(salt_hex);
    out_vault_content.hmac = HexStringToBytes(hmac_hex);
    out_vault_content.data = HexStringToBytes(data_hex);

    return DECRYPT_RESULT::OK;
}


DECRYPT_RESULT decrypt(std::string_view encrypted_utf8, std::string_view password_utf8, std::optional<std::string_view> salt_utf8, std::string& output_vault_id_utf8, std::ostringstream& output_utf8)
{
    output_vault_id_utf8.clear();
    output_utf8.clear();

    return DECRYPT_RESULT::OK;
}

bool calculateHMAC(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data, std::vector<uint8_t>& out_hmac)
{
    // Set the output to the correct number of zeros
    out_hmac.assign(32, 0);

std::cout<<"calculateHMAC key length: "<<key.size()<<", data length: "<<data.size()<<std::endl;

    try {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac((const CryptoPP::byte*)key.data(), key.size());

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

bool verifyHMAC(const std::vector<uint8_t>& expected_hmac, const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> calculated_hmac;
    if (!calculateHMAC(key, data, calculated_hmac)) {
        return false;
    }

    return (expected_hmac == calculated_hmac);
}




//public final static String CYPHER_ID = "AES256";
//public final static String KEYGEN_ALGO = "HmacSHA256";
//public final static String CYPHER_KEY_ALGO = "AES";
//public static final String CYPHER_ALGO = "AES/CTR/NoPadding";



// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#if 0

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CTR_Mode;

#include "assert.h"

int main(int argc, char* argv[])
{
  AutoSeededRandomPool prng;

  byte key[AES::DEFAULT_KEYLENGTH];
  prng.GenerateBlock(key, sizeof(key));

  byte iv[AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));

  string plain = "CTR Mode Test";
  string cipher, encoded, recovered;

  /*********************************\
  \*********************************/

  // Pretty print key
  encoded.clear();
  StringSource(key, sizeof(key), true,
    new HexEncoder(
      new StringSink(encoded)
    ) // HexEncoder
  ); // StringSource
  cout << "key: " << encoded << endl;

  // Pretty print iv
  encoded.clear();
  StringSource(iv, sizeof(iv), true,
    new HexEncoder(
      new StringSink(encoded)
    ) // HexEncoder
  ); // StringSource
  cout << "iv: " << encoded << endl;

  /*********************************\
  \*********************************/

  try
  {
    cout << "plain text: " << plain << endl;

    CTR_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource(plain, true, 
      new StreamTransformationFilter(e,
        new StringSink(cipher)
      ) // StreamTransformationFilter      
    ); // StringSource
  }
  catch(const CryptoPP::Exception& e)
  {
    cerr << e.what() << endl;
    exit(1);
  }

  /*********************************\
  \*********************************/

  // Pretty print
  encoded.clear();
  StringSource(cipher, true,
    new HexEncoder(
      new StringSink(encoded)
    ) // HexEncoder
  ); // StringSource
  cout << "cipher text: " << encoded << endl;

  /*********************************\
  \*********************************/

  try
  {
    CTR_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(cipher, true, 
      new StreamTransformationFilter(d,
        new StringSink(recovered)
      ) // StreamTransformationFilter
    ); // StringSource

    cout << "recovered text: " << recovered << endl;
  }
  catch(const CryptoPP::Exception& e)
  {
    cerr << e.what() << endl;
    exit(1);
  }

  /*********************************\
  \*********************************/

  return 0;
}

#endif


bool decryptAES(const std::vector<uint8_t>& _cypher, const std::vector<uint8_t>& _key, const std::vector<uint8_t>& _iv, std::vector<uint8_t>& out_decrypted)
{
    out_decrypted.clear();

    if (_key.size() != CryptoPP::AES::DEFAULT_KEYLENGTH) {
        std::cerr<<"decryptAES Key is the wrong size"<<std::endl;
        return false;
    } else if (_iv.size() != CryptoPP::AES::BLOCKSIZE) {
        std::cerr<<"decryptAES IV is the wrong size"<<std::endl;
        return false;
    }

    /*SecretKeySpec keySpec = new SecretKeySpec(key, CYPHER_KEY_ALGO);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    Cipher cipher = Cipher.getInstance(CYPHER_ALGO);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    byte[] decrypted = cipher.doFinal(cypher);
    out_decrypted = unpad(decrypted);*/


  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    for (size_t i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++) {
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

    std::string recovered;

    try {
        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        CryptoPP::StringSource s(cypher.str(), true, 
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(recovered)
            )
        );
    } catch(const CryptoPP::Exception& e) {
        std::cerr<<e.what()<<std::endl;
        return false;
    }

    std::cout<<"decryptAES Recovered text: "<<recovered<<std::endl;

    return true;
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
    const std::vector<uint8_t> cypherKey = keys.getEncryptionKey();
    std::ostringstream o4;
    BytesToHexString(cypherKey, 100, o4);
    std::cout<<"Key 1 length: "<<cypherKey.size()<<", value: "<<o4.str()<<std::endl;

    // key2
    const std::vector<uint8_t> hmacKey = keys.getHMACKey();
    std::ostringstream o5;
    BytesToHexString(hmacKey, 100, o5);
    std::cout<<"Key 2 length: "<<hmacKey.size()<<", value: "<<o5.str()<<std::endl;

    // iv
    const std::vector<uint8_t> iv = keys.getIV();
    std::ostringstream o6;
    BytesToHexString(iv, 100, o6);
    std::cout<<"IV length: "<<iv.size()<<", value: "<<o6.str()<<std::endl;

    const std::vector<uint8_t>& cypher = vault_content.data;

    if (!verifyHMAC(vault_content.hmac, hmacKey, cypher)) {
        std::cerr<<"Error verifying hmac"<<std::endl;
        return DECRYPT_RESULT::ERROR_VERIFYING_HMAC;
    }

    std::cout<<"Signature matches - decrypting"<<std::endl;
    std::vector<uint8_t> decrypted;
    if (!decryptAES(cypher, cypherKey, iv, decrypted)) {
        std::cerr<<"Error decrypting"<<std::endl;
        return DECRYPT_RESULT::ERROR_DECRYPTING_CONTENT;
    }

    std::cout<<"Decoded: \""<<std::string((const char*)decrypted.data(), decrypted.size())<<"\""<<std::endl;

    return DECRYPT_RESULT::OK;

    //std::string output_vault_id_utf8;
    //return decrypt(encrypted_utf8, password_utf8, std::nullopt, output_vault_id_utf8, output_utf8);
}

}

### libansible-vault-cpp

## About

**Warning: I am not an expert. This library is purely for my own curiosity. Do not use it in production.**  

We try to use as much third party code as possible. This library is basically just a wrapper around [CryptoPP](https://www.cryptopp.com/) with some glue code to read and write ansible vault files.  
We use SecureArray and SecureString which clear the array when released, whenever we store sensitive values such as the vault content, password, salt, hmac, key, and iv.

## Safer, battle hardened, tested, more sensible options for storing secrets (Use these instead)

### Ansible Vault Manipulation

- https://docs.ansible.com/ansible/latest/cli/ansible-vault.html
- https://github.com/Wedjaa/JavaAnsibleVault
- https://github.com/vermut/intellij-encryption
- https://github.com/pbthorste/avtool

### General Secret Storage

- https://github.com/AGWA/git-crypt
- https://github.com/getsops/sops
- https://github.com/dani-garcia/vaultwarden
- https://www.hashicorp.com/products/vault

## I'm Brave/Fool Hardy! Building

### Install Prerquisites

```bash
sudo yum install cryptopp-devel gtest-devel
```

### Build the library and unit tests

```bash
cmake .
make
```

Generates libansible-vault-cpp.so\[.0.1\] and ansible-vault-cpp_test.

### Run the unit tests

```bash
./ansible-vault-cpp_test
```

## Limitations

- Does not support the Vault ID part
- Apart from some basic unit tests this is basically untested code. It is basically experimental code, do **not** trust it with your secrets

## Ansible Vault Format

### Without Vault ID

```
$ANSIBLE_VAULT;1.1;AES256
65333363656231663530393762613031336662613262326666386233643763636339366235626334
3236636366366131383962323463633861653061346538360a386566363337383133613761313566
31623761656437393862643936373564313565663633636366396231653131386364336534626338
3430343561626237660a333562616537623035396539343634656439356439616439376630396438
3730
```

### With Vault ID (Not supported by ansible-vault-cpp)

```
$ANSIBLE_VAULT;1.2;AES256;myvaultid
30613233633461343837653833666333643061636561303338373661313838333565653635353162
3263363434623733343538653462613064333634333464660a663633623939393439316636633863
61636237636537333938306331383339353265363239643939666639386530626330633337633833
6664656334373166630a363736393262666465663432613932613036303963343263623137386239
6330
```

## Encryption Process

The encryption process is basically:
1. Generate a salt
2. Use [PKCS5 PBKDF2 HMAC](https://cryptopp.com/wiki/PKCS5_PBKDF2_HMAC) with the salt and password to derive the encryption key, HMAC key, and IV
3. Derived encryption key and IV are used to key a block cypher for [AES256 encryption](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard)
4. Create [HMAC](https://www.cryptopp.com/wiki/HMAC) with SHA256 from the encrypted data
5. Combine hex(salt) + '\n' + hex(hmachash) + '\n' + hex(encrypted)
6. hex(combined)

## Decryption Process

Decryption is basically the reverse:
1. unhex(combined)
2. Split parts salt, hmachash, encrypted
3. unhex(salt), unhex(hmachash), unhex(encrypted)
4. Use [PKCS5 PBKDF2 HMAC](https://cryptopp.com/wiki/PKCS5_PBKDF2_HMAC) with the salt and password to derive the encryption key, HMAC key, and IV
5. Verify [HMAC](https://www.cryptopp.com/wiki/HMAC) with SHA256 for the the encrypted data matches the expected hmachash
6. Derived encryption key and IV are used to key a block cypher for [AES256 decryption](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard)

## Standard Red Hat ansible-vault Executable Usage for Testing Compatibility (Not ansible-vault-cpp)

https://stackoverflow.com/questions/43467180/how-to-decrypt-string-with-ansible-vault-2-3-0

### Decrypting From Pipe

Password: 123

```bash
echo '$ANSIBLE_VAULT;1.2;AES256;dev
30613233633461343837653833666333643061636561303338373661313838333565653635353162
3263363434623733343538653462613064333634333464660a663633623939393439316636633863
61636237636537333938306331383339353265363239643939666639386530626330633337633833
6664656334373166630a363736393262666465663432613932613036303963343263623137386239
6330' | ansible-vault decrypt
```

### Encrypt/decrypt In Place

Encrypt:  
```bash
ansible-vault encrypt vars/vault.yaml
```

Decrypt:  
```bash
ansible-vault decrypt vars/vault.yaml
```

### Encrypt/decrypt From Files

Encrypt:  
```bash
echo "mypassword" > password.txt
echo "My plain text file\nMultiple lines\n" > plaintext.txt
ansible-vault encrypt --vault-password-file password.txt --output output_encrypted.txt plaintext.txt
```
OR  
(Asks for password, which is "mypassword")  
```bash
echo "My plain text file\nMultiple lines\n" > plaintext.txt
ansible-vault encrypt --output output_encrypted.txt plaintext.txt
```

Decrypt:  
```bash
ansible-vault decrypt --vault-password-file password.txt --output output_decrypted.txt output_encrypted.txt
```
OR  
(Asks for password, which is "mypassword")  
```bash
ansible-vault decrypt --output sample_decrypted.txt test/data/sample.txt
```

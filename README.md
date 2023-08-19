### ansible-vault-cpp

## About

**Warning: I am not an expert. This library is purely for my own curiosity. Do not use it in production.**  
I try to use as much third party code. This library is basically just a wrapper around [CryptoPP](https://www.cryptopp.com/) with some glue code to read and write ansible vault files.

## Ansible Vault Format

The encryption process is basically:
1. Generate a salt
2. Use [PKCS5 PBKDF2 HMAC](https://cryptopp.com/wiki/PKCS5_PBKDF2_HMAC) with the salt and password to derive the encryption key, HMAC key, and IV
3. Derived encryption key and IV are used to key a block cypher for [AES256 encryption](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard)
4. Create [HMAC](https://www.cryptopp.com/wiki/HMAC) with SHA256 from the encrypted data
5. Combine hex(salt) + '\n' + hex(hmachash) + '\n' + hex(encrypted)
6. hex(combined)

Decryption is basically the reverse:
1. unhex(combined)
2. Split parts salt, hmachash, encrypted
3. unhex(salt), unhex(hmachash), unhex(encrypted)
4. Use [PKCS5 PBKDF2 HMAC](https://cryptopp.com/wiki/PKCS5_PBKDF2_HMAC) with the salt and password to derive the encryption key, HMAC key, and IV
5. Verify [HMAC](https://www.cryptopp.com/wiki/HMAC) with SHA256 for the the encrypted data matches the expected hmachash
6. Derived encryption key and IV are used to key a block cypher for [AES256 decryption](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard)

## Safer, battle hardened, tested, more sensible options for storing secrets

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

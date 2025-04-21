# AES Algorithm

Does not implement prevention against side channel attacks, cache-based attacks, and other sophisticated types of attacks, this is mainly for educational purposes only, use a better library for production cryptographic operations.
 
Based on your `aes.hpp` file, here is a suggested README that provides an overview of the AES algorithm, instructions on how to use the functionalities in your code, and some AES history.

---

# AES Algorithm Implementation

This repository provides an implementation of the Advanced Encryption Standard (AES) algorithm, supporting key sizes of 128 and 256 bits. The AES algorithm is a widely used symmetric encryption standard adopted by the U.S. government and many organizations worldwide for securing sensitive data.

## Table of Contents

1. [About AES](#about-aes)
2. [Features](#features)
3. [Usage](#usage)
   - [Generating a Secure Key](#generating-a-secure-key)
   - [Encrypting Data](#encrypting-data)
   - [Decrypting Data](#decrypting-data)
4. [Code Example](#code-example)
5. [References](#references)

---

## About AES

AES was established as a Federal Information Processing Standard (FIPS) in 2001 by the National Institute of Standards and Technology (NIST). It is based on the Rijndael block cipher developed by Vincent Rijmen and Joan Daemen.

Key characteristics of AES:
- **Block Size:** 128 bits
- **Key Sizes:** 128, 192, or 256 bits (only 128 and 256 are implemented in this repository)
- **Rounds:** 10 (128-bit keys), 14 (256-bit keys)

AES is widely used in secure communications, file encryption, and other applications requiring strong encryption.

---

## Features

- **Key Sizes Supported:** 128 bits and 256 bits
- **Encryption and Decryption:** Implements both AES encryption and decryption.
- **Utilities:**
  - Generate secure random keys.
  - Perform Galois Field arithmetic.
  - Create S-Box and inverse S-Box.
  - Rounds for SubBytes, ShiftRows, MixColumns, and AddRoundKey.

---

## Usage

### Generating a Secure Key

The `AESUtils` class provides a method to generate secure random keys of the specified size.

```cpp
std::string key = AESUtils::genSecKeyBlock(AES128KS); // For 128-bit key
```

### Encrypting Data

To encrypt data, use the `AES_Encryption` class. Ensure the input is padded to match the block size (128 bits).

```cpp
#include "aes.hpp"
using namespace AESCrypto;

AES_Encryption<AES128KS> encryptor;
std::vector<byte> encryptedData = encryptor.call("plaintext", "securekey128");
```

### Decrypting Data

To decrypt the encrypted data, use the `AES_Decryption` class.

```cpp
AES_Decryption<AES128KS> decryptor;
std::vector<byte> decryptedData = decryptor.call(std::string(encryptedData.begin(), encryptedData.end(), "securekey128");
```

---

## Code Example

Here's a complete example of encryption and decryption using a 128-bit key:

```cpp
#include "aes.hpp"
#include <iostream>

int main() {
    using namespace AESCrypto;

    std::string plaintext = "Hello, AES!";
    std::string key = AESUtils::genSecKeyBlock(AES128KS);

    // Encrypt
    AES_Encryption<AES128KS> encryptor;
    std::vector<byte> encryptedData = encryptor.call(plaintext, key);

    // Decrypt
    AES_Decryption<AES128KS> decryptor;
    std::vector<byte> decryptedData = decryptor.call(std::string(encryptedData.begin(), encryptedData.end()), key);

    // Output
    std::cout << "Original: " << plaintext << "\n";
    std::cout << "Decrypted: " << std::string(decryptedData.begin(), decryptedData.end()) << "\n";

    return 0;
}
```

---

## References

- [NIST AES Overview](https://csrc.nist.gov/projects/block-cipher-techniques)
- [AES on Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

---

# AES Algorithm

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17 Ready](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![AES Algorithm](https://img.shields.io/badge/algorithm-AES-lightgrey.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![AES Winner](https://img.shields.io/badge/AES-Winner-blue.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![Block Size: 128 bits](https://img.shields.io/badge/block%20size-128%20bits-orange.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![Key Sizes: 128/192/256 bits](https://img.shields.io/badge/key%20sizes-128%2F192%2F256%20bits-green.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![Modes: ECB, CBC, CFB, OFB, CTR](https://img.shields.io/badge/modes-ECB%2C%20CBC%2C%20CFB%2C%20OFB%2C%20CTR-lightblue.svg)](#modes-of-operation)
[![Header-only](https://img.shields.io/badge/header--only-yes-critical.svg)](https://github.com/runaway666666/aes)
[![Status: Educational](https://img.shields.io/badge/status-educational-important.svg)](#security-notes-and-disclaimer)

# Contents

* Disclaimer
* How AES works
* Prerequisites
* Code Components
* Usage
* Limitations
* Resources
* Contributions
* License

---

## ⚠ Disclaimer 🚨

This implementation of the **AES (Advanced Encryption Standard)** algorithm is provided for **educational and demonstration purposes only**.  
It is **not intended** to be secure, efficient, or suitable for production environments.  

👉 **Recommendation:** Use well-established and thoroughly tested cryptographic libraries for robust encryption needs.

---

## How AES works

The goal of this [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) implementation is to provide an understanding of how AES works, its internal mathematical operations, and concepts that make AES efficient.  
This implementation is written in modern C++ (C++17), using template-free and object-oriented approaches for clarity and educational value.

**AES** (Rijndael) is a symmetric block cipher algorithm adopted by [NIST](https://www.nist.gov/) in 2001.  
It operates on fixed block sizes of 128 bits (16 bytes) and supports key sizes of 128, 192, and 256 bits.

### AES Rounds

| Key Size | Rounds |
|----------|--------|
| 128      | 10     |
| 192      | 12     |
| 256      | 14     |

### AES Constants

| Constant   | Size (bytes) |
|------------|-------------|
| Sbox       | 256         |
| InvSbox    | 256         |
| MixCols    | 16          |
| InvMixCols | 16          |
| Rcon       | 256         |

**Nb**: Number of columns in the state (always 4 for AES)  
**Nk**: Number of 32-bit words in the key (4, 6, or 8)  
**Nr**: Number of rounds (10, 12, 14)

### Main AES Operations

#### Encryption

- KeyExpansion
- SubBytes
- ShiftRows
- MixColumns
- AddRoundKey

#### Decryption

- KeyExpansion
- InvShiftRows
- InvSubBytes
- AddRoundKey
- InvMixColumns

### Padding

AES operates on 16-byte blocks. If the data is not a multiple of the block size, it must be padded.  
This implementation uses PKCS#7 padding via `AES::Utils::PKCS7Pad` and unpadding via `AES::Utils::PKCS7Unpad`.

### Modes of Operation

AES supports several modes:

| Mode | Parallelizable (Enc) | Parallelizable (Dec) | Random-Read | IV/Nonce | Counter | Style           |
|------|----------------------|---------------------|-------------|----------|---------|-----------------|
| ECB  | YES                  | YES                 | YES         | NO       | NO      | Block           |
| CBC  | NO                   | YES                 | YES         | YES      | NO      | Block           |
| OFB  | NO                   | NO                  | NO          | YES      | NO      | Stream-like     |
| CFB  | NO                   | YES                 | YES         | YES      | NO      | Stream-like     |
| CTR  | YES                  | YES                 | YES         | YES      | YES     | Stream-like     |

**Note:** GCM is not implemented in this header.

---

## Prerequisites

- C++17-compliant compiler.
- Linux/Unix recommended for best entropy (key/IV generation).

---

## Code Components

The header `aes.hpp` defines:

- `AES::byte` — Byte alias (`uint8_t`)
- `AES::SecureByteBlock` — Secure byte container for keys/IVs.
- `AES::SecureByteGenerator` — Static methods to generate random key/IV blocks using CSPRNG or PRNG.
- `AES::Utils` — Utility namespace (PKCS#7 padding, key size validation, etc).
- `AES::Engine` — AES core engine for block operations.
- `AES::Result` — Result wrapper with various output conversions.
- `AES::ECB`, `AES::CBC`, `AES::CFB`, `AES::OFB`, `AES::CTR` — Structs, each providing static `Encrypt` and `Decrypt` for that mode.

### Example Table: Core API

| Struct/Class                   | Purpose                                               |
|------------------------------- |------------------------------------------------------|
| `AES::Engine`                  | Performs AES block encryption/decryption              |
| `AES::ECB`, ...                | Provides mode-specific high-level API                |
| `AES::SecureByteGenerator`     | Generate keys and IVs securely                       |
| `AES::Result`                  | Output wrapper: `.toVector()`, `.toString()`, etc.   |

---

Absolutely! Here’s a **comprehensive and detailed Usage section** for your `aes.hpp` showing all important functionalities, including both simple and advanced usage for every mode (ECB, CBC, CFB, OFB, CTR), with all variants (`Encrypt`, `Decrypt`, `ParallelEncryption`, `SerialEncryption`, etc.), and demonstrating how to use `AES::Result` for output. This will form a robust reference for users of your header.

---

Certainly! Here is a segmented, well-structured Usage section for your README. Each section introduces and explains the concept before showing concise, correct code samples, specifically tailored to your aes.hpp header. This is ideal for onboarding users who want both conceptual clarity and practical code at a glance.

---

## Usage

---

### 1. Generating a Secure AES Key

**Description:**  
AES keys must be random and of the correct length for the chosen security level (128, 192, or 256 bits).  
This library provides a simple, secure way to generate keys.

```cpp
// Generate a 128-bit AES key (16 bytes)
std::string key128 = AES::SecureByteGenerator::GenKeyBlock(AES::AES128KS).toString(); // or .toVector() for std::vector<byte> ...

// Generate a 192-bit AES key (24 bytes)
std::string key192 = AES::SecureByteGenerator::GenKeyBlock(AES::AES192KS).toString();

// Generate a 256-bit AES key (32 bytes)
std::string key256 = AES::SecureByteGenerator::GenKeyBlock(AES::AES256KS).toString();
```

*Use the correct key size for your security requirements and make sure to keep the key secret.*

---

### 2. Creating a Secure Initialization Vector (IV)

**Description:**  
Some AES modes (CBC, CFB, OFB, CTR) require a random Initialization Vector (IV) of 16 bytes (128 bits).  
An IV should be unique and unpredictable for every encryption session.

```cpp
std::string iv = AES::SecureByteGenerator::GenIvBlock(16).toString(); // or .toVector() for vector type...
```

*Always generate a new IV for each message when using modes that require it. The IV does not need to be kept secret, but must be unique.*

---

### 3. Serial vs Parallel Encryption/Decryption

**Description:**  
- **Serial mode** processes one block at a time, suitable for environments with limited resources or when deterministic order is required.
- **Parallel mode** leverages multi-core CPUs to process multiple blocks at once, offering better performance for large data if `AES_ENABLE_PARALLEL_MODE` is defined.

---

#### Serial Mode Example

```cpp
std::string plaintext("some message to encrypt!");

// Serial Encryption (CBC mode)
AES::Result encrypted = AES::CBC::SerialEncryption(plaintext, key, iv);

// Serial Decryption
AES::Result decrypted = AES::CBC::SerialDecryption(encrypted.toString(), key, iv);
```

---

#### Parallel Mode Example

**Description:**  
Parallel encryption and decryption will process blocks concurrently.  
Use this when encrypting/decrypting large data for better speed (if your system supports it).

```cpp
// Parallel Encryption (CBC mode)
AES::Result encrypted = AES::CBC::ParallelEncryption(plaintext, key, iv);

// Parallel Decryption
AES::Result decrypted = AES::CBC::ParallelDecryption(encrypted.toString(), key, iv);
```

*Choose parallel for speed, serial for simple or deterministic use.*

---

### 4. Output Formats

**Description:**  
After encryption or decryption, you can extract the result in different formats.

```cpp
AES::Result result = AES::ECB::SerialEncryption("test", key);
std::vector<AES::byte> raw = result.toVector();   // Raw bytes
std::string hex = result.toHex();                 // Hex string
std::string b64 = result.toBase64();              // Base64
std::string ascii = result.toAscii();             // ASCII
std::string plain = AES::ECB::SerialDecryption(raw, key).toString(); // Decrypted as string
```

---

### 5. Mode-by-Mode Examples

---

#### ECB Mode

**About:**  
ECB (Electronic Codebook) is the simplest AES mode. Each block is encrypted independently.  
**Warning:** Do not use ECB for sensitive data—it leaks patterns!

```cpp
AES::Result enc = AES::ECB::SerialEncryption(plaintext, key);
AES::Result dec = AES::ECB::SerialDecryption(enc.toString(), key);
```

---

#### CBC Mode

**About:**  
CBC (Cipher Block Chaining) xors each plaintext block with the previous ciphertext block, using an IV for the first block.  
This is a secure default for most applications (with random IV per message).

```cpp
AES::Result enc = AES::CBC::SerialEncryption(plaintext, key, iv);
AES::Result dec = AES::CBC::SerialDecryption(enc.toString(), key, iv);
```

---

#### CFB Mode

**About:**  
CFB (Cipher Feedback) turns AES into a self-synchronizing stream cipher. Good for encrypting data of arbitrary length.

```cpp
AES::Result enc = AES::CFB::SerialEncryption(plaintext, key, iv);
AES::Result dec = AES::CFB::SerialDecryption(enc.toString(), key, iv);
```

---

#### OFB Mode

**About:**  
OFB (Output Feedback) is similar to CFB, but more resistant to transmission errors. Produces a key stream that is xored with plaintext.

```cpp
AES::Result enc = AES::OFB::SerialEncryption(plaintext, key, iv);
AES::Result dec = AES::OFB::SerialDecryption(enc.toString(), key, iv);
```

---

#### CTR Mode

**About:**  
CTR (Counter) mode turns AES into a stream cipher using a nonce and counter. Allows random access to encrypted data and parallel processing.

```cpp
AES::Result enc = AES::CTR::SerialEncryption(plaintext, key, iv);
AES::Result dec = AES::CTR::SerialDecryption(enc.toString(), key, iv);
```

---

### 6. Full Example using Parallel Mode

```cpp
#include "aes.hpp"
#include <iostream>

int main() {
    // 1. Generate a 128-bit AES key and a 16-byte IV
    std::string key = AES::SecureByteGenerator::GenKeyBlock(AES::AES256KS).toString();
    std::string iv  = AES::SecureByteGenerator::GenIvBlock(16).toString();

    // 2. Define plaintext
    std::string plaintext = "Parallel encryption and decryption example!";

    // 3. Parallel Encryption (CBC mode)
    AES::Result encrypted = AES::CBC::ParallelEncryption(plaintext, key, iv);

    // 4. Parallel Decryption (CBC mode)
    AES::Result decrypted = AES::CBC::ParallelDecryption(encrypted.toString(), key, iv);

    // 5. Print results
    std::cout << "Original:        " << plaintext << std::endl;
    std::cout << "Encrypted(Hex):  " << encrypted.toHex() << std::endl;
    std::cout << "Decrypted:       " << decrypted.toString() << std::endl;

    return 0;
}
```

### 6. Full Example using Serial Mode

```cpp
#include "aes.hpp"
#include <iostream>

int main() {
    // 1. Generate a 128-bit AES key and a 16-byte IV
    std::string key = AES::SecureByteGenerator::GenKeyBlock(AES::AES256KS).toString();
    std::string iv  = AES::SecureByteGenerator::GenIvBlock(16).toString();

    // 2. Define plaintext
    std::string plaintext = "Serial encryption and decryption example!";

    // 3. Serial Encryption (CBC mode)
    AES::Result encrypted = AES::CBC::SerialEncryption(plaintext, key, iv);

    // 4. Serial Decryption (CBC mode)
    AES::Result decrypted = AES::CBC::SerialDecryption(encrypted.toString(), key, iv);

    // 5. Print results
    std::cout << "Original:        " << plaintext << std::endl;
    std::cout << "Encrypted(Hex):  " << encrypted.toHex() << std::endl;
    std::cout << "Decrypted:       " << decrypted.toString() << std::endl;

    return 0;
}
```


---

### 13. Note on PKCS#7 Padding

ECB and CBC modes require padding. This implementation applies PKCS#7 automatically for those modes.  
OFB, CFB, and CTR do not require padding and are safe for arbitrary-length plaintext.

---


### 4. Output Formats

`AES::Result` provides:

- `.toVector()` — Get as `std::vector<AES::byte>`
- `.toString()` — As plaintext (if decrypting)
- `.toHex()` — Hex representation
- `.toBase64()` — Base64
- `.toAscii()` — ASCII-safe

### 5. Key Sizes

- 16 bytes → 128 bits
- 24 bytes → 192 bits
- 32 bytes → 256 bits

Use the appropriate key size for your desired AES strength.

---

## Limitations

1. **Security**:
   - Not hardened against side-channel or cache attacks.
   - Not production ready.


---

## Resources

### 📚 General Cryptography
- [Cryptography (Wikipedia)](https://en.wikipedia.org/wiki/Cryptography)  
- [Cryptographic Primitives Overview](https://en.wikipedia.org/wiki/Cryptographic_primitive)  
- [Symmetric-key Cryptography](https://en.wikipedia.org/wiki/Symmetric-key_algorithm)  
- [Public-key Cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)  

### 🔐 AES (Advanced Encryption Standard)
- [AES (Wikipedia)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)  
- [NIST AES Specification (FIPS 197)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)  
- [AES Explained (Khan Academy)](https://www.khanacademy.org/computing/computer-science/cryptography/modern-crypt/v/advanced-encryption-standard-aes)  
- [AES Key Sizes and Security](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard)  

### 🧩 Block Ciphers
- [Block Cipher (Wikipedia)](https://en.wikipedia.org/wiki/Block_cipher)  
- [Modes of Block Ciphers](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)  
- [ECB vs CBC vs CTR Modes](https://crypto.stackexchange.com/questions/202/what-are-the-differences-between-ecb-cbc-and-ctr-encryption-modes)  
- [Padding in Block Ciphers](https://crypto.stackexchange.com/questions/2996/what-is-padding-and-why-is-it-required)  

### 📦 Cryptographic Libraries
- [Crypto++](https://cryptopp.com/)  
- [OpenSSL](https://www.openssl.org/)  
- [Bouncy Castle](https://www.bouncycastle.org/)  
- [Libsodium](https://libsodium.org/)  

### 📘 Cryptanalysis and Attacks
- [Cryptanalysis (Wikipedia)](https://en.wikipedia.org/wiki/Cryptanalysis)  
- [Side-channel Attacks](https://en.wikipedia.org/wiki/Side-channel_attack)  
- [Differential Cryptanalysis](https://en.wikipedia.org/wiki/Differential_cryptanalysis)  
- [Linear Cryptanalysis](https://en.wikipedia.org/wiki/Linear_cryptanalysis)  

### 📄 Additional Learning Resources
- [Applied Cryptography by Bruce Schneier](https://www.schneier.com/books/applied_cryptography/)  
- [Introduction to Modern Cryptography](https://www.crcpress.com/Introduction-to-Modern-Cryptography/Katz-Lindell/p/book/9780367331757)  
- [Cryptography I (Stanford Online)](https://online.stanford.edu/courses/cs155-cryptography)  

### 🛠 Tools for Cryptography
- [Online AES Encryption Tool](https://www.devglan.com/online-tools/aes-encryption-decryption)  
- [CyberChef (The Cyber Swiss Army Knife)](https://gchq.github.io/CyberChef/)  
- [Hash Function Testers](https://passwordsgenerator.net/sha256-hash-generator/)  

---

## Contributions

Contributions are welcome! If you encounter issues or have suggestions, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

# AES Algorithm

## Table of Contents
- [Introduction](#introduction)
- [History of AES](#history-of-aes)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Example Code](#example-code)
- [Explanation](#explanation)
- [License](#license)

## Introduction

AES (Advanced Encryption Standard) is a symmetric block cipher algorithm that operates on fixed-size blocks of data. AES is the most widely used encryption algorithm today due to its efficiency and security properties. This repository provides a C++ implementation of the AES algorithm for educational and application purposes.

## History of AES

The Advanced Encryption Standard (AES) was established by the U.S. National Institute of Standards and Technology (NIST) in 2001. It replaced the older Data Encryption Standard (DES) due to DES's vulnerability to brute-force attacks. The AES algorithm was selected through a competition involving various cryptographic algorithms, with the Rijndael algorithm, designed by Vincent Rijmen and Joan Daemen, emerging as the winner. AES has since become a global standard for encryption, widely adopted in government, financial services, and other industries requiring secure data transmission.

## Features

- Supports AES-128, AES-192, and AES-256 encryption modes.
- Encryption and decryption functionalities.
- Easy-to-use interface.
- Detailed implementation using Galois fields and polynomial arithmetic.

## Requirements

- C++11 or higher
- CMake (optional)

## Installation

To use this AES implementation, you can simply clone the repository:

```sh
git clone https://github.com/MrkFrcsl98/AES_algorithm.git
cd AES_algorithm
```

## Usage

Include the `aes.hpp` header file in your project and use the provided classes and functions to perform encryption and decryption.

### Example Code

Here is an example of how to use the AES implementation:

```cpp
#include "aes.hpp"
#include <iostream>
#include <vector>
#include <string>

int main() {
    // Key and plaintext examples
    std::vector<uint8_t> key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xc5, 0x6d, 0x2a, 0x4a, 0x6a, 0x6e};
    std::vector<uint8_t> plaintext = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    // Create AES object
    AES::AES_Encryption_v1 aes;

    // Encrypt
    std::vector<uint8_t> ciphertext(16);
    aes.Encrypt(plaintext.data(), ciphertext.data(), key.data());
    std::cout << "Ciphertext: ";
    for (auto c : ciphertext) {
        std::cout << std::hex << static_cast<int>(c) << " ";
    }
    std::cout << std::endl;

    // Decrypt
    std::vector<uint8_t> decrypted(16);
    aes.Decrypt(ciphertext.data(), decrypted.data(), key.data());
    std::cout << "Decrypted: ";
    for (auto d : decrypted) {
        std::cout << std::hex << static_cast<int>(d) << " ";
    }
    std::cout << std::endl;

    return 0;
}
```

Using AES_Encryption_v2...
```cpp
#include "aes.hpp"
#include <iostream>
#include <vector>
#include <string>

int main() {
   try {
      AES::AES_Encryption_v2 simpleAES;

      std::string key = "thisisasecretkey"; // 16 bytes for AES-128
      std::string plaintext = "hello world";

      // Encrypt
      std::string encrypted = simpleAES.Encrypt(plaintext, key);
      std::cout << "Encrypted text (hex): " << encrypted << std::endl;

      // Decrypt
      std::string decrypted = simpleAES.Decrypt(encrypted, key);
      std::cout << "Decrypted text: " << decrypted << std::endl;
    } catch (const std::exception &e) {
      std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

## Explanation

### AES Class

The `AES` class is the main class used for encryption and decryption. You can create an instance of this class by specifying the key size (128, 192, or 256 bits).

```cpp
AES::AES_Encryption_v1 aes; // For AES-128
```

### Encryption

The `Encrypt` method takes a plaintext array and a key array as input and returns the encrypted ciphertext.

```cpp
std::vector<uint8_t> ciphertext(16);
aes.Encrypt(plaintext.data(), ciphertext.data(), key.data());
```

### Decryption

The `Decrypt` method takes a ciphertext array and a key array as input and returns the decrypted plaintext.

```cpp
std::vector<uint8_t> decrypted(16);
aes.Decrypt(ciphertext.data(), decrypted.data(), key.data());
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

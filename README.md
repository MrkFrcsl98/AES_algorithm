# AES Algorithm Implementation

This repository contains a C++ implementation of the Advanced Encryption Standard (AES) algorithm. The implementation supports key sizes of 128, 192 and 256 bits. It provides encryption and decryption functionalities as well as utilities for secure key generation using both Mersenne Twister and a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).

`This is intended for education purpose only, do not use this shit in production mode, first because it sucks in size and speed(is not optimized at all), second, does not protect against any attack vector.`

## Features

- **AES Encryption and Decryption**:
  - Supports AES-128, AES-192 and AES-256 modes.
  - Implements all AES components including S-Box generation, key expansion, and Rijndael transformations.
  
- **Key Generation**:
  - Generates secure random keys using a custom CSPRNG or Mersenne Twister PRNG.
  
- **Test Framework**:
  - Includes a test suite to validate AES encryption and decryption for varying plaintext lengths and key sizes.

---

## File Structure

- **`aes.hpp`**: The main implementation file containing the core AES classes and utility functions.
- **Namespaces**:
  - `AesCryptoModule`: Contains the AES implementation and utilities.
  - `AESCrypto`: Includes the AES-specific encryption and decryption logic.
  - `Test`: Provides testing functionality for the AES implementation.

---

## How It Works

### AES Components

- **Key Expansion**:
  - Expands the input key into multiple round keys for AES operations.
- **Rijndael Transformations**:
  - Implements SubBytes, ShiftRows, MixColumns, and AddRoundKey operations.
- **Padding**:
  - Uses PKCS#7 padding for plaintext alignment with AES block sizes.

### Key Generation

- **Mersenne Twister PRNG**:
  - Generates random keys for AES encryption.
- **CSPRNG** (Linux/Unix):
  - Provides higher entropy key generation by reading from `/dev/urandom`.

---

## Usage

### Prerequisites

- A C++ compiler supporting C++17 or later.
- Linux/Unix system recommended for the CSPRNG functionality.

### Example Code

Here is an example of how to use the AES implementation:

```cpp
#include "aes.hpp"

int main() {
    std::string plaintext = "This is a secret message!";
    std::string key = Test::CSPRNG::genSecKeyBlock(128); // Generate a 128-bit AES key.

    // Encrypt the plaintext.
    AESCrypto::AES_Encryption<AES128KS> aesEncryptor;
    std::vector<byte> encryptedData = aesEncryptor.call(plaintext, key);

    // Decrypt the ciphertext.
    AESCrypto::AES_Decryption<AES128KS> aesDecryptor;
    std::vector<byte> decryptedData = aesDecryptor.call(std::string(encryptedData.begin(), encryptedData.end()), key);

    // Output results.
    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Encrypted (Hex): ";
    for (byte b : encryptedData) {
        std::cout << std::hex << (int)b << " ";
    }
    std::cout << "\nDecrypted: " << std::string(decryptedData.begin(), decryptedData.end()) << std::endl;

    return 0;
}
```

### Test Suite

To run the provided test cases:

1. Compile and execute the `run()` function in the `Test` namespace.
2. The test suite encrypts and decrypts the plaintext using AES-128, AES-192, and AES-256 keys, validating the correctness of the implementation.

---

## Key Classes and Functions

### `AESCrypto::AES_Encryption`
Handles AES encryption for a specified key size (`AES128KS`, `AES192KS` or `AES256KS`).

### `AESCrypto::AES_Decryption`
Handles AES decryption for a specified key size.

### `AESUtils`
Utility class for AES-specific operations:
- S-Box generation.
- Rijndael MixColumns and InvMixColumns constants.
- Secure key generation.

### `Test::CSPRNG`
A cryptographically secure pseudo-random number generator for key generation.

---

## Limitations

1. **Security**:
   - Does not protect against attacks such as side channel and cache based...
   
2. **CSPRNG on Windows**:
   - Windows uses a fallback Mersenne Twister PRNG, which provides lower entropy.

---

## Contributions

Contributions are welcome! If you encounter issues or have suggestions, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

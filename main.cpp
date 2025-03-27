
#include "aes.hpp"

int main() {

    #ifdef _AES_ENCRYPTION_ALGORITHM_

    // Create an instance of the AES_Encryption class
    AES::AES_Encryption_v1 aes;

    // Define the key (16 bytes for AES-128)
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0xcf, 0x7e, 0x15, 0x16, 0x28, 0xae
    };

    // Define the plaintext ("hello world")
    const char* plaintext = "hello world";
    size_t plaintext_len = strlen(plaintext);

    // Ensure the plaintext length is a multiple of 16 bytes (AES block size)
    size_t padded_len = ((plaintext_len + 15) / 16) * 16;
    uint8_t input[padded_len];
    memset(input, 0, padded_len);
    memcpy(input, plaintext, plaintext_len);

    // Define output buffers for encryption and decryption
    uint8_t encrypted[padded_len];
    uint8_t decrypted[padded_len];

    // Encrypt the plaintext
    aes.Encrypt(input, encrypted, key);
    std::cout << "Encrypted text: ";
    for (size_t i = 0; i < padded_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(encrypted[i]);
    }
    std::cout << std::endl;

    // Decrypt the ciphertext
    aes.Decrypt(encrypted, decrypted, key);
    std::cout << "Decrypted text: ";
    for (size_t i = 0; i < padded_len; ++i) {
        std::cout << decrypted[i];
    }
    std::cout << std::endl;


    {
        // Simpler version
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
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    }
    #endif

    return 0;
}

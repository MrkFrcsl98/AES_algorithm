#include <iostream>
#include <vector>
#include <string>
#include "aes.hpp"

int main() {
    std::string plaintext = "Stupid message to encrypt!";
    std::string key = AES::Utils::SecureKeyBlock(AES128KS); // Generate a random 128-bit key
    std::vector<byte> iv = AES::Utils::SecureIVBlock();      // Generate a random IV

    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Key (hex): " << AES::Result(std::vector<byte>(key.begin(), key.end())).toHex() << std::endl;
    std::cout << "IV (hex):  " << AES::Result(iv).toHex() << std::endl << std::endl;

    // ECB (no IV), AKA mode-less mode
    auto ecb_encrypted = AES::ECB::Encrypt(plaintext, key);
    auto ecb_decrypted = AES::ECB::Decrypt(ecb_encrypted.toVector(), key);

    // CBC
    auto cbc_encrypted = AES::CBC::Encrypt(plaintext, key, iv);
    auto cbc_decrypted = AES::CBC::Decrypt(cbc_encrypted.toVector(), key, iv);

    // CFB
    auto cfb_encrypted = AES::CFB::Encrypt(plaintext, key, iv);
    auto cfb_decrypted = AES::CFB::Decrypt(cfb_encrypted.toVector(), key, iv);

    // OFB
    auto ofb_encrypted = AES::OFB::Encrypt(plaintext, key, iv);
    auto ofb_decrypted = AES::OFB::Decrypt(ofb_encrypted.toVector(), key, iv);

    // CTR
    auto ctr_encrypted = AES::CTR::Encrypt(plaintext, key, iv);
    auto ctr_decrypted = AES::CTR::Decrypt(ctr_encrypted.toVector(), key, iv);

    // Print Encrypted data
    std::cout << "[ECB] Encrypted(Hex): " << ecb_encrypted.toHex() << std::endl;
    std::cout << "[CBC] Encrypted(Hex): " << cbc_encrypted.toHex() << std::endl;
    std::cout << "[CFB] Encrypted(Hex): " << cfb_encrypted.toHex() << std::endl;
    std::cout << "[OFB] Encrypted(Hex): " << ofb_encrypted.toHex() << std::endl;
    std::cout << "[CTR] Encrypted(Hex): " << ctr_encrypted.toHex() << std::endl;
    
    // Print the decrypted data
    std::cout << "[ECB] Decrypted: " << ecb_decrypted.toString() << std::endl;
    std::cout << "[CBC] Decrypted: " << cbc_decrypted.toString() << std::endl;
    std::cout << "[CFB] Decrypted: " << cfb_decrypted.toString() << std::endl;
    std::cout << "[OFB] Decrypted: " << ofb_decrypted.toString() << std::endl;
    std::cout << "[CTR] Decrypted: " << ctr_decrypted.toString() << std::endl;


    return 0;
}

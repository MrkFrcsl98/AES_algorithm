#include "aes.hpp"
#include <iomanip>
#include <iostream>

int main() {
  try {
    std::string plaintext = "this is a secret message sh!";
    std::string keyAES128 = AESUtils::genSecKeyBlock(128); // not the best security out there...
    std::string keyAES256 = AESUtils::genSecKeyBlock(256); // same shit... but im simulating a key generator, you would use a CSPRNG for this purpose

    // Print plaintext data
    std::cout << "Plaintext(Hex):        ";
    for (byte b : plaintext) {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
    }
    std::cout << "\n" << std::endl;

    // ---------------- AES 128 Encryption ---------------------
    { // Encrypt
      std::vector<byte> encryptedData;
      AESCrypto::AES_Encryption<AES128KS> encryptor(plaintext, encryptedData, keyAES128);

      // Print encrypted data
      std::cout << "AES128 Encrypted(Hex): ";
      for (byte b : encryptedData) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
      }
      std::cout << std::endl;

      // Decrypt
      std::vector<byte> decryptedData;
      std::string encryptedData2(encryptedData.begin(), encryptedData.end());
      AESCrypto::AES_Decryption<AES128KS> decryptor(encryptedData2, decryptedData, keyAES128);

      // Print decrypted data
      std::cout << "AES128 Decrypted(Hex): ";
      for (byte b : decryptedData) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
      }
      std::cout << "\n" << std::endl;
    }


    // ---------------- AES 256 Encryption ---------------------
    { // Encrypt
      std::vector<byte> encryptedData;
      AESCrypto::AES_Encryption<AES256KS> encryptor(plaintext, encryptedData, keyAES256);

      // Print encrypted data
      std::cout << "AES256 Encrypted(Hex): ";
      for (byte b : encryptedData) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
      }
      std::cout << std::endl;

      // Decrypt
      std::vector<byte> decryptedData;
      std::string encryptedData2(encryptedData.begin(), encryptedData.end());
      AESCrypto::AES_Decryption<AES256KS> decryptor(encryptedData2, decryptedData, keyAES256);

      // Print decrypted data
      std::cout << "AES256 Decrypted(Hex): ";
      for (byte b : decryptedData) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
      }
      std::cout << std::endl;
    }

    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}

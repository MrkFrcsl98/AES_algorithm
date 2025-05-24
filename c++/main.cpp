#include <iostream>
#include <vector>
#include <string>
#include "aes.hpp"

void print_bytes(const std::string& data) {
    for (const AES::byte b : data)
        std::cout << std::hex << std::uppercase << (int)b << " ";
    std::cout << std::dec << std::endl;
}

int main() {
    std::string key = AES::SecureByteGenerator::GenKeyBlock(AES::AES128KS).toString();
    std::string iv  = AES::SecureByteGenerator::GenIvBlock().toString();
    std::string plaintext = "Testing with parallel and serial encryption!";

    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Key (hex): ";
    print_bytes(key);
    std::cout << "IV  (hex): ";
    print_bytes(iv);

    // ECB Parallel
    auto ecb_par = AES::ECB::ParallelEncryption(plaintext, key);
    auto ecb_ser = AES::ECB::SerialEncryption(plaintext, key);

    std::cout << "\nECB Parallel ciphertext (hex): " << ecb_par.toHex() << std::endl;
    std::cout << "ECB Serial ciphertext  (hex): " << ecb_ser.toHex() << std::endl;

    auto decrypted_ecb_par = AES::ECB::ParallelDecryption(ecb_par.toVector(), key);
    auto decrypted_ecb_ser = AES::ECB::SerialDecryption(ecb_ser.toVector(), key);

    std::cout << "ECB Parallel Decrypted: " << decrypted_ecb_par.toString() << std::endl;
    std::cout << "ECB Serial Decrypted:   " << decrypted_ecb_ser.toString() << std::endl;

    // CBC Parallel
    auto cbc_par = AES::CBC::ParallelEncryption(plaintext, key, iv);
    auto cbc_ser = AES::CBC::SerialEncryption(plaintext, key, iv);

    std::cout << "\nCBC Parallel ciphertext (hex): " << cbc_par.toHex() << std::endl;
    std::cout << "CBC Serial ciphertext  (hex): " << cbc_ser.toHex() << std::endl;

    auto decrypted_cbc_par = AES::CBC::ParallelDecryption(cbc_par.toVector(), key, iv);
    auto decrypted_cbc_ser = AES::CBC::SerialDecryption(cbc_ser.toVector(), key, iv);

    std::cout << "CBC Parallel Decrypted: " << decrypted_cbc_par.toString() << std::endl;
    std::cout << "CBC Serial Decrypted:   " << decrypted_cbc_ser.toString() << std::endl;

    // CFB Parallel
    auto cfb_par = AES::CFB::ParallelEncryption(plaintext, key, iv);
    auto cfb_ser = AES::CFB::SerialEncryption(plaintext, key, iv);

    std::cout << "\nCFB Parallel ciphertext (hex): " << cfb_par.toHex() << std::endl;
    std::cout << "CFB Serial ciphertext  (hex): " << cfb_ser.toHex() << std::endl;

    auto decrypted_cfb_par = AES::CFB::ParallelDecryption(cfb_par.toVector(), key, iv);
    auto decrypted_cfb_ser = AES::CFB::SerialDecryption(cfb_ser.toVector(), key, iv);

    std::cout << "CFB Parallel Decrypted: " << decrypted_cfb_par.toString() << std::endl;
    std::cout << "CFB Serial Decrypted:   " << decrypted_cfb_ser.toString() << std::endl;

    // OFB Parallel
    auto ofb_par = AES::OFB::ParallelEncryption(plaintext, key, iv);
    auto ofb_ser = AES::OFB::SerialEncryption(plaintext, key, iv);

    std::cout << "\nOFB Parallel ciphertext (hex): " << ofb_par.toHex() << std::endl;
    std::cout << "OFB Serial ciphertext  (hex): " << ofb_ser.toHex() << std::endl;

    auto decrypted_ofb_par = AES::OFB::ParallelDecryption(ofb_par.toVector(), key, iv);
    auto decrypted_ofb_ser = AES::OFB::SerialDecryption(ofb_ser.toVector(), key, iv);

    std::cout << "OFB Parallel Decrypted: " << decrypted_ofb_par.toString() << std::endl;
    std::cout << "OFB Serial Decrypted:   " << decrypted_ofb_ser.toString() << std::endl;

    // CTR Parallel
    auto ctr_par = AES::CTR::ParallelEncryption(plaintext, key, iv);
    auto ctr_ser = AES::CTR::SerialEncryption(plaintext, key, iv);

    std::cout << "\nCTR Parallel ciphertext (hex): " << ctr_par.toHex() << std::endl;
    std::cout << "CTR Serial ciphertext  (hex): " << ctr_ser.toHex() << std::endl;

    auto decrypted_ctr_par = AES::CTR::ParallelDecryption(ctr_par.toVector(), key, iv);
    auto decrypted_ctr_ser = AES::CTR::SerialDecryption(ctr_ser.toVector(), key, iv);

    std::cout << "CTR Parallel Decrypted: " << decrypted_ctr_par.toString() << std::endl;
    std::cout << "CTR Serial Decrypted:   " << decrypted_ctr_ser.toString() << std::endl;

    return 0;
}

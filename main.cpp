
#include "aes.hpp"  
#include <iomanip> 
#include <iostream>  

namespace AES = AesCryptoModule;

// a function to print the result of the encryption operation...
static bool isEqual(const std::vector<byte>& o1, const std::vector<byte>& o2) {
    if(o1.size() != o2.size()) return false;
    for(int i = 0; i < o1.size(); ++i) {
       if(o1[i] != o2[i]) return false;   
    }
    return true;
}

int main(int argc, char **argv)
{
    try
    {       
        const uint8_t AES_KEY_SIZE    = 128;                                            // for AES-128 bits
        const AES::AESMode AES_MODE   = AES::AESMode::ECB;                              // define the mode of operation
        const std::string message     = "some random message to encrypt!";              // this is the message to encrypt
        const std::string seckey      = AES::AESUtils::genSecKeyBlock(AES_KEY_SIZE);    // this is the key for AES encryption/decryption

        AES::AES_Encryption<AES_KEY_SIZE, AES_MODE> Encryption; // instantiate AES encryption object
        AES::AES_Decryption<AES_KEY_SIZE, AES_MODE> Decryption; // instantiate AES decryption object

        const std::vector<byte> ENCRYPTED_DATA = Encryption.convert(message, seckey);                  // encrypt plaintext
        const std::vector<byte> DECRYPTED_DATA = Decryption.convert(ENCRYPTED_DATA, seckey);           // recover ciphertext

        // ------- PRINT RESULT: *OPTIONAL* ---------

        std::cout << "Original Data(Hex):  ";
        for(const byte b: message) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
        std::cout << std::endl;

        std::cout << "Encrypted Data(Hex): ";
        for(const byte b: ENCRYPTED_DATA) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
        std::cout << std::endl;

        std::cout << "Decrypted Data(Hex): ";
        for(const byte b: DECRYPTED_DATA) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
        std::cout << std::endl;

        // Verify result...
        std::cout << "result status: " << std::boolalpha << isEqual(DECRYPTED_DATA, std::vector<byte>(message.begin(), message.end())) << "\n";

    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

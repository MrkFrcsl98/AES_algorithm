#include "aes.hpp"
#include <iostream>
#include <iomanip>

int main()
{
    try
    {
        constexpr int SZ = 17;
        const char* input = {"message123456789"};
        const char* key = {"keykeykeykeykeyk"};
        __uint8T out[SZ], rev[SZ];

       std::cout << "Original Text(Hex):  ";
       for(int i = 0; i < SZ; ++i) 
       std::cout << std::setw(2) << std::hex << std::setfill('0') << (int)input[i] << " ";
       std::cout << std::endl;

       AESCrypto::AES_Encryption<128> aes(input, out, key);
       std::cout << "Encrypted Text(Hex): ";
       for(int i = 0; i < SZ; ++i) 
       std::cout << std::setw(2) << std::hex << std::setfill('0') << (int)out[i] << " ";
       std::cout << std::endl;

       AESCrypto::AES_Decryption<128> aesDec(reinterpret_cast<__ccptrT>(out), rev, key);
       std::cout << "Decrypted Text(Hex): ";
       for(int i = 0; i < SZ; ++i) 
       std::cout << std::setw(2) << std::hex << std::setfill('0') << (int)rev[i] << " ";
       std::cout << std::endl;

    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
    }

        return 0;
    };

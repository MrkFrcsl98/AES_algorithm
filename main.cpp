#include "aes.hpp"
#include <iostream>
#include <iomanip>

int main()
{
    try
    {
        const char* input = {"super secret message 0123456789"};
        const char* key = {"keykeykeykeykeykkeykeykeykeykeyk"};
        const __uint64T byte_size = AESCrypto::getByteSize(input);
         

       std::cout << "Original  Text(Hex)(" << std::dec << (int)byte_size << "): ";
       for(int i = 0; i < byte_size; ++i) 
       std::cout << std::setw(2) << std::hex << std::setfill('0') << (int)input[i] << " ";
       std::cout << std::endl;

       constexpr __uint16T KEY_SIZE = 128;

       AESCrypto::AES_Encryption<KEY_SIZE> encryption(input, key);
       Sequence<__uint8T> _out = encryption.invoke();
       std::cout << "Encrypted Text(Hex)(" <<std::dec << (int)_out.size << "): ";
       for(int i = 0; i < _out.size; ++i) 
       std::cout << std::setw(2) << std::hex << std::setfill('0') << (int)_out[i] << " ";
       std::cout << std::endl;
       AESCrypto::AES_Decryption<KEY_SIZE> decryption(reinterpret_cast<__ccptrT>(_out.data), key);
       Sequence<__uint8T> _rev = decryption.invoke();
       std::cout << "Decrypted Text(Hex)(" << std::dec << (int)_rev.size << "): ";
       for(int i = 0; i < _rev.size; ++i) 
       std::cout << std::setw(2) << std::hex << std::setfill('0') << (int)_rev[i] << " ";
       std::cout << std::endl;


    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
    }

        return 0;
    };

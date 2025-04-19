#include "aes.hpp"
#include <iomanip>
#include <iostream>

static constexpr __uint16T KEY_SIZE = 128u;

int main() {
  try {
    const char *input         = {"super secret message 0123456789"};
    const char *key           = {"keykeykeykeykeyk"};
    const __uint64T byte_size = AESCrypto::getByteSize(input);

    std::cout << "Original  Text(Ascii): " << input << "\n";

    /** Encryption */
    AESCrypto::AES_Encryption<KEY_SIZE> encryption(input, key);
    Sequence<__uint8T> encrypted = encryption.invoke();
    std::cout << "Encrypted Text(Ascii): " << encrypted.data << "\n";

    /** Decryption */
    AESCrypto::AES_Decryption<KEY_SIZE> decryption(reinterpret_cast<__ccptrT>(encrypted.data), key);
    Sequence<__uint8T> decrypted = decryption.invoke();
    std::cout << "Decrypted Text(Ascii): " << decrypted.data << "\n";

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
  }

  return 0;
};

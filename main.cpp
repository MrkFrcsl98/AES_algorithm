#include "aes.hpp" // the implementation of aes

int main() {
  try {

    AesCryptoModule::Test::runGlobal();
    
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}

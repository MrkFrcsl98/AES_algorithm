#include "aes.hpp" // the implementation of aes
#include <chrono>
#include <fstream> // basically for the CSPRNG operation
#include <iomanip> // needed to print as hex format
#include <iostream> // required for the CSPRNG function
#include <thread> // for std::this_thread::sleep_for(...)


/**
 *  ***** NOTE *****
 *  ******************************** FOR LINUX ONLY ***********************************
 *  ***** !!!! *****
 */

#if defined(__linux__) || defined(__unix__) || defined(__unix)


// im writing this simple but more secure CSPRNG utility class to generate secure 
// keys(at least more random than mersenne generations), im doing this because i noticed 
// that the function from AESUtils::genSecKeyBlock that i wrote produces non-random bytes at all...
// this should provide higher entropy, but still, only for educational purposes!
class CSPRNG {
public:
  explicit CSPRNG() noexcept {};

  ~CSPRNG() noexcept {};

  static const size_t generate(const size_t min, const size_t max) {
    int bytes = 0;
    try {
      CSPRNG::_entropy_collect_source();
      if (CSPRNG::_sEntropy.urandom.empty())
        return 0;
      size_t state{0};
      for (auto c : CSPRNG::_sEntropy.urandom) {
        state += (int)c;
      }
      state += state + std::time(nullptr) / 2;

      // now basically is doing some PRNG XorShift operation on the state
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      bytes = min + (state % (max - min + 1));
    } catch (const std::exception &e) {
      std::cerr << "CSPRNG Error: " << e.what() << "\n";
    }
    return bytes;
  };

  static const std::string genSecKeyBlock(const uint16_t key_size) {
    const char alpha[26 * 2 + 12] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                     'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                                     'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '.', ',', '!', '@', '#', '$', '%', '^', '&', '*', '+', '-'};
    if (key_size != AES128KS && key_size != AES256KS && key_size != AES192KS)
      return "";
    std::string seckey;
    seckey.resize(key_size / 8);
    uint16_t c = 0;
    while (c < key_size / 8) {
      seckey[c++] = alpha[CSPRNG::generate(0, 26 * 2 + 11)];
    }
    return seckey;
  };

  struct entropySource {
    std::string urandom{};
  };

  static struct entropySource _sEntropy;

  static void _entropy_collect_source() { CSPRNG::_read_urandom(); };

  static void _read_urandom() __attribute__((hot, stack_protect)) {
    // hope you got this location on your device, otherwise you are SCREWED...
    std::ifstream FILE("/dev/urandom", std::ios::binary);
    if (!FILE.is_open()) {
      std::string errmsg("Error Code: ");
      errmsg += strerror(errno);
      errmsg += ", Cannot Open File /dev/urandom";
      throw std::runtime_error("Cannot open file /dev/urandom !!");
    }
    const unsigned short int THRESHOLD = 32;
    unsigned short int byte_count = 0;
    std::array<unsigned char, THRESHOLD> fileContent;
    std::string hexBytes;
    char bytes_read;
    FILE.read(reinterpret_cast<char *>(fileContent.data()), THRESHOLD);
    bytes_read = FILE.gcount();
    hexBytes.reserve(fileContent.size() * 2);
    if (fileContent.size() > 0 && fileContent.size() <= THRESHOLD) {
      for (unsigned short int i = 0; i < bytes_read; ++i) {
        _sEntropy.urandom += fileContent[i];
      }
    }
  };
};

struct CSPRNG::entropySource CSPRNG::_sEntropy = {};

static const std::string cPlaintext("this is a secret message to deliver!");
static std::string plaintext(cPlaintext.begin(), cPlaintext.begin()+1);
static std::string keyAES128(CSPRNG::genSecKeyBlock(128)); // not the best security out there...
static std::string keyAES192(CSPRNG::genSecKeyBlock(192));
static std::string keyAES256(CSPRNG::genSecKeyBlock(256)); // same shit... but im simulating a key generator, you would use a CSPRNG for this purpose

static size_t tscore = 3; // for 3 test cases(128, 192, 256) starting from index 0
static size_t S_THRESHOLD = 0;

static constexpr size_t exec_delay = 20; // set the delay between each execution(ms)

// defining the AES instances that will be used later
AESCrypto::AES_Encryption<AES128KS> aes128Encryptor;
AESCrypto::AES_Encryption<AES192KS> aes192Encryptor;
AESCrypto::AES_Encryption<AES256KS> aes256Encryptor;


AESCrypto::AES_Decryption<AES128KS> aes128Decryptor;
AESCrypto::AES_Decryption<AES192KS> aes192Decryptor;
AESCrypto::AES_Decryption<AES256KS> aes256Decryptor;

static void printPlaintext() {
  std::cout << "Plaintext(Hex):        ";
  for (byte b : plaintext) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
  }
  std::cout << "\n" << std::endl;
};

static void printResult(const std::string_view l, const std::vector<byte> &data) {
  std::cout << l;
  for (byte b : data) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
  }
  std::cout << std::endl;
  std::this_thread::sleep_for(std::chrono::milliseconds(exec_delay));
};

static void runAesTest(const uint16_t ks) {
  std::vector<byte> encryptedData, decryptedData;
  if (ks == AES128KS) {
    encryptedData = aes128Encryptor.call(plaintext, keyAES128);
    decryptedData = aes128Decryptor.call(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
    printResult("AES128 Encrypted(Hex): ", encryptedData);
    printResult("AES128 Decrypted(Hex): ", decryptedData);
    tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
  } else if(ks == AES192KS) {
    encryptedData = aes192Encryptor.call(plaintext, keyAES192);
    decryptedData = aes192Decryptor.call(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
    printResult("AES192 Encrypted(Hex): ", encryptedData);
    printResult("AES192 Decrypted(Hex): ", decryptedData);
    tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
  }else{
    encryptedData = aes256Encryptor.call(plaintext, keyAES256);
    decryptedData = aes256Decryptor.call(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
    printResult("AES256 Encrypted(Hex): ", encryptedData);
    printResult("AES256 Decrypted(Hex): ", decryptedData);
    tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
  }
};

void runTest() {
  // test case for all aes Key sizes, run a loop of size plaintext.length() for each key size,
  // starting from index 1 up to pt.size, to test how the implementation behaves on different
  // data lengths, each iteration will generate a new key using my custom created CSPRNG
  // class(not the best thing you will see btw... but it works so far), and through 
  // each iteration the plaintext(data) will be the previous one plus 1 more byte from 
  // the original data.
  const uint16_t threshold = cPlaintext.length();
  uint16_t c = 0;
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin()+c);
    keyAES128 = CSPRNG::genSecKeyBlock(128);
    runAesTest(128);
  }
  S_THRESHOLD += c; // updating threshold of score counter ...

  c = 0; // reset iteration counter for the next case
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin()+c);
    keyAES192 = CSPRNG::genSecKeyBlock(192);
    runAesTest(192);
  }
  S_THRESHOLD += c;

  c = 0;
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin()+c);
    keyAES256 = CSPRNG::genSecKeyBlock(256);
    runAesTest(256);
  }
  S_THRESHOLD += c;
};

int main() {
  try {
    printPlaintext();
    runTest();
    std::cout << "Test Execution Finished... total tests passed = " << std::dec << (int)tscore << "/" << (int)S_THRESHOLD << "\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}

#else
int main(){
  std::cout << "You are not on Unix architecture... sorry!!\n";
  return 0;
}
#endif

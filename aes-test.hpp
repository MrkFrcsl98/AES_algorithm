#pragma once

#include <fstream>     // for the CSPRNG readFILE operation
#include "aes.hpp"

namespace AESTest
{


class CSPRNG;

// implementing slightly more secure version of a PRNG for unix like OSs, because i dont know how to do that
// for windows ...
#if defined(__linux__) || defined(__unix) || defined(__unix__)
// im writing this simple but more secure CSPRNG utility class to generate secure
// keys(at least more random than mersenne generations), im doing this because i noticed
// that the function from AESUtils::genSecKeyBlock that i wrote produces non-random bytes at all...
// this should provide higher entropy, but still, only for educational purposes!
class CSPRNG
{
  public:
    explicit CSPRNG() noexcept {};

    ~CSPRNG() noexcept {};

    static const size_t generate(const size_t min, const size_t max)
    {
        int bytes = 0;
        try
        {
            CSPRNG::_entropy_collect_source();
            if (CSPRNG::_sEntropy.urandom.empty())
                return 0;
            size_t state{0};
            for (auto c : CSPRNG::_sEntropy.urandom)
            {
                state += (int)c;
            }
            state += state + std::time(nullptr) / 2;

            // now basically is doing some PRNG XorShift operation on the state
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes = min + (state % (max - min + 1));
        }
        catch (const std::exception &e)
        {
            std::cerr << "CSPRNG Error: " << e.what() << "\n";
        }
        return bytes;
    };

    static const std::string genSecKeyBlock(const uint16_t key_size)
    {
        if (key_size != AES128KS && key_size != AES256KS && key_size != AES192KS)
            return "";
        std::string seckey;
        seckey.resize(key_size / 8);
        uint16_t c = 0;
        while (c < key_size / 8)
        {
            seckey[c++] = CSPRNG::generate(0, 255);
        }
        return seckey;
    };

    struct entropySource
    {
        std::string urandom{};
    };

    static struct entropySource _sEntropy;

    static void _entropy_collect_source()
    {
        CSPRNG::_read_urandom();
    };

    static void _read_urandom() __attribute__((hot, stack_protect))
    {
        std::ifstream FILE("/dev/urandom", std::ios::binary);
        if (!FILE.is_open())
        {
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
        if (fileContent.size() > 0 && fileContent.size() <= THRESHOLD)
        {
            for (unsigned short int i = 0; i < bytes_read; ++i)
            {
                _sEntropy.urandom += fileContent[i];
            }
        }
    };
};

struct CSPRNG::entropySource CSPRNG::_sEntropy = {};

#else
// windows will use a less efficient version of CSPRNG , why? because im not a windows user...
// here will use a mersenne twister PRNG instead...
class CSPRNG
{
  public:
    explicit CSPRNG() noexcept {};
    ~CSPRNG() noexcept = default;
    static const std::string genSecKeyBlock(const uint16_t ks)
    {
        return AESUtils::genSecKeyBlock(ks);
    };
};

#endif

static const std::string cPlaintext("this is a secret message!");
static std::string plaintext(cPlaintext.begin(), cPlaintext.begin() + 1);
static std::string keyAES128(CSPRNG::genSecKeyBlock(128));
static std::string keyAES192(CSPRNG::genSecKeyBlock(192));
static std::string keyAES256(CSPRNG::genSecKeyBlock(256));
static std::vector<byte> IV(IV_BLOCK_SIZE), authTag(IV_BLOCK_SIZE);

static size_t tscore = 3 * 5;
static size_t S_THRESHOLD = 0;

static constexpr size_t exec_delay = 10; // delay between each execution(ms)

// AES ECB Mode, multiple key size constructors
AesCryptoModule::AES_Encryption<AES128KS, AesCryptoModule::AESMode::ECB> aesECB128Encryptor;
AesCryptoModule::AES_Encryption<AES192KS, AesCryptoModule::AESMode::ECB> aesECB192Encryptor;
AesCryptoModule::AES_Encryption<AES256KS, AesCryptoModule::AESMode::ECB> aesECB256Encryptor;

AesCryptoModule::AES_Decryption<AES128KS, AesCryptoModule::AESMode::ECB> aesECB128Decryptor;
AesCryptoModule::AES_Decryption<AES192KS, AesCryptoModule::AESMode::ECB> aesECB192Decryptor;
AesCryptoModule::AES_Decryption<AES256KS, AesCryptoModule::AESMode::ECB> aesECB256Decryptor;

// AES ECB Mode, multiple key size constructors
AesCryptoModule::AES_Encryption<AES128KS, AesCryptoModule::AESMode::CBC> aesCBC128Encryptor;
AesCryptoModule::AES_Encryption<AES192KS, AesCryptoModule::AESMode::CBC> aesCBC192Encryptor;
AesCryptoModule::AES_Encryption<AES256KS, AesCryptoModule::AESMode::CBC> aesCBC256Encryptor;

AesCryptoModule::AES_Decryption<AES128KS, AesCryptoModule::AESMode::CBC> aesCBC128Decryptor;
AesCryptoModule::AES_Decryption<AES192KS, AesCryptoModule::AESMode::CBC> aesCBC192Decryptor;
AesCryptoModule::AES_Decryption<AES256KS, AesCryptoModule::AESMode::CBC> aesCBC256Decryptor;

AesCryptoModule::AES_Encryption<AES128KS, AesCryptoModule::AESMode::CTR> aesCTR128Encryptor;
AesCryptoModule::AES_Encryption<AES192KS, AesCryptoModule::AESMode::CTR> aesCTR192Encryptor;
AesCryptoModule::AES_Encryption<AES256KS, AesCryptoModule::AESMode::CTR> aesCTR256Encryptor;

AesCryptoModule::AES_Decryption<AES128KS, AesCryptoModule::AESMode::CTR> aesCTR128Decryptor;
AesCryptoModule::AES_Decryption<AES192KS, AesCryptoModule::AESMode::CTR> aesCTR192Decryptor;
AesCryptoModule::AES_Decryption<AES256KS, AesCryptoModule::AESMode::CTR> aesCTR256Decryptor;

AesCryptoModule::AES_Encryption<AES128KS, AesCryptoModule::AESMode::OFB> aesOFB128Encryptor;
AesCryptoModule::AES_Encryption<AES192KS, AesCryptoModule::AESMode::OFB> aesOFB192Encryptor;
AesCryptoModule::AES_Encryption<AES256KS, AesCryptoModule::AESMode::OFB> aesOFB256Encryptor;

AesCryptoModule::AES_Decryption<AES128KS, AesCryptoModule::AESMode::OFB> aesOFB128Decryptor;
AesCryptoModule::AES_Decryption<AES192KS, AesCryptoModule::AESMode::OFB> aesOFB192Decryptor;
AesCryptoModule::AES_Decryption<AES256KS, AesCryptoModule::AESMode::OFB> aesOFB256Decryptor;

AesCryptoModule::AES_Encryption<AES128KS, AesCryptoModule::AESMode::CFB> aesCFB128Encryptor;
AesCryptoModule::AES_Encryption<AES192KS, AesCryptoModule::AESMode::CFB> aesCFB192Encryptor;
AesCryptoModule::AES_Encryption<AES256KS, AesCryptoModule::AESMode::CFB> aesCFB256Encryptor;

AesCryptoModule::AES_Decryption<AES128KS, AesCryptoModule::AESMode::CFB> aesCFB128Decryptor;
AesCryptoModule::AES_Decryption<AES192KS, AesCryptoModule::AESMode::CFB> aesCFB192Decryptor;
AesCryptoModule::AES_Decryption<AES256KS, AesCryptoModule::AESMode::CFB> aesCFB256Decryptor;

static void printPlaintext()
{
    std::cout << "Plaintext(Ascii):      " << cPlaintext << "\n";
    std::cout << "Plaintext(Hex):        ";
    for (byte b : cPlaintext)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
    }
    std::cout << "\n" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));
};

static void printResult(const std::string_view l, const std::vector<byte> &data)
{
    std::cout << l;
    for (byte b : data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
    }
    std::cout << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(exec_delay));
};

static void runAesTest(const uint16_t ks, const AesCryptoModule::AESMode MODE = AesCryptoModule::AESMode::ECB)
{
using namespace AesCryptoModule;
    std::vector<byte> encryptedData, decryptedData;
    const std::string model(
        MODE == AesCryptoModule::AESMode::ECB ? "ECB"
                             : (MODE == AesCryptoModule::AESMode::CBC ? "CBC" : (MODE == AesCryptoModule::AESMode::CFB ? "CFB" : (MODE == AesCryptoModule::AESMode::CTR ? "CTR" : (MODE == AesCryptoModule::AESMode::OFB ? "OFB" : "GCM")))));

    if (ks == AES128KS)
    {
        if (MODE == AesCryptoModule::AESMode::ECB)
        {
            encryptedData = aesECB128Encryptor.apply(plaintext, keyAES128);
            decryptedData = aesECB128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
        }
        else if (MODE == AesCryptoModule::AESMode::CBC)
        {
            aesCBC128Encryptor.iv = IV;
            encryptedData = aesCBC128Encryptor.apply(plaintext, keyAES128);
            aesCBC128Decryptor.iv = IV;
            decryptedData = aesCBC128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
        }
        else if (MODE == AesCryptoModule::AESMode::CTR)
        {
            std::vector<byte> iv = IV;
            aesCTR128Encryptor.iv = iv;
            encryptedData = aesCTR128Encryptor.apply(plaintext, keyAES128);
            iv = IV;
            aesCTR128Decryptor.iv = iv;
            decryptedData = aesCTR128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
        }
        else if (MODE == AesCryptoModule::AESMode::OFB)
        {
            std::vector<byte> iv = IV;
            aesOFB128Encryptor.iv = iv;
            encryptedData = aesOFB128Encryptor.apply(plaintext, keyAES128);
            iv = IV;
            aesOFB128Decryptor.iv = iv;
            decryptedData = aesOFB128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
        }
        else if (MODE == AesCryptoModule::AESMode::CFB)
        {
            std::vector<byte> iv = IV;
            aesCFB128Encryptor.iv = iv;
            encryptedData = aesCFB128Encryptor.apply(plaintext, keyAES128);
            iv = IV;
            aesCFB128Decryptor.iv = iv;
            decryptedData = aesCFB128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
        }
        printResult(std::string("AES(128) ") += model + " -> Encrypted(Hex): ", encryptedData);
        printResult(std::string("AES(128) ") += model + " -> Decrypted(Hex): ", decryptedData);
        if (std::string(decryptedData.begin(), decryptedData.end()) != plaintext)
        {
            std::cout << "Error AES 128 " << model << "\n";
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
    }
    else if (ks == AES192KS)
    {
        if (MODE == AesCryptoModule::AESMode::ECB)
        {
            encryptedData = aesECB192Encryptor.apply(plaintext, keyAES192);
            decryptedData = aesECB192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
        }
        else if (MODE == AesCryptoModule::AESMode::CBC)
        {
            aesCBC192Encryptor.iv = IV;
            encryptedData = aesCBC192Encryptor.apply(plaintext, keyAES192);
            aesCBC192Decryptor.iv = IV;
            decryptedData = aesCBC192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
        }
        else if (MODE == AesCryptoModule::AESMode::CTR)
        {
            aesCTR192Encryptor.iv = IV;
            encryptedData = aesCTR192Encryptor.apply(plaintext, keyAES192);
            aesCTR192Decryptor.iv = IV;
            decryptedData = aesCTR192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
        }
        else if (MODE == AesCryptoModule::AESMode::OFB)
        {
            std::vector<byte> iv = IV;
            aesOFB192Encryptor.iv = iv;
            encryptedData = aesOFB192Encryptor.apply(plaintext, keyAES192);
            iv = IV;
            aesOFB192Decryptor.iv = iv;
            decryptedData = aesOFB192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
        }
        else if (MODE == AesCryptoModule::AESMode::CFB)
        {
            std::vector<byte> iv = IV;
            aesCFB192Encryptor.iv = iv;
            encryptedData = aesCFB192Encryptor.apply(plaintext, keyAES192);
            iv = IV;
            aesCFB192Decryptor.iv = iv;
            decryptedData = aesCFB192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
        }
        printResult(std::string("AES(192) ") += model + " -> Encrypted(Hex): ", encryptedData);
        printResult(std::string("AES(192) ") += model + " -> Decrypted(Hex): ", decryptedData);
        if (std::string(decryptedData.begin(), decryptedData.end()) != plaintext)
        {
            std::cout << "Error AES 192 " << model << "\n";
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
    }
    else
    {
        if (MODE == AesCryptoModule::AESMode::ECB)
        {
            encryptedData = aesECB256Encryptor.apply(plaintext, keyAES256);
            decryptedData = aesECB256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
        }
        else if (MODE == AesCryptoModule::AESMode::CBC)
        {
            aesCBC256Encryptor.iv = IV;
            encryptedData = aesCBC256Encryptor.apply(plaintext, keyAES256);
            aesCBC256Decryptor.iv = IV;
            decryptedData = aesCBC256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
        }
        else if (MODE == AesCryptoModule::AESMode::CTR)
        {
            aesCTR256Encryptor.iv = IV;
            encryptedData = aesCTR256Encryptor.apply(plaintext, keyAES256);
            aesCTR256Decryptor.iv = IV;
            decryptedData = aesCTR256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
        }
        else if (MODE == AesCryptoModule::AESMode::OFB)
        {
            std::vector<byte> iv = IV;
            aesOFB256Encryptor.iv = iv;
            encryptedData = aesOFB256Encryptor.apply(plaintext, keyAES256);
            iv = IV;
            aesOFB256Decryptor.iv = iv;
            decryptedData = aesOFB256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
        }
        else if (MODE == AesCryptoModule::AESMode::CFB)
        {
            std::vector<byte> iv = IV;
            aesCFB256Encryptor.iv = iv;
            encryptedData = aesCFB256Encryptor.apply(plaintext, keyAES256);
            iv = IV;
            aesCFB256Decryptor.iv = iv;
            decryptedData = aesCFB256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
        }
        printResult(std::string("AES(256) ") += model + " -> Encrypted(Hex): ", encryptedData);
        printResult(std::string("AES(256) ") += model + " -> Decrypted(Hex): ", decryptedData);
        if (std::string(decryptedData.begin(), decryptedData.end()) != plaintext)
        {
            std::cout << "Error AES 256 " << model << "\n";
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
    }
};

static const uint16_t threshold = cPlaintext.length();
static uint16_t c = 0;

static void execAES128(const AesCryptoModule::AESMode M)
{
    using namespace AesCryptoModule;
    c = 0;
    while (++c < threshold)
    {
        plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
        keyAES128 = CSPRNG::genSecKeyBlock(128);
        IV = AESUtils::GenIvBlock(IV_BLOCK_SIZE);
        runAesTest(128, M);
    }
    S_THRESHOLD += c;
};

static void execAES192(const AesCryptoModule::AESMode M)
{
    using namespace AesCryptoModule;
    c = 0;
    while (++c < threshold)
    {
        plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
        keyAES192 = CSPRNG::genSecKeyBlock(192);
        IV = AESUtils::GenIvBlock(IV_BLOCK_SIZE);
        runAesTest(192, M);
    }
    S_THRESHOLD += c;
};

static void execAES256(const AesCryptoModule::AESMode M)
{
    using namespace AesCryptoModule;
    c = 0;
    while (++c < threshold)
    {
        plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
        keyAES256 = CSPRNG::genSecKeyBlock(256);
        IV = AESUtils::GenIvBlock(IV_BLOCK_SIZE);
        runAesTest(256, M);
    }
    S_THRESHOLD += c;
};

static void run_AES_ECB_test()
{
    using namespace AesCryptoModule;
    std::cout << "\n*********** Execute AES ECB Mode ***********\n";
    std::thread([&] { execAES128(AesCryptoModule::AESMode::ECB); }).join();
    std::thread([&] { execAES192(AesCryptoModule::AESMode::ECB); }).join();
    std::thread([&] { execAES256(AesCryptoModule::AESMode::ECB); }).join();
};

static void run_AES_CBC_test()
{using namespace AesCryptoModule;
    std::cout << "\n*********** Execute AES CBC Mode ***********\n";
    std::thread([&] { execAES128(AesCryptoModule::AESMode::CBC); }).join();
    std::thread([&] { execAES192(AesCryptoModule::AESMode::CBC); }).join();
    std::thread([&] { execAES256(AesCryptoModule::AESMode::CBC); }).join();
};

static void run_AES_CTR_test()
{using namespace AesCryptoModule;
    std::cout << "\n*********** Execute AES CTR Mode ***********\n";
    std::thread([&] { execAES128(AesCryptoModule::AESMode::CTR); }).join();
    std::thread([&] { execAES192(AesCryptoModule::AESMode::CTR); }).join();
    std::thread([&] { execAES256(AesCryptoModule::AESMode::CTR); }).join();
}

static void run_AES_OFB_test()
{using namespace AesCryptoModule;
    std::cout << "\n*********** Execute AES OFB Mode ***********\n";
    std::thread([&] { execAES128(AesCryptoModule::AESMode::OFB); }).join();
    std::thread([&] { execAES192(AesCryptoModule::AESMode::OFB); }).join();
    std::thread([&] { execAES256(AesCryptoModule::AESMode::OFB); }).join();
}

static void run_AES_CFB_test()
{using namespace AesCryptoModule;
    std::cout << "\n*********** Execute AES CFB Mode ***********\n";
    std::thread([&] { execAES128(AesCryptoModule::AESMode::CFB); }).join();
    std::thread([&] { execAES192(AesCryptoModule::AESMode::CFB); }).join();
    std::thread([&] { execAES256(AesCryptoModule::AESMode::CFB); }).join();
}

// run aes in all modes(ECB, CBC, OFB, CTR, CFB)
static void runGlobal()
{

    printPlaintext();

    run_AES_ECB_test();
    run_AES_CBC_test();
    run_AES_CTR_test();
    run_AES_OFB_test();
    run_AES_CFB_test();

    std::cout << "Tests Finished... total tests passed = " << std::dec << (int)tscore << "/" << (int)S_THRESHOLD << "\n";
};

}; // namespace Test

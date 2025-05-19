#pragma once
#include <algorithm> // used for std::transform, etc...
#include <array>     // for fixed size arrays
#include <chrono>
#include <cstring>     // for something...
#include <ctime>       // for CSPRNG state value(seed)
#include <stdexcept>   // exceptions
#include <string>      // std::string
#include <type_traits> // for some type trait implementation
#include <vector>      // dynamic memory allocation sequence

#ifndef __MFAES_BLOCK_CIPHER_lbv01__
#define __MFAES_BLOCK_CIPHER_lbv01__ 0x01

constexpr uint16_t AES128KS = 0x80;
constexpr uint16_t AES192KS = 0xC0;
constexpr uint16_t AES256KS = 0x100;
constexpr uint8_t AES128_ROUNDS = 0x0A;
constexpr uint8_t AES192_ROUNDS = 0x0C;
constexpr uint8_t AES256_ROUNDS = 0x0E;
constexpr uint8_t IV_BLOCK_SIZE = 0x10;
constexpr uint8_t AES_BLOCK_SIZE = 0x10;

using byte = uint8_t;

namespace AesCryptoModule
{

class PRNG
{
  private:
    static constexpr size_t N = 0x270;
    static constexpr size_t M = 0x17B;
    static constexpr size_t MATRIX_A = 0x9908b0dfUL;
    static constexpr size_t UPPER_MASK = 0x80000000UL;
    static constexpr size_t LOWER_MASK = 0x7fffffffUL;

    size_t state;
    std::array<size_t, N> mt;
    int mti;

    void init_mersenne_twister(size_t seed)
    {
        mt[0] = seed;
        for (mti = 1; mti < N; mti++)
        {
            mt[mti] = (1812433253UL * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + mti);
        }
    }

  public:
    PRNG(size_t seed = std::time(nullptr), size_t sequence = 1) : state(seed), mti(N)
    {
        init_mersenne_twister(seed);
    };

    __attribute__((cold)) const size_t MersenneTwister(const size_t min, const size_t max)
    {
        if (min >= max) [[unlikely]]
            throw std::invalid_argument("min must be less than max");
        size_t y;
        static const size_t mag01[2] = {0x0UL, MATRIX_A};
        if (mti >= N)
        {
            int kk;
            for (kk = 0; kk < N - M; kk++)
            {
                y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1UL];
            }
            for (; kk < N - 1; kk++)
            {
                y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                mt[kk] = mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
            }
            y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
            mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ mag01[y & 0x1UL];
            mti = 0;
        }
        y = mt[mti++];
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680UL;
        y ^= (y << 15) & 0xefc60000UL;
        y ^= (y >> 18);
        return min + (y % (max - min + 1));
    };

    __attribute__((cold)) void reseed(size_t new_seed)
    {
        state = new_seed;
        init_mersenne_twister(new_seed);
    };
};

class AESUtils
{
  public:
    AESUtils() = default;
    AESUtils(const AESUtils &c) = delete;
    AESUtils(AESUtils &&c) = delete;
    ~AESUtils() = default;

    __attribute__((hot, pure, nothrow)) static inline constexpr byte galloisFieldMultiplication(byte a, byte b) noexcept
    {
        byte p = 0;
        for (uint16_t i = 0; i < 8; ++i)
        {
            if (b & 1)
            {
                p ^= a;
            }
            bool hiBitSet = (a & 0x80);
            a <<= 1;
            if (hiBitSet)
            {
                a ^= 0x1B; // 0x1B is the irreducible polynomial for AES
            }
            b >>= 1;
        }
        return p;
    }

    __attribute__((hot, pure, nothrow)) inline static constexpr byte galloisFieldInverse(byte x) noexcept
    {
        byte y = x;
        for (uint16_t i = 0; i < 4; ++i)
        {
            y = galloisFieldMultiplication(y, y);
            y = galloisFieldMultiplication(y, x);
        }
        return y;
    }

    __attribute__((hot, pure, nothrow)) inline static constexpr byte affineTransform(byte x) noexcept
    {
        byte result = 0x63;
        for (uint16_t i = 0; i < 8; ++i)
        {
            result ^= (x >> i) & 1 ? (0xF1 >> (7 - i)) & 0xFF : 0;
        }
        return result;
    }

    __attribute__((cold, pure, nothrow)) static constexpr byte createSBoxEntry(byte x) noexcept
    {
        return affineTransform(galloisFieldInverse(x));
    }

    __attribute__((cold, leaf, nothrow)) inline static constexpr void createSBox(std::array<byte, 256> &sbox) noexcept
    {
        for (uint16_t i = 0; i < 256; ++i)
        {
            sbox[i] = createSBoxEntry(static_cast<byte>(i));
        }
    }

    __attribute__((cold, leaf, nothrow)) static constexpr void createInvSBox(const std::array<byte, 256> &sbox, std::array<byte, 256> &invSbox) noexcept
    {
        for (uint16_t i = 0; i < 256; ++i)
        {
            invSbox[sbox[i]] = static_cast<byte>(i);
        }
    }

    __attribute__((cold, nothrow)) static constexpr void createRCon(std::array<byte, 256> &rcon) noexcept
    {
        byte c = 1;
        for (uint16_t i = 0; i < 256; ++i)
        {
            rcon[i] = c;
            c = galloisFieldMultiplication(c, 0x02);
        }
    }

    __attribute__((cold, leaf, nothrow)) static constexpr void createMixCols(std::array<std::array<byte, 4>, 4> &mixCols) noexcept
    {
        mixCols[0] = {0x02, 0x03, 0x01, 0x01};
        mixCols[1] = {0x01, 0x02, 0x03, 0x01};
        mixCols[2] = {0x01, 0x01, 0x02, 0x03};
        mixCols[3] = {0x03, 0x01, 0x01, 0x02};
    }

    __attribute__((cold, leaf, nothrow)) static constexpr void createInvMixCols(std::array<std::array<byte, 4>, 4> &invMixCols) noexcept
    {
        invMixCols[0] = {0x0E, 0x0B, 0x0D, 0x09};
        invMixCols[1] = {0x09, 0x0E, 0x0B, 0x0D};
        invMixCols[2] = {0x0D, 0x09, 0x0E, 0x0B};
        invMixCols[3] = {0x0B, 0x0D, 0x09, 0x0E};
    }

    __attribute__((cold)) static const std::string genSecKeyBlock(const uint16_t key_size)
    {

        if (key_size != AES128KS && key_size != AES256KS && key_size != AES192KS)
            return "";
        std::string seckey;
        seckey.resize(key_size / 8);
        uint16_t c = 0;
        PRNG generator;
        while (c < key_size / 8)
        {
            seckey[c++] = generator.MersenneTwister(0, 255);
        }
        return seckey;
    };

    static const std::vector<byte> GenIvBlock(const uint16_t size)
    {
        std::vector<byte> iv(size, 0);
        PRNG generator;
        for (auto &b : iv)
        {
            b = generator.MersenneTwister(0, 255);
        }
        return iv;
    };

    static std::array<byte, 256> SBox;
    static std::array<byte, 256> InvSBox;
    static std::array<byte, 256> RCon;
    static std::array<std::array<byte, 4>, 4> MixCols;
    static std::array<std::array<byte, 4>, 4> InvMixCols;
};

std::array<byte, 256> AESUtils::SBox = {};
std::array<byte, 256> AESUtils::InvSBox = {};
std::array<byte, 256> AESUtils::RCon = {};
std::array<std::array<byte, 4>, 4> AESUtils::MixCols = {};
std::array<std::array<byte, 4>, 4> AESUtils::InvMixCols = {};

constexpr unsigned short int Nb = (0b0001 << 0b0010);
constexpr unsigned short int AES128_BLOCK_CIPHER = (0b0001 << 0b0111);
struct AesParameters
{
    std::vector<uint16_t> data;
    std::vector<uint16_t> key;
};

template <uint16_t AES_KEY_SIZE> struct IsValidBlockSize
{
    static constexpr bool value = (AES_KEY_SIZE == AES128KS || AES_KEY_SIZE == AES192KS || AES_KEY_SIZE == AES256KS);
};

enum AESMode
{
    ECB = 0,
    CBC = 1,
    CFB = 2,
    OFB = 3,
    CTR = 4,
    GCM = 5
};

template <AESMode MODE> struct IsValidModeOfOperation
{
    static constexpr bool value =
        (MODE == AESMode::ECB || MODE == AESMode::CBC || MODE == AESMode::CFB || MODE == AESMode::OFB || MODE == AESMode::CTR || MODE == AESMode::GCM);
};

template <uint16_t AES_KEY_SIZE, AESMode Mode, typename EnableM = void, typename Enable = void> class AES_Encryption;
template <uint16_t AES_KEY_SIZE, AESMode Mode, typename EnableM = void, typename Enable = void> class AES_Decryption;
template <uint16_t AES_KEY_SIZE, typename Enable = void> class AesEngine;

using RoundKeysT = std::vector<std::vector<byte>>;
using StateMatrixT = RoundKeysT;

template <uint16_t AES_KEY_SIZE> class AesEngine<AES_KEY_SIZE, typename std::enable_if<IsValidBlockSize<AES_KEY_SIZE>::value>::type>
{
  protected:
    size_t iSz;
    size_t kSz;
    RoundKeysT round_keys;
    StateMatrixT state_matrix;

  public:
    static constexpr byte Nk = AES_KEY_SIZE / 32;
    static constexpr byte Nr = AES_KEY_SIZE == AES128KS ? AES128_ROUNDS : (AES_KEY_SIZE == AES192KS ? AES192_ROUNDS : AES256_ROUNDS);
    struct AesParameters parameter;
    AesEngine() noexcept = default;
    AesEngine(const AesEngine &) noexcept = delete;
    AesEngine(AesEngine &&) noexcept = delete;

    virtual ~AesEngine() noexcept
    {
        _eraseData();
    }

    __attribute__((cold)) void _validateParameters(const std::string &input, const std::string &key)
    {
        this->iSz = input.size();
        this->kSz = key.size();
        if (this->iSz >= UINT64_MAX || this->iSz == 0 || (this->kSz != (AES256KS / 8) && this->kSz != (AES128KS / 8) && this->kSz != (AES192KS / 8))) [[unlikely]]
        {
            throw std::invalid_argument("invalid input or key!");
        }
    }

    __attribute__((cold, nothrow)) inline void _bindParameters(const std::string &input, const std::string &key) noexcept
    {
        this->parameter.data.assign(input.begin(), input.end());
        this->parameter.key.assign(key.begin(), key.end());
    }

    __attribute__((cold, nothrow)) inline void _stateInitialization() noexcept
    {
        this->state_matrix.resize(Nr + 1, std::vector<byte>(Nb));
        this->round_keys.resize((Nr + 1) * Nb, std::vector<byte>(Nb));
    }

    __attribute__((cold, nothrow)) inline void _eraseData() noexcept
    {
        this->state_matrix.clear();
        this->round_keys.clear();
        this->parameter.data.clear();
        this->parameter.key.clear();
    }

    __attribute__((cold)) void _keySchedule()
    {
        for (byte i = 0; i < Nk; ++i)
        {
            for (byte j = 0; j < Nb; ++j)
            {
                this->round_keys[i][j] = this->parameter.key[i * Nb + j];
            }
        }
        for (uint16_t i = Nk; i < ((Nr + 1) * Nb); ++i)
        {
            std::vector<byte> kRound = this->round_keys[i - 1];
            if (i % Nk == 0)
            {
                this->_keyRotate(kRound, 1);
                std::transform(kRound.begin(), kRound.end(), kRound.begin(), [](byte b) { return AESUtils::SBox[b]; });
                kRound[0] ^= AESUtils::RCon[i / Nk];
            }
            else if (Nk > 6 && (i % Nk == 4))
            {
                std::transform(kRound.begin(), kRound.end(), kRound.begin(), [](byte b) { return AESUtils::SBox[b]; });
            }
            for (byte j = 0; j < kRound.size(); ++j)
            {
                this->round_keys[i][j] = this->round_keys[i - Nk][j] ^ kRound[j];
            }
        }
    }

    __attribute__((hot, nothrow)) inline void _keyRotate(std::vector<byte> &data, size_t positions) noexcept
    {
        if (data.empty()) [[unlikely]]
            return;
        positions %= data.size();
        if (positions == 0) [[unlikely]]
            return;

        std::reverse(data.begin(), data.begin() + positions);
        std::reverse(data.begin() + positions, data.end());
        std::reverse(data.begin(), data.end());
    }

    __attribute__((hot, nothrow)) inline void _addRoundKey(size_t round) noexcept
    {
        for (byte r = 0; r < Nb; ++r)
        {
            for (byte k = 0; k < Nb; ++k)
            {
                this->state_matrix[k][r] ^= this->round_keys[round * Nb + r][k];
            }
        }
    }

    __attribute__((hot, nothrow)) inline void _subBytes() noexcept
    {
        for (auto &row : this->state_matrix)
        {
            std::transform(row.begin(), row.end(), row.begin(), [](byte b) { return AESUtils::SBox[b]; });
        }
    }

    __attribute__((hot, nothrow)) inline void _invSubBytes() noexcept
    {
        for (auto &row : this->state_matrix)
        {
            std::transform(row.begin(), row.end(), row.begin(), [](byte b) { return AESUtils::InvSBox[b]; });
        }
    }

    __attribute__((hot, nothrow)) inline void _shiftRows() noexcept
    {
        for (uint8_t i = 1; i < Nb; ++i)
        {
            this->_keyRotate(this->state_matrix[i], i);
        }
    }

    __attribute__((hot, nothrow)) inline void _invShiftRows() noexcept
    {
        for (uint8_t i = 1; i < Nb; ++i)
        {
            this->_keyRotate(this->state_matrix[Nb - i], i);
        }
    }

    __attribute__((hot, nothrow)) inline void _mixColumns() noexcept
    {
        for (uint8_t i = 0; i < Nb; ++i)
        {
            std::array<byte, 4> temp;
            temp[0] = __gfmultip2(this->state_matrix[0][i]) ^ __gfmultip3(this->state_matrix[1][i]) ^ this->state_matrix[2][i] ^ this->state_matrix[3][i];
            temp[1] = this->state_matrix[0][i] ^ __gfmultip2(this->state_matrix[1][i]) ^ __gfmultip3(this->state_matrix[2][i]) ^ this->state_matrix[3][i];
            temp[2] = this->state_matrix[0][i] ^ this->state_matrix[1][i] ^ __gfmultip2(this->state_matrix[2][i]) ^ __gfmultip3(this->state_matrix[3][i]);
            temp[3] = __gfmultip3(this->state_matrix[0][i]) ^ this->state_matrix[1][i] ^ this->state_matrix[2][i] ^ __gfmultip2(this->state_matrix[3][i]);
            for (uint8_t j = 0; j < 4; ++j)
            {
                this->state_matrix[j][i] = temp[j];
            }
        }
    }

    __attribute__((hot, nothrow)) inline void _invMixColumns() noexcept
    {
        for (uint8_t i = 0; i < Nb; ++i)
        {
            std::array<byte, 4> temp;
            temp[0] = __gfmultip14(this->state_matrix[0][i]) ^ __gfmultip11(this->state_matrix[1][i]) ^ __gfmultip13(this->state_matrix[2][i]) ^
                      __gfmultip9(this->state_matrix[3][i]);
            temp[1] = __gfmultip9(this->state_matrix[0][i]) ^ __gfmultip14(this->state_matrix[1][i]) ^ __gfmultip11(this->state_matrix[2][i]) ^
                      __gfmultip13(this->state_matrix[3][i]);
            temp[2] = __gfmultip13(this->state_matrix[0][i]) ^ __gfmultip9(this->state_matrix[1][i]) ^ __gfmultip14(this->state_matrix[2][i]) ^
                      __gfmultip11(this->state_matrix[3][i]);
            temp[3] = __gfmultip11(this->state_matrix[0][i]) ^ __gfmultip13(this->state_matrix[1][i]) ^ __gfmultip9(this->state_matrix[2][i]) ^
                      __gfmultip14(this->state_matrix[3][i]);
            for (uint8_t j = 0; j < 4; ++j)
            {
                this->state_matrix[j][i] = temp[j];
            }
        }
    }

    __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip2(const byte x) const noexcept
    {
        return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
    }
    __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip3(const byte x) const noexcept
    {
        return __gfmultip2(x) ^ x;
    }
    __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip9(const byte x) const noexcept
    {
        return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ x;
    }
    __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip11(const byte x) const noexcept
    {
        return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(x) ^ x;
    }
    __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip13(const byte x) const noexcept
    {
        return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(__gfmultip2(x)) ^ x;
    }
    __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip14(const byte x) const noexcept
    {
        return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(__gfmultip2(x)) ^ __gfmultip2(x);
    }

    virtual void _execRound(const uint8_t r) {};
    __attribute__((cold)) virtual void _finalRound(const uint8_t r) {};
    __attribute__((cold)) virtual void _generateAesConstants() noexcept {};
    virtual void _transformation() {};
    virtual inline void _initMainRounds()
    {
    }

    __attribute__((hot, nothrow)) inline void _initStateMatrix(const std::string &bytes) noexcept
    {
        for (byte r = 0; r < Nb; ++r)
        {
            for (byte c = 0; c < Nb; ++c)
            {
                this->state_matrix[r][c] = bytes[r + Nb * c];
            }
        }
    }

    __attribute__((hot, nothrow)) inline void _setOutput(std::array<byte, AES_BLOCK_SIZE> &out) noexcept
    {
        for (uint8_t i = 0; i < 4; ++i)
        {
            for (uint8_t j = 0; j < Nb; ++j)
            {
                out[i + 4 * j] = this->state_matrix[i][j];
            }
        }
    }

    __attribute__((cold, nothrow)) inline std::string _pkcs7Attach(const std::string &input, size_t blockSize) noexcept
    {
        uint8_t paddingSize = blockSize - (input.size() % blockSize);
        std::string padded(input);
        padded.reserve(input.size() + paddingSize);
        while (padded.size() < input.size() + paddingSize)
        {
            padded.push_back(static_cast<int>(paddingSize));
        }
        return padded;
    }

    __attribute__((cold, nothrow)) inline void _pkcs7Dettach(std::vector<uint8_t> &data) noexcept
    {
        if (data.empty()) [[unlikely]]
        {
            return;
        }
        const uint8_t paddingSize = data.back();
        if (paddingSize > 128 / 8) [[unlikely]]
        {
            return;
        }
        data.erase(data.end() - paddingSize, data.end());
    }

    __attribute__((cold, nothrow)) inline const std::string _addPadding(const std::string &input) noexcept
    {
        if (input.length() % AES_BLOCK_SIZE == 0) [[unlikely]]
        {
            return input;
        }
        const std::string paddedInput = this->_pkcs7Attach(input, 128 / 8);
        this->iSz = paddedInput.size();
        return paddedInput;
    }
};
template <AESMode Mode> struct AESModeHandler;
template <> struct AESModeHandler<AESMode::ECB>
{
    template <uint16_t AES_KEY_SIZE> static std::vector<byte> convert(const std::string &in, const std::string &key)
    {
        AES_Encryption<AES_KEY_SIZE, AESMode::ECB> engine;
        return engine.convert(in, key);
    }
};

namespace ModeOfOperation
{
class ModeCipherSpecs
{
  public:
    ModeCipherSpecs() {};
    ~ModeCipherSpecs() {};
    static inline void xorBlock(std::vector<byte> &dataBlock, const std::vector<byte> &keystream)
    {
        for (size_t i = 0; i < dataBlock.size(); ++i)
        {
            dataBlock[i] ^= keystream[i];
        }
    }
    template <typename AesEngineT> static inline std::vector<byte> generateKeystream(AesEngineT *core, const std::vector<byte> &ivOrCounter)
    {
        std::string input(ivOrCounter.begin(), ivOrCounter.end());
        const std::string key(core->parameter.key.begin(), core->parameter.key.end());
        return AESModeHandler<AESMode::ECB>::convert<128>(input, key);
    }
};

class ECB_Mode
{
  public:
    ECB_Mode() noexcept {};
    ECB_Mode(const ECB_Mode &) noexcept = delete;
    ECB_Mode(ECB_Mode &&) noexcept = delete;
    ECB_Mode &operator=(const ECB_Mode &) noexcept = delete;
    ECB_Mode &operator=(ECB_Mode &&) noexcept = delete;
    ~ECB_Mode() noexcept {};

    __attribute__((hot, always_inline, nothrow)) inline static const bool isValidBlock(std::string &block) noexcept
    {
        return block.size() == AES_BLOCK_SIZE;
    };

    template <typename AesEngineT> __attribute__((hot, always_inline)) inline static void Encryption(AesEngineT *core, std::vector<byte> &out)
    {
        for (uint64_t i = 0; i < core->parameter.data.size(); i += AES_BLOCK_SIZE)
        {
            std::string block(core->parameter.data.begin() + i, core->parameter.data.begin() + i + AES_BLOCK_SIZE);

            if (!isValidBlock(block)) [[unlikely]]
            {
                throw std::invalid_argument("Invalid block size for ECB encryption");
            }
            std::array<byte, AES_BLOCK_SIZE> tmpOut;
            core->_initStateMatrix(block);
            core->_addRoundKey(0);
            core->_initMainRounds();
            core->_finalRound(AesEngineT::Nr);
            core->_setOutput(tmpOut);
            out.insert(out.end(), tmpOut.begin(), tmpOut.end());
        }
    }

    template <typename AesEngineT> __attribute__((hot, always_inline)) inline static void Decryption(AesEngineT *core, std::vector<byte> &out)
    {
        for (uint64_t i = 0; i < core->parameter.data.size(); i += AES_BLOCK_SIZE)
        {
            std::string block(core->parameter.data.begin() + i, core->parameter.data.begin() + i + AES_BLOCK_SIZE);
            if (!isValidBlock(block)) [[unlikely]]
            {
                throw std::invalid_argument("Invalid block size for ECB decryption");
            }
            std::array<byte, AES_BLOCK_SIZE> tmpOut;
            core->_initStateMatrix(block);
            core->_addRoundKey(AesEngineT::Nr);
            core->_initMainRounds();
            core->_finalRound(0);
            core->_setOutput(tmpOut);
            out.insert(out.end(), tmpOut.begin(), tmpOut.end());
        }
    }
};

class CBC_Mode
{
  public:
    CBC_Mode() noexcept {};
    CBC_Mode(const CBC_Mode &) noexcept = delete;
    CBC_Mode(CBC_Mode &&) noexcept = delete;
    CBC_Mode &operator=(const CBC_Mode &) noexcept = delete;
    CBC_Mode &operator=(CBC_Mode &&) noexcept = delete;
    ~CBC_Mode() noexcept {};

    template <typename AesEngineT> static void Encryption(AesEngineT *core, std::vector<byte> &out)
    {
        for (uint64_t i = 0; i < core->parameter.data.size(); i += AES_BLOCK_SIZE)
        {
            std::string block(core->parameter.data.begin() + i, core->parameter.data.begin() + i + AES_BLOCK_SIZE);
            if (block.size() != AES_BLOCK_SIZE) [[unlikely]]
            {
                throw std::invalid_argument("Invalid block size for CBC encryption");
            }
            for (size_t i = 0; i < AES_BLOCK_SIZE; ++i)
            {
                block[i] ^= core->iv[i];
            }
            std::array<byte, AES_BLOCK_SIZE> tmpOut;
            core->_initStateMatrix(block);
            core->_addRoundKey(0);
            core->_initMainRounds();
            core->_finalRound(AesEngineT::Nr);
            core->_setOutput(tmpOut);
            out.insert(out.end(), tmpOut.begin(), tmpOut.end());
            core->iv.assign(tmpOut.begin(), tmpOut.end());
        }
    }

    template <typename AesEngineT> static void Decryption(AesEngineT *core, std::vector<byte> &out)
    {
        for (uint64_t i = 0; i < core->parameter.data.size(); i += AES_BLOCK_SIZE)
        {
            std::string block(core->parameter.data.begin() + i, core->parameter.data.begin() + i + AES_BLOCK_SIZE);
            if (block.size() != AES_BLOCK_SIZE) [[unlikely]]
            {
                throw std::invalid_argument("Invalid block size for CBC decryption");
            }
            std::array<byte, AES_BLOCK_SIZE> tmpOut;
            core->_initStateMatrix(block);
            core->_addRoundKey(AesEngineT::Nr);
            core->_initMainRounds();
            core->_finalRound(0);
            core->_setOutput(tmpOut);

            for (size_t i = 0; i < AES_BLOCK_SIZE; ++i)
            {
                tmpOut[i] ^= core->iv[i];
            }
            core->iv.assign(block.begin(), block.end());
            out.insert(out.end(), tmpOut.begin(), tmpOut.end());
        }
    }
};

class CTR_Mode
{
  public:
    CTR_Mode() noexcept {};
    CTR_Mode(const CTR_Mode &) noexcept = delete;
    CTR_Mode(CTR_Mode &&) noexcept = delete;
    CTR_Mode &operator=(const CTR_Mode &) noexcept = delete;
    CTR_Mode &operator=(CTR_Mode &&) noexcept = delete;
    ~CTR_Mode() noexcept {};

    template <typename AesEngineT> inline static void Encryption(AesEngineT *core, std::vector<byte> &out)
    {
        const size_t blocksize{core->parameter.data.size()};
        for (size_t i{0}; i < blocksize; i += AES_BLOCK_SIZE)
        {
            std::vector<byte> keystream(ModeCipherSpecs::generateKeystream(core, core->iv));
            std::vector<byte> block(core->parameter.data.begin() + i, core->parameter.data.begin() + std::min(i + AES_BLOCK_SIZE, blocksize));
            ModeCipherSpecs::xorBlock(block, keystream);
            out.insert(out.end(), block.begin(), block.end());
            ++core->counter;
        }
    }

    template <typename AesEngineT> __attribute__((hot, always_inline)) inline static void Decryption(AesEngineT *core, std::vector<byte> &out)
    {
        Encryption(core, out);
    }
};

class OFB_Mode
{
  public:
    OFB_Mode() noexcept {};
    OFB_Mode(const OFB_Mode &) noexcept = delete;
    OFB_Mode(OFB_Mode &&) noexcept = delete;
    OFB_Mode &operator=(const OFB_Mode &) noexcept = delete;
    OFB_Mode &operator=(OFB_Mode &&) noexcept = delete;
    ~OFB_Mode() noexcept {};

    template <typename AesEngineT> inline static void Encryption(AesEngineT *core, std::vector<byte> &out)
    {
        const size_t blocksize{core->parameter.data.size()};
        for (size_t i{0}; i < blocksize; i += AES_BLOCK_SIZE)
        {
            std::vector<byte> keystream(ModeCipherSpecs::generateKeystream(core, core->iv));
            std::vector<byte> block(core->parameter.data.begin() + i, core->parameter.data.begin() + std::min(i + AES_BLOCK_SIZE, blocksize));
            ModeCipherSpecs::xorBlock(block, keystream);
            out.insert(out.end(), block.begin(), block.end());
            core->iv = keystream;
        }
    }

    template <typename AesEngineT> __attribute__((hot, always_inline)) inline static void Decryption(AesEngineT *core, std::vector<byte> &out)
    {
        Encryption(core, out);
    }
};

class CFB_Mode
{
  public:
    CFB_Mode() noexcept {};
    CFB_Mode(const CFB_Mode &) noexcept = delete;
    CFB_Mode(CFB_Mode &&) noexcept = delete;
    CFB_Mode &operator=(const CFB_Mode &) noexcept = delete;
    CFB_Mode &operator=(CFB_Mode &&) noexcept = delete;
    ~CFB_Mode() noexcept {};

    template <typename AesEngineT> inline static void Encryption(AesEngineT *core, std::vector<byte> &out)
    {
        const size_t blocksize{core->parameter.data.size()};
        for (size_t i{0}; i < blocksize; i += AES_BLOCK_SIZE)
        {
            std::vector<byte> keystream(ModeCipherSpecs::generateKeystream(core, core->iv));
            std::vector<byte> block(core->parameter.data.begin() + i, core->parameter.data.begin() + std::min(i + AES_BLOCK_SIZE, blocksize));
            ModeCipherSpecs::xorBlock(block, keystream);
            out.insert(out.end(), block.begin(), block.end());
            core->iv.assign(block.begin(), block.end());
        }
    }

    template <typename AesEngineT> inline static void Decryption(AesEngineT *core, std::vector<byte> &out)
    {
        const size_t blocksize{core->parameter.data.size()};
        std::vector<byte> prevCiphertext(core->iv);
        for (size_t i{0}; i < blocksize; i += AES_BLOCK_SIZE)
        {
            std::vector<byte> keystream(ModeCipherSpecs::generateKeystream(core, prevCiphertext));
            std::vector<byte> ciphertextBlock(core->parameter.data.begin() + i, core->parameter.data.begin() + std::min(i + AES_BLOCK_SIZE, blocksize));
            std::vector<byte> decryptedBlock(ciphertextBlock);
            ModeCipherSpecs::xorBlock(decryptedBlock, keystream);
            out.insert(out.end(), decryptedBlock.begin(), decryptedBlock.end());
            prevCiphertext = ciphertextBlock;
        }
    }
};
} // namespace ModeOfOperation

template <uint16_t AES_KEY_SIZE, AESMode Mode>
class AES_Encryption<AES_KEY_SIZE, Mode, typename std::enable_if<IsValidModeOfOperation<Mode>::value>::type,
                     typename std::enable_if<IsValidBlockSize<AES_KEY_SIZE>::value>::type> : public AesEngine<AES_KEY_SIZE>
{
    AESMode M = Mode;

  public:
    std::vector<byte> iv;
    std::vector<byte> authTag;
    uint64_t counter = 0;
    std::vector<byte> aad;
    AES_Encryption() noexcept = default;
    AES_Encryption(const AES_Encryption &) noexcept = delete;
    AES_Encryption(AES_Encryption &&) noexcept = delete;

    __attribute__((cold)) const std::vector<byte> convert(const std::string &input, const std::string &key)
    {
        std::vector<byte> result;
        this->_validateParameters(input, key);
        this->_generateAesConstants();
        this->_bindParameters((Mode == AESMode::CTR || Mode == AESMode::OFB || Mode == AESMode::CFB || Mode == AESMode::GCM ? input : this->_addPadding(input)), key);
        this->_stateInitialization();
        this->_keySchedule();
        this->_transformation(result);
        return result;
    };

    __attribute__((cold)) const std::vector<byte> convert(const std::vector<byte> &input, const std::string &key)
    {
        return this->convert(std::string(input.begin(), input.end()), std::move(key));
    };

    ~AES_Encryption() noexcept override = default;

    __attribute__((cold)) void _transformation(std::vector<byte> &out)
    {
        if (Mode == AESMode::CTR)
            ModeOfOperation::CTR_Mode::Encryption(this, out);
        else if (Mode == AESMode::OFB)
            ModeOfOperation::OFB_Mode::Encryption(this, out);
        else if (Mode == AESMode::CFB)
            ModeOfOperation::CFB_Mode::Encryption(this, out);
        else if (Mode == AESMode::CBC)
            ModeOfOperation::CBC_Mode::Encryption(this, out);
        else if (Mode == AESMode::ECB)
            ModeOfOperation::ECB_Mode::Encryption(this, out);
        else
            throw std::invalid_argument("invalid AES mode of operation, valid modes are(ECB, OFB, CBC, CTR, ECB)");
    };

    __attribute__((cold)) void _generateAesConstants() noexcept override
    {
        AESUtils::createSBox(AESUtils::SBox);
        AESUtils::createRCon(AESUtils::RCon);
        AESUtils::createMixCols(AESUtils::MixCols);
    }

    __attribute__((hot)) void _execRound(const uint8_t r) override
    {
        this->_subBytes();
        this->_shiftRows();
        this->_mixColumns();
        this->_addRoundKey(r);
    }

    __attribute__((cold)) void _finalRound(const uint8_t r) override
    {
        this->_subBytes();
        this->_shiftRows();
        this->_addRoundKey(r);
    }

    __attribute__((cold)) inline void _initMainRounds() override
    {
        for (uint8_t r = 1; r < AesEngine<AES_KEY_SIZE>::Nr; ++r)
        {
            this->_execRound(r);
        }
    }
};
template <uint16_t AES_KEY_SIZE, AESMode Mode>
class AES_Decryption<AES_KEY_SIZE, Mode, typename std::enable_if<IsValidModeOfOperation<Mode>::value>::type,
                     typename std::enable_if<IsValidBlockSize<AES_KEY_SIZE>::value>::type> : public AesEngine<AES_KEY_SIZE>
{
    AESMode M = Mode;

  public:
    std::vector<byte> iv;
    std::vector<byte> authTag;
    uint64_t counter = 0;
    std::vector<byte> aad;
    AES_Decryption() noexcept = default;
    AES_Decryption(const AES_Decryption &) noexcept = delete;
    AES_Decryption(AES_Decryption &&) noexcept = delete;

    __attribute__((cold)) const std::vector<byte> convert(const std::string &input, const std::string &key)
    {
        std::vector<byte> result;
        this->_validateParameters(input, key);
        this->_generateAesConstants();
        this->_bindParameters(input, key);
        this->_stateInitialization();
        this->_keySchedule();
        this->_transformation(result);
        this->_pkcs7Dettach(result);
        return result;
    }

     __attribute__((cold)) const std::vector<byte> convert(const std::vector<byte> &input, const std::string &key)
    {
        return this->convert(std::string(input.begin(), input.end()), std::move(key));
    };

    ~AES_Decryption() noexcept override = default;

    __attribute__((cold)) void _transformation(std::vector<byte> &out)
    {
        if (Mode == AESMode::CTR)
            ModeOfOperation::CTR_Mode::Decryption(this, out);
        else if (Mode == AESMode::OFB)
            ModeOfOperation::OFB_Mode::Decryption(this, out);
        else if (Mode == AESMode::CFB)
            ModeOfOperation::CFB_Mode::Decryption(this, out);
        else if (Mode == AESMode::CBC)
            ModeOfOperation::CBC_Mode::Decryption(this, out);
        else if (Mode == AESMode::ECB)
            ModeOfOperation::ECB_Mode::Decryption(this, out);
        else
            throw std::invalid_argument("invalid AES mode of operation, valid modes are(ECB, OFB, CBC, CTR, ECB)");
    };

    __attribute__((cold)) void _generateAesConstants() noexcept override
    {
        AESUtils::createInvSBox(AESUtils::SBox, AESUtils::InvSBox);
        AESUtils::createRCon(AESUtils::RCon);
        AESUtils::createInvMixCols(AESUtils::InvMixCols);
    }

    __attribute__((hot)) void _execRound(const uint8_t r) override
    {
        this->_invShiftRows();
        this->_invSubBytes();
        this->_addRoundKey(r);
        this->_invMixColumns();
    }

    __attribute__((cold)) void _finalRound(const uint8_t r) override
    {
        this->_invShiftRows();
        this->_invSubBytes();
        this->_addRoundKey(r);
    }

    __attribute__((cold)) inline void _initMainRounds() override
    {
        for (uint8_t round = AesEngine<AES_KEY_SIZE>::Nr - 1; round > 0; --round)
        {
            this->_execRound(round);
        }
    }
};

}; // namespace AesCryptoModule

#endif

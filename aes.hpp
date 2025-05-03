#pragma once
#include <algorithm>   // used for std::transform, etc...
#include <array>       // for fixed size arrays
#include <chrono>      // for timer interval
#include <cstring>     // for something...
#include <ctime>       // for CSPRNG state value(seed)
#include <fstream>     // for the CSPRNG readFILE operation
#include <iomanip>     // needed to print as hex format
#include <iostream>    // required for the CSPRNG function
#include <stdexcept>   // exceptions
#include <string>      // std::string
#include <thread>      // for std::this_thread::sleep_for(...), std::thread().join()...
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

using byte = uint8_t;

namespace AesCryptoModule {

class PRNG {
private:
  static constexpr size_t N = 0x270;
  static constexpr size_t M = 0x17B;
  static constexpr size_t MATRIX_A = 0x9908b0dfUL;
  static constexpr size_t UPPER_MASK = 0x80000000UL;
  static constexpr size_t LOWER_MASK = 0x7fffffffUL;

  size_t state;
  std::array<size_t, N> mt;
  int mti;

  void init_mersenne_twister(size_t seed) {
    mt[0] = seed;
    for (mti = 1; mti < N; mti++) {
      mt[mti] = (1812433253UL * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + mti);
    }
  }

public:
  PRNG(size_t seed = std::time(nullptr), size_t sequence = 1) : state(seed), mti(N) { init_mersenne_twister(seed); };

  __attribute__((cold)) const size_t MersenneTwister(const size_t min, const size_t max) {
    if (min >= max) [[unlikely]]
      throw std::invalid_argument("min must be less than max");
    size_t y;
    static const size_t mag01[2] = {0x0UL, MATRIX_A};
    if (mti >= N) {
      int kk;
      for (kk = 0; kk < N - M; kk++) {
        y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
        mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1UL];
      }
      for (; kk < N - 1; kk++) {
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

  __attribute__((cold)) void reseed(size_t new_seed) {
    state = new_seed;
    init_mersenne_twister(new_seed);
  };
};

class AESUtils {
public:
  AESUtils() = default;
  AESUtils(const AESUtils &c) = delete;
  AESUtils(AESUtils &&c) = delete;
  ~AESUtils() = default;

  __attribute__((hot, pure, nothrow)) static inline constexpr byte galloisFieldMultiplication(byte a, byte b) noexcept {
    byte p = 0;
    for (uint16_t i = 0; i < 8; ++i) {
      if (b & 1) {
        p ^= a;
      }
      bool hiBitSet = (a & 0x80);
      a <<= 1;
      if (hiBitSet) {
        a ^= 0x1B; // 0x1B is the irreducible polynomial for AES
      }
      b >>= 1;
    }
    return p;
  }

  __attribute__((hot, pure, nothrow)) inline static constexpr byte galloisFieldInverse(byte x) noexcept {
    byte y = x;
    for (uint16_t i = 0; i < 4; ++i) {
      y = galloisFieldMultiplication(y, y);
      y = galloisFieldMultiplication(y, x);
    }
    return y;
  }

  __attribute__((hot, pure, nothrow)) inline static constexpr byte affineTransform(byte x) noexcept {
    byte result = 0x63;
    for (uint16_t i = 0; i < 8; ++i) {
      result ^= (x >> i) & 1 ? (0xF1 >> (7 - i)) & 0xFF : 0;
    }
    return result;
  }

  __attribute__((cold, pure, nothrow)) static constexpr byte createSBoxEntry(byte x) noexcept { return affineTransform(galloisFieldInverse(x)); }

  __attribute__((cold, leaf, nothrow)) inline static constexpr void createSBox(std::array<byte, 256> &sbox) noexcept {
    for (uint16_t i = 0; i < 256; ++i) {
      sbox[i] = createSBoxEntry(static_cast<byte>(i));
    }
  }

  __attribute__((cold, leaf, nothrow)) static constexpr void createInvSBox(const std::array<byte, 256> &sbox, std::array<byte, 256> &invSbox) noexcept {
    for (uint16_t i = 0; i < 256; ++i) {
      invSbox[sbox[i]] = static_cast<byte>(i);
    }
  }

  __attribute__((cold, nothrow)) static constexpr void createRCon(std::array<byte, 256> &rcon) noexcept {
    byte c = 1;
    for (uint16_t i = 0; i < 256; ++i) {
      rcon[i] = c;
      c = galloisFieldMultiplication(c, 0x02);
    }
  }

  __attribute__((cold, leaf, nothrow)) static constexpr void createMixCols(std::array<std::array<byte, 4>, 4> &mixCols) noexcept {
    mixCols[0] = {0x02, 0x03, 0x01, 0x01};
    mixCols[1] = {0x01, 0x02, 0x03, 0x01};
    mixCols[2] = {0x01, 0x01, 0x02, 0x03};
    mixCols[3] = {0x03, 0x01, 0x01, 0x02};
  }

  __attribute__((cold, leaf, nothrow)) static constexpr void createInvMixCols(std::array<std::array<byte, 4>, 4> &invMixCols) noexcept {
    invMixCols[0] = {0x0E, 0x0B, 0x0D, 0x09};
    invMixCols[1] = {0x09, 0x0E, 0x0B, 0x0D};
    invMixCols[2] = {0x0D, 0x09, 0x0E, 0x0B};
    invMixCols[3] = {0x0B, 0x0D, 0x09, 0x0E};
  }

  __attribute__((cold)) static const std::string genSecKeyBlock(const uint16_t key_size) {
    const char alpha[26 * 2 + 12] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                     'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                                     'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '.', ',', '!', '@', '#', '$', '%', '^', '&', '*', '+', '-'};
    if (key_size != AES128KS && key_size != AES256KS && key_size != AES192KS)
      return "";
    std::string seckey;
    seckey.resize(key_size / 8);
    uint16_t c = 0;
    PRNG generator;
    while (c < key_size / 8) {
      seckey[c++] = alpha[generator.MersenneTwister(0, 26 * 2 + 11)];
    }
    return seckey;
  };

  static void GenerateIvBlock(std::vector<byte> &iv) {
    iv.resize(16); // Block size for AES is 16 bytes
    PRNG generator;
    for (auto &b : iv) {
      b = generator.MersenneTwister(0, 255);
    }
  }

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
struct AesParameters {
  std::vector<uint16_t> data;
  std::vector<uint16_t> key;
};

template <uint16_t BlockSz> struct IsValidBlockSize {
  static constexpr bool value = (BlockSz == AES128KS || BlockSz == AES192KS || BlockSz == AES256KS);
};

enum AESMode { ECB = 0, CBC = 1, CFB = 2, OFB = 3, CTR = 4, GCM = 5 };

template <AESMode MODE> struct IsValidModeOfOperation {
  static constexpr bool value =
      (MODE == AESMode::ECB || MODE == AESMode::CBC || MODE == AESMode::CFB || MODE == AESMode::OFB || MODE == AESMode::CTR || MODE == AESMode::GCM);
};

template <uint16_t BlockSz, AESMode Mode, typename EnableM = void, typename Enable = void> class AES_Encryption;
template <uint16_t BlockSz, AESMode Mode, typename EnableM = void, typename Enable = void> class AES_Decryption;
template <uint16_t BlockSz, typename Enable = void> class AesEngine;

using RoundKeysT = std::vector<std::vector<byte>>;
using StateMatrixT = RoundKeysT;

template <uint16_t BlockSz> class AesEngine<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> {
public:
  static constexpr byte Nk = BlockSz / 32;
  static constexpr byte Nr = BlockSz == AES128KS ? AES128_ROUNDS : (BlockSz == AES192KS ? AES192_ROUNDS : AES256_ROUNDS);
  size_t iSz;
  size_t kSz;
  struct AesParameters parameter;
  RoundKeysT round_keys;
  StateMatrixT state_matrix;

public:
  AesEngine() noexcept = default;
  AesEngine(const AesEngine &) noexcept = delete;
  AesEngine(AesEngine &&) noexcept = delete;

  virtual ~AesEngine() noexcept { _eraseData(); }

  // protected:
  __attribute__((cold)) void _validateParameters(const std::string &input, const std::string &key) {
    this->iSz = input.size();
    this->kSz = key.size();
    if (this->iSz >= UINT64_MAX || this->iSz == 0 || (this->kSz != (AES256KS / 8) && this->kSz != (AES128KS / 8) && this->kSz != (AES192KS / 8))) [[unlikely]] {
      throw std::invalid_argument("invalid input or key!");
    }
  }

  __attribute__((cold, nothrow)) inline void _bindParameters(const std::string &input, const std::string &key) noexcept {
    this->parameter.data.assign(input.begin(), input.end());
    this->parameter.key.assign(key.begin(), key.end());
  }

  __attribute__((cold, nothrow)) inline void _stateInitialization() noexcept {
    this->state_matrix.resize(Nr + 1, std::vector<byte>(Nb));
    this->round_keys.resize((Nr + 1) * Nb, std::vector<byte>(Nb));
  }

  __attribute__((cold, nothrow)) inline void _eraseData() noexcept {
    this->state_matrix.clear();
    this->round_keys.clear();
    this->parameter.data.clear();
    this->parameter.key.clear();
  }

  __attribute__((cold)) void _keySchedule() {
    for (byte i = 0; i < Nk; ++i) {
      for (byte j = 0; j < Nb; ++j) {
        this->round_keys[i][j] = this->parameter.key[i * Nb + j];
      }
    }
    for (uint16_t i = Nk; i < ((Nr + 1) * Nb); ++i) {
      std::vector<byte> kRound = this->round_keys[i - 1];
      if (i % Nk == 0) {
        this->_keyRotate(kRound, 1);
        std::transform(kRound.begin(), kRound.end(), kRound.begin(), [](byte b) { return AESUtils::SBox[b]; });
        kRound[0] ^= AESUtils::RCon[i / Nk];
      } else if (Nk > 6 && (i % Nk == 4)) {
        std::transform(kRound.begin(), kRound.end(), kRound.begin(), [](byte b) { return AESUtils::SBox[b]; });
      }
      for (byte j = 0; j < kRound.size(); ++j) {
        this->round_keys[i][j] = this->round_keys[i - Nk][j] ^ kRound[j];
      }
    }
  }

  __attribute__((hot, nothrow)) inline void _keyRotate(std::vector<byte> &data, size_t positions) noexcept {
    if (data.empty()) [[unlikely]]
      return;
    positions %= data.size();
    if (positions == 0) [[unlikely]]
      return;

    std::reverse(data.begin(), data.begin() + positions);
    std::reverse(data.begin() + positions, data.end());
    std::reverse(data.begin(), data.end());
  }

  __attribute__((hot, nothrow)) inline void _addRoundKey(size_t round) noexcept {
    for (byte r = 0; r < Nb; ++r) {
      for (byte k = 0; k < Nb; ++k) {
        this->state_matrix[k][r] ^= this->round_keys[round * Nb + r][k];
      }
    }
  }

  __attribute__((hot, nothrow)) inline void _subBytes() noexcept {
    for (auto &row : this->state_matrix) {
      std::transform(row.begin(), row.end(), row.begin(), [](byte b) { return AESUtils::SBox[b]; });
    }
  }

  __attribute__((hot, nothrow)) inline void _invSubBytes() noexcept {
    for (auto &row : this->state_matrix) {
      std::transform(row.begin(), row.end(), row.begin(), [](byte b) { return AESUtils::InvSBox[b]; });
    }
  }

  __attribute__((hot, nothrow)) inline void _shiftRows() noexcept {
    for (uint8_t i = 1; i < Nb; ++i) {
      this->_keyRotate(this->state_matrix[i], i);
    }
  }

  __attribute__((hot, nothrow)) inline void _invShiftRows() noexcept {
    for (uint8_t i = 1; i < Nb; ++i) {
      this->_keyRotate(this->state_matrix[Nb - i], i);
    }
  }

  __attribute__((hot, nothrow)) inline void _mixColumns() noexcept {
    for (uint8_t i = 0; i < Nb; ++i) {
      std::array<byte, 4> temp;
      temp[0] = __gfmultip2(this->state_matrix[0][i]) ^ __gfmultip3(this->state_matrix[1][i]) ^ this->state_matrix[2][i] ^ this->state_matrix[3][i];
      temp[1] = this->state_matrix[0][i] ^ __gfmultip2(this->state_matrix[1][i]) ^ __gfmultip3(this->state_matrix[2][i]) ^ this->state_matrix[3][i];
      temp[2] = this->state_matrix[0][i] ^ this->state_matrix[1][i] ^ __gfmultip2(this->state_matrix[2][i]) ^ __gfmultip3(this->state_matrix[3][i]);
      temp[3] = __gfmultip3(this->state_matrix[0][i]) ^ this->state_matrix[1][i] ^ this->state_matrix[2][i] ^ __gfmultip2(this->state_matrix[3][i]);
      for (uint8_t j = 0; j < 4; ++j) {
        this->state_matrix[j][i] = temp[j];
      }
    }
  }

  __attribute__((hot, nothrow)) inline void _invMixColumns() noexcept {
    for (uint8_t i = 0; i < Nb; ++i) {
      std::array<byte, 4> temp;
      temp[0] = __gfmultip14(this->state_matrix[0][i]) ^ __gfmultip11(this->state_matrix[1][i]) ^ __gfmultip13(this->state_matrix[2][i]) ^
                __gfmultip9(this->state_matrix[3][i]);
      temp[1] = __gfmultip9(this->state_matrix[0][i]) ^ __gfmultip14(this->state_matrix[1][i]) ^ __gfmultip11(this->state_matrix[2][i]) ^
                __gfmultip13(this->state_matrix[3][i]);
      temp[2] = __gfmultip13(this->state_matrix[0][i]) ^ __gfmultip9(this->state_matrix[1][i]) ^ __gfmultip14(this->state_matrix[2][i]) ^
                __gfmultip11(this->state_matrix[3][i]);
      temp[3] = __gfmultip11(this->state_matrix[0][i]) ^ __gfmultip13(this->state_matrix[1][i]) ^ __gfmultip9(this->state_matrix[2][i]) ^
                __gfmultip14(this->state_matrix[3][i]);
      for (uint8_t j = 0; j < 4; ++j) {
        this->state_matrix[j][i] = temp[j];
      }
    }
  }

  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip2(const byte x) const noexcept { return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00); }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip3(const byte x) const noexcept { return __gfmultip2(x) ^ x; }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip9(const byte x) const noexcept { return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ x; }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip11(const byte x) const noexcept {
    return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(x) ^ x;
  }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip13(const byte x) const noexcept {
    return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(__gfmultip2(x)) ^ x;
  }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip14(const byte x) const noexcept {
    return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(__gfmultip2(x)) ^ __gfmultip2(x);
  }

  virtual void _execRound(const uint8_t r) {};
  __attribute__((cold)) virtual void _finalRound(const uint8_t r) {};
  __attribute__((cold)) virtual void _generateAesConstants() noexcept {};
  virtual void _modeTransformation() {};
  virtual inline void _initMainRounds() {}

  __attribute__((hot, nothrow)) inline void _initStateMatrix(const std::string &bytes) noexcept {
    for (byte r = 0; r < Nb; ++r) {
      for (byte c = 0; c < Nb; ++c) {
        this->state_matrix[r][c] = bytes[r + Nb * c];
      }
    }
  }

  __attribute__((hot, nothrow)) inline void _setOutput(std::vector<byte> &out) noexcept {
    for (uint8_t i = 0; i < 4; ++i) {
      for (uint8_t j = 0; j < Nb; ++j) {
        out[i + 4 * j] = this->state_matrix[i][j];
      }
    }
  }

  __attribute__((cold, nothrow)) inline std::string _pkcs7Attach(const std::string &input, size_t blockSize) noexcept {
    uint8_t paddingSize = blockSize - (input.size() % blockSize);
    std::string padded(input);
    padded.reserve(input.size() + paddingSize);
    while (padded.size() < input.size() + paddingSize) {
      padded.push_back(static_cast<int>(paddingSize));
    }
    return padded;
  }

  __attribute__((cold, nothrow)) inline void _pkcs7Dettach(std::vector<uint8_t> &data) noexcept {
    if (data.empty()) [[unlikely]] {
      return;
    }
    const uint8_t paddingSize = data.back();
    if (paddingSize > 128 / 8) [[unlikely]] {
      return;
    }
    data.erase(data.end() - paddingSize, data.end());
  }

  __attribute__((cold, nothrow)) inline const std::string _addPadding(const std::string &input) noexcept {
    if (input.length() % 16 == 0) [[unlikely]] {
      return input;
    }
    const std::string paddedInput = this->_pkcs7Attach(input, 128 / 8);
    this->iSz = paddedInput.size();
    return paddedInput;
  }

  __attribute__((hot, always_inline, nothrow)) inline void _blockDigest(std::vector<byte> &tmp, std::vector<byte> &out, std::string &block) noexcept {
    tmp.assign(block.begin(), block.end());
    out.insert(out.end(), tmp.begin(), tmp.end());
  };

  __attribute__((hot, always_inline, nothrow)) inline void _createBlock(std::string &out, const uint16_t offset) {
    out = std::string(this->parameter.data.begin() + offset, this->parameter.data.begin() + offset + 16);
  };
};

class ECB_Mode {
public:
  ECB_Mode() noexcept {};
  ECB_Mode(const ECB_Mode &) noexcept = delete;
  ECB_Mode(ECB_Mode &&) noexcept = delete;
  ECB_Mode &operator=(const ECB_Mode &) noexcept = delete;
  ECB_Mode &operator=(ECB_Mode &&) noexcept = delete;
  ~ECB_Mode() noexcept {};

  __attribute__((hot, always_inline, nothrow)) inline static const bool isValidBlock(std::string &block) noexcept { return block.size() == 16; };

  template <typename AesEngineT> __attribute__((hot, always_inline)) inline static void Encryption(AesEngineT *core, std::string &block) {
    if (!isValidBlock(block)) [[unlikely]] {
      throw std::invalid_argument("Invalid block size for ECB encryption");
    }
    std::vector<byte> tmpOut(16);
    core->_initStateMatrix(block);
    core->_addRoundKey(0);
    core->_initMainRounds();
    core->_finalRound(AesEngineT::Nr);
    core->_setOutput(tmpOut);
    block = std::string(tmpOut.begin(), tmpOut.end());
  }

  template <typename AesEngineT> __attribute__((hot, always_inline)) inline static void Decryption(AesEngineT *core, std::string &block) {
    if (!isValidBlock(block)) [[unlikely]] {
      throw std::invalid_argument("Invalid block size for ECB decryption");
    }
    std::vector<byte> tmpOut(16);
    core->_initStateMatrix(block);
    core->_addRoundKey(AesEngineT::Nr);
    core->_initMainRounds();
    core->_finalRound(0);
    core->_setOutput(tmpOut);
    block = std::string(tmpOut.begin(), tmpOut.end());
  }
};

class CBC_Mode {
public:
  CBC_Mode() noexcept {};
  CBC_Mode(const CBC_Mode &) noexcept = delete;
  CBC_Mode(CBC_Mode &&) noexcept = delete;
  CBC_Mode &operator=(const CBC_Mode &) noexcept = delete;
  CBC_Mode &operator=(CBC_Mode &&) noexcept = delete;
  ~CBC_Mode() noexcept {};

  template <typename AesEngineT> static void Encryption(AesEngineT *core, std::string &block, std::vector<byte> &iv) {
    if (block.size() != 16) [[unlikely]] {
      throw std::invalid_argument("Invalid block size for CBC encryption");
    }
    for (size_t i = 0; i < 16; ++i) {
      block[i] ^= iv[i];
    }
    std::vector<byte> tmpOut(16);
    core->_initStateMatrix(block);
    core->_addRoundKey(0);
    core->_initMainRounds();
    core->_finalRound(AesEngineT::Nr);
    core->_setOutput(tmpOut);
    block = std::string(tmpOut.begin(), tmpOut.end());
    iv = std::move(tmpOut);
  }

  template <typename AesEngineT> static void Decryption(AesEngineT *core, std::string &block, std::vector<byte> &iv) {
    if (block.size() != 16) [[unlikely]] {
      throw std::invalid_argument("Invalid block size for CBC decryption");
    }
    std::vector<byte> tmpOut(16);
    core->_initStateMatrix(block);
    core->_addRoundKey(AesEngineT::Nr);
    core->_initMainRounds();
    core->_finalRound(0);
    core->_setOutput(tmpOut);

    for (size_t i = 0; i < 16; ++i) {
      tmpOut[i] ^= iv[i];
    }
    iv.assign(block.begin(), block.end());
    block = std::string(tmpOut.begin(), tmpOut.end());
  }
};

class CTR_Mode {
public:
  CTR_Mode() noexcept {};
  CTR_Mode(const CTR_Mode &) noexcept = delete;
  CTR_Mode(CTR_Mode &&) noexcept = delete;
  CTR_Mode &operator=(const CTR_Mode &) noexcept = delete;
  CTR_Mode &operator=(CTR_Mode &&) noexcept = delete;
  ~CTR_Mode() noexcept {};

  static std::vector<byte> join(const std::vector<byte> &nonce, uint64_t counter) {
    size_t nonce_size = nonce.size();
    if (nonce_size > 16) {
      throw std::invalid_argument("Nonce size exceeds 16 bytes!");
    }
    std::vector<byte> ksbuffer(16, 0);
    std::copy(nonce.begin(), nonce.end(), ksbuffer.begin());

    for (size_t i = 0; i < 8 && (nonce_size + i) < 16; ++i) {
      ksbuffer[nonce_size + i] = (counter >> (8 * (7 - i))) & 0xFF;
    }
    return ksbuffer;
  }

  template <typename AesEngineT> __attribute__((hot, always_inline)) inline static void Encryption(AesEngineT *core, std::string &block, std::vector<byte> &keystream) {
    size_t blocksize = block.length();
    std::string result;
    for (int i = 0; i < blocksize; i += 16) {
      size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
      std::string dblock;
      for (int c = 0; c < offset; ++c) {
        dblock += block[i + c];
      }
      for (int c = 0; c < dblock.size(); ++c) {
        dblock[c] ^= keystream[c];
      }
      result += dblock;
    }
    block = std::move(result);
  }

  template <typename AesEngineT> __attribute__((hot, always_inline)) inline static void Decryption(AesEngineT *core, std::string &block, std::vector<byte> &keystream) {
    Encryption(core, block, keystream);
  }
};

class OFB_Mode {
public:
  OFB_Mode() noexcept {};
  OFB_Mode(const OFB_Mode &) noexcept = delete;
  OFB_Mode(OFB_Mode &&) noexcept = delete;
  OFB_Mode &operator=(const OFB_Mode &) noexcept = delete;
  OFB_Mode &operator=(OFB_Mode &&) noexcept = delete;
  ~OFB_Mode() noexcept {};

  template <typename AesEngineT> static void Encryption(AesEngineT *core, std::string &block, std::vector<byte> &keystream) {
    size_t blocksize = block.length();
    std::string result;
    for (int i = 0; i < blocksize; i += 16) {
      size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
      std::string dblock;
      for (int c = 0; c < offset; ++c) {
        dblock += block[i + c];
      }
      for (int c = 0; c < dblock.size(); ++c) {
        dblock[c] ^= keystream[c];
      }
      result += dblock;
    }
    block = std::move(result);
  }

  template <typename AesEngineT> static void Decryption(AesEngineT *core, std::string &block, std::vector<byte> &keystream) { Encryption(core, block, keystream); }
};

class CFB_Mode {
public:
  CFB_Mode() noexcept {};
  CFB_Mode(const CFB_Mode &) noexcept = delete;
  CFB_Mode(CFB_Mode &&) noexcept = delete;
  CFB_Mode &operator=(const CFB_Mode &) noexcept = delete;
  CFB_Mode &operator=(CFB_Mode &&) noexcept = delete;
  ~CFB_Mode() noexcept {};

  template <typename AesEngineT> static void Encryption(AesEngineT *core, std::string &block, std::vector<byte> &keystream) {
    size_t blocksize = block.length();
    std::string result;
    for (int i = 0; i < blocksize; i += 16) {
      size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
      std::string dblock;
      for (int c = 0; c < offset; ++c) {
        dblock += block[i + c];
      }
      for (int c = 0; c < dblock.size(); ++c) {
        dblock[c] ^= keystream[c];
      }
      result += dblock;
    }
    block = std::move(result);
  }

  template <typename AesEngineT> static void Decryption(AesEngineT *core, std::string &block, std::vector<byte> &keystream) { Encryption(core, block, keystream); }
};

class GCM_Mode {
public:
  GCM_Mode() noexcept {};
  GCM_Mode(const GCM_Mode &) noexcept = delete;
  GCM_Mode(GCM_Mode &&) noexcept = delete;
  GCM_Mode &operator=(const GCM_Mode &) noexcept = delete;
  GCM_Mode &operator=(GCM_Mode &&) noexcept = delete;
  ~GCM_Mode() noexcept {};

  template <typename AesEngineT> static void Encryption(AesEngineT *core, std::string &block, std::vector<byte> &iv, std::vector<byte> &authTag) {}

  template <typename AesEngineT> static void Decryption(AesEngineT *core, std::string &block, std::vector<byte> &iv, std::vector<byte> &authTag) {}
};

template <uint16_t BlockSz, AESMode Mode>
class AES_Encryption<BlockSz, Mode, typename std::enable_if<IsValidModeOfOperation<Mode>::value>::type, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type>
    : public AesEngine<BlockSz> {
  AESMode M = Mode;

public:
  std::vector<byte> iv;
  std::vector<byte> authTag;
  uint64_t counter = 0;
  AES_Encryption() noexcept = default;
  AES_Encryption(const AES_Encryption &) noexcept = delete;
  AES_Encryption(AES_Encryption &&) noexcept = delete;

  __attribute__((cold)) const std::vector<byte> apply(const std::string &input, const std::string &key) {
    std::vector<byte> result;
    this->_generateAesConstants();
    this->_validateParameters(input, key);
    this->_bindParameters((Mode == AESMode::CTR || Mode == AESMode::OFB || Mode == AESMode::CFB ? input : this->_addPadding(input)), key);
    this->_stateInitialization();
    this->_keySchedule();
    this->_modeTransformation(result);
    return result;
  };

  ~AES_Encryption() noexcept override = default;

  void _modeTransformation(std::vector<byte> &out) {
    if (Mode == AESMode::CTR) {
      std::string block = std::string(this->parameter.data.begin(), this->parameter.data.end());
      size_t blocksize = this->parameter.data.size();
      for (int i = 0; i < blocksize; i += 16) {
        std::vector<byte> ks, r;
        std::string in, k;
        AES_Encryption<128, AESMode::ECB> E;
        ks = CTR_Mode::join(this->iv, this->counter);
        in = std::string(ks.begin(), ks.end());
        k = std::string(this->parameter.key.begin(), this->parameter.key.end());

        r = E.apply(in, k);

        size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
        std::string dblock;
        for (int c = 0; c < offset; ++c) {
          dblock += block[i + c];
        }
        for (int c = 0; c < dblock.size(); ++c) {
          dblock[c] ^= r[c];
        }
        for (int g = 0; g < dblock.length(); ++g) {
          out.push_back(dblock[g]);
        }
        ++this->counter;
      }

    } else if (Mode == AESMode::OFB) {

      size_t blocksize = this->parameter.data.size();
      std::string result;
      for (int i = 0; i < blocksize; i += 16) {

        std::vector<byte> ks, r;
        std::string in, k, block;
        AES_Encryption<128, AESMode::ECB> E;
        ks = this->iv;
        in = std::string(ks.begin(), ks.end());
        k = std::string(this->parameter.key.begin(), this->parameter.key.end());
        block = std::string(this->parameter.data.begin(), this->parameter.data.end());
        r = E.apply(in, k);

        size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
        std::string dblock;
        for (int c = 0; c < offset; ++c) {
          dblock += block[i + c];
        }
        for (int c = 0; c < dblock.size(); ++c) {
          dblock[c] ^= r[c];
        }
        for (int g = 0; g < dblock.length(); ++g) {
          out.push_back(dblock[g]);
        }
        this->iv.assign(r.begin(), r.end());
      }

    } else if (Mode == AESMode::CFB) {

      size_t blocksize = this->parameter.data.size();
      std::string result;
      for (int i = 0; i < blocksize; i += 16) {

        std::vector<byte> ks, r;
        std::string in, k, block;
        AES_Encryption<128, AESMode::ECB> E;
        ks = this->iv;
        in = std::string(ks.begin(), ks.end());
        k = std::string(this->parameter.key.begin(), this->parameter.key.end());
        block = std::string(this->parameter.data.begin(), this->parameter.data.end());
        r = E.apply(in, k);

        size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
        std::string dblock;
        for (int c = 0; c < offset; ++c) {
          dblock += block[i + c];
        }
        for (int c = 0; c < dblock.size(); ++c) {
          dblock[c] ^= r[c];
        }
        for (int g = 0; g < dblock.length(); ++g) {
          out.push_back(dblock[g]);
        }
        this->iv.assign(dblock.begin(), dblock.end());
      }

    } else {
      std::vector<byte> tmp(16);
      for (uint8_t i = 0; i < this->parameter.data.size(); i += 16) {
        std::string block(this->parameter.data.begin() + i, this->parameter.data.begin() + i + 16);
        this->_createBlock(block, i);
        switch ((int)M) {
        case AESMode::ECB:
          ECB_Mode::Encryption(this, block);
          break;
        case AESMode::CBC:
          CBC_Mode::Encryption(this, block, this->iv);
          break;
        case AESMode::GCM:
          GCM_Mode::Encryption(this, block, this->iv, this->authTag);
          break;
        default:
          throw std::invalid_argument("invalid AES mode of operation, valid modes are(ECB, OFB, CBC, CTR, ECB, GCM)");
        }
        this->_blockDigest(tmp, out, block);
      }
    }
  };

  void _generateAesConstants() noexcept override {
    AESUtils::createSBox(AESUtils::SBox);
    AESUtils::createRCon(AESUtils::RCon);
    AESUtils::createMixCols(AESUtils::MixCols);
  }

  void _execRound(const uint8_t r) override {
    this->_subBytes();
    this->_shiftRows();
    this->_mixColumns();
    this->_addRoundKey(r);
  }

  void _finalRound(const uint8_t r) override {
    this->_subBytes();
    this->_shiftRows();
    this->_addRoundKey(r);
  }

  inline void _initMainRounds() override {
    for (uint8_t r = 1; r < AesEngine<BlockSz>::Nr; ++r) {
      this->_execRound(r);
    }
  }
};
template <uint16_t BlockSz, AESMode Mode>
class AES_Decryption<BlockSz, Mode, typename std::enable_if<IsValidModeOfOperation<Mode>::value>::type, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type>
    : public AesEngine<BlockSz> {
public:
  AESMode M = Mode;
  std::vector<byte> iv;
  std::vector<byte> authTag;
  uint64_t counter = 0;

  AES_Decryption() noexcept = default;
  AES_Decryption(const AES_Decryption &) noexcept = delete;
  AES_Decryption(AES_Decryption &&) noexcept = delete;

  __attribute__((cold)) const std::vector<byte> apply(const std::string &input, const std::string &key) {
    std::vector<byte> result;
    this->_generateAesConstants();
    this->_validateParameters(input, key);
    this->_bindParameters(input, key);
    this->_stateInitialization();
    this->_keySchedule();
    this->_modeTransformation(result);
    this->_pkcs7Dettach(result);
    return result;
  }

  ~AES_Decryption() noexcept override = default;

  void _modeTransformation(std::vector<byte> &out) {
    if (Mode == AESMode::CTR) {
      std::string block = std::string(this->parameter.data.begin(), this->parameter.data.end());
 size_t blocksize = this->parameter.data.size();
    for (int i = 0; i < blocksize; i += 16) {
       std::vector<byte> ks, r;
      std::string in, k;
      AES_Encryption<128, AESMode::ECB> E;
      ks = CTR_Mode::join(this->iv, this->counter);
      in = std::string(ks.begin(), ks.end());
      k = std::string(this->parameter.key.begin(), this->parameter.key.end());
      
      r = E.apply(in, k);
      
      size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
      std::string dblock;
      for (int c = 0; c < offset; ++c) {
        dblock += block[i + c];
      }
      for (int c = 0; c < dblock.size(); ++c) {
        dblock[c] ^= r[c];
      }
     for (int g = 0; g < dblock.length(); ++g) {
        out.push_back(dblock[g]);
      }
      ++this->counter;
    }
    } else if (Mode == AESMode::OFB) {

      size_t blocksize = this->parameter.data.size();
      std::string result;
      for (int i = 0; i < blocksize; i += 16) {

        std::vector<byte> ks, r;
        std::string in, k, block;
        AES_Encryption<128, AESMode::ECB> E;
        ks = this->iv;
        in = std::string(ks.begin(), ks.end());
        k = std::string(this->parameter.key.begin(), this->parameter.key.end());
        block = std::string(this->parameter.data.begin(), this->parameter.data.end());
        r = E.apply(in, k);

        size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
        std::string dblock;
        for (int c = 0; c < offset; ++c) {
          dblock += block[i + c];
        }
        for (int c = 0; c < dblock.size(); ++c) {
          dblock[c] ^= r[c];
        }
        for (int g = 0; g < dblock.length(); ++g) {
          out.push_back(dblock[g]);
        }
        this->iv.assign(r.begin(), r.end());
      }

    } else if (Mode == AESMode::CFB) {
      size_t blocksize = this->parameter.data.size();
      std::string result;
      for (int i = 0; i < blocksize; i += 16) {

        std::vector<byte> ks, r;
        std::string in, k, block;
        AES_Encryption<128, AESMode::ECB> E;
        ks = this->iv;
        in = std::string(ks.begin(), ks.end());
        k = std::string(this->parameter.key.begin(), this->parameter.key.end());
        block = std::string(this->parameter.data.begin(), this->parameter.data.end());
        std::string pblock = block;
        r = E.apply(in, k);

        size_t offset = blocksize - i >= 16 ? 16 : blocksize - i;
        std::string dblock;
        for (int c = 0; c < offset; ++c) {
          dblock += block[i + c];
        }
        for (int c = 0; c < dblock.size(); ++c) {
          dblock[c] ^= r[c];
        }
        for (int g = 0; g < dblock.length(); ++g) {
          out.push_back(dblock[g]);
        }
        this->iv.assign(pblock.begin(), pblock.end());
      }
    } else {
      std::vector<byte> tmp(16);

      for (uint8_t i = 0; i < this->parameter.data.size(); i += 16) {
        std::string block(this->parameter.data.begin() + i, this->parameter.data.begin() + i + 16);
        this->_createBlock(block, i);
        switch ((int)M) {
        case AESMode::ECB:
          ECB_Mode::Decryption(this, block);
          break;
        case AESMode::CBC:
          CBC_Mode::Decryption(this, block, this->iv);
          break;
        case AESMode::GCM:
          GCM_Mode::Decryption(this, block, this->iv, this->authTag);
          break;
        default:
          throw std::invalid_argument("invalid AES mode of operation, valid modes are(ECB, OFB, CBC, CTR, ECB, GCM)");
        }
        this->_blockDigest(tmp, out, block);
      }
    }
  };

  void _generateAesConstants() noexcept override {
    AESUtils::createInvSBox(AESUtils::SBox, AESUtils::InvSBox);
    AESUtils::createRCon(AESUtils::RCon);
    AESUtils::createInvMixCols(AESUtils::InvMixCols);
  }

  void _execRound(const uint8_t r) override {
    this->_invShiftRows();
    this->_invSubBytes();
    this->_addRoundKey(r);
    this->_invMixColumns();
  }

  void _finalRound(const uint8_t r) override {
    this->_invShiftRows();
    this->_invSubBytes();
    this->_addRoundKey(r);
  }

  inline void _initMainRounds() override {
    for (uint8_t round = AesEngine<BlockSz>::Nr - 1; round > 0; --round) {
      this->_invShiftRows();
      this->_invSubBytes();
      this->_addRoundKey(round);
      this->_invMixColumns();
    }
  }
};

namespace Test {

class CSPRNG;

// implementing slightly more secure version of a PRNG for unix like OSs, because i dont know how to do that
// for windows ...
#if defined(__linux__) || defined(__unix) || defined(__unix__)
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
    // a readable format ...
    const char alpha[26 * 2 + 22] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                                     'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                     'Y', 'Z', '.', ',', '!', '@', '#', '$', '%', '^', '&', '*', '+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    if (key_size != AES128KS && key_size != AES256KS && key_size != AES192KS)
      return "";
    std::string seckey;
    seckey.resize(key_size / 8);
    uint16_t c = 0;
    while (c < key_size / 8) {
      seckey[c++] = alpha[CSPRNG::generate(0, 26 * 2 + 21)];
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

#else
// windows will use a less efficient version of CSPRNG , why? because im not a windows user...
// here will use a mersenne twister PRNG instead...
class CSPRNG {
public:
  explicit CSPRNG() noexcept {};
  ~CSPRNG() noexcept = default;
  static const std::string genSecKeyBlock(const uint16_t ks) { return AESUtils::genSecKeyBlock(ks); };
};

#endif

static const std::string cPlaintext("this is a secret message to deliver!");
static std::string plaintext(cPlaintext.begin(), cPlaintext.begin() + 1);
static std::string keyAES128(CSPRNG::genSecKeyBlock(128));
static std::string keyAES192(CSPRNG::genSecKeyBlock(192));
static std::string keyAES256(CSPRNG::genSecKeyBlock(256));
static std::vector<byte> IV(16), authTag(16);

static size_t tscore = 3 * 6;
static size_t S_THRESHOLD = 0;

static constexpr size_t exec_delay = 10; // delay between each execution(ms)

// AES ECB Mode, multiple key size constructors
AES_Encryption<AES128KS, AESMode::ECB> aesECB128Encryptor;
AES_Encryption<AES192KS, AESMode::ECB> aesECB192Encryptor;
AES_Encryption<AES256KS, AESMode::ECB> aesECB256Encryptor;

AES_Decryption<AES128KS, AESMode::ECB> aesECB128Decryptor;
AES_Decryption<AES192KS, AESMode::ECB> aesECB192Decryptor;
AES_Decryption<AES256KS, AESMode::ECB> aesECB256Decryptor;

// AES ECB Mode, multiple key size constructors
AES_Encryption<AES128KS, AESMode::CBC> aesCBC128Encryptor;
AES_Encryption<AES192KS, AESMode::CBC> aesCBC192Encryptor;
AES_Encryption<AES256KS, AESMode::CBC> aesCBC256Encryptor;

AES_Decryption<AES128KS, AESMode::CBC> aesCBC128Decryptor;
AES_Decryption<AES192KS, AESMode::CBC> aesCBC192Decryptor;
AES_Decryption<AES256KS, AESMode::CBC> aesCBC256Decryptor;

AES_Encryption<AES128KS, AESMode::CTR> aesCTR128Encryptor;
AES_Encryption<AES192KS, AESMode::CTR> aesCTR192Encryptor;
AES_Encryption<AES256KS, AESMode::CTR> aesCTR256Encryptor;

AES_Decryption<AES128KS, AESMode::CTR> aesCTR128Decryptor;
AES_Decryption<AES192KS, AESMode::CTR> aesCTR192Decryptor;
AES_Decryption<AES256KS, AESMode::CTR> aesCTR256Decryptor;

AES_Encryption<AES128KS, AESMode::OFB> aesOFB128Encryptor;
AES_Encryption<AES192KS, AESMode::OFB> aesOFB192Encryptor;
AES_Encryption<AES256KS, AESMode::OFB> aesOFB256Encryptor;

AES_Decryption<AES128KS, AESMode::OFB> aesOFB128Decryptor;
AES_Decryption<AES192KS, AESMode::OFB> aesOFB192Decryptor;
AES_Decryption<AES256KS, AESMode::OFB> aesOFB256Decryptor;

AES_Encryption<AES128KS, AESMode::CFB> aesCFB128Encryptor;
AES_Encryption<AES192KS, AESMode::CFB> aesCFB192Encryptor;
AES_Encryption<AES256KS, AESMode::CFB> aesCFB256Encryptor;

AES_Decryption<AES128KS, AESMode::CFB> aesCFB128Decryptor;
AES_Decryption<AES192KS, AESMode::CFB> aesCFB192Decryptor;
AES_Decryption<AES256KS, AESMode::CFB> aesCFB256Decryptor;

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

static void runAesTest(const uint16_t ks, const AesCryptoModule::AESMode MODE = AESMode::ECB) {

  std::vector<byte> encryptedData, decryptedData;
  const std::string model(
      MODE == AESMode::ECB ? "ECB"
                           : (MODE == AESMode::CBC ? "CBC" : (MODE == AESMode::CFB ? "CFB" : (MODE == AESMode::CTR ? "CTR" : (MODE == AESMode::OFB ? "OFB" : "GCM")))));

  if (ks == AES128KS) {
    if (MODE == AESMode::ECB) {
      encryptedData = aesECB128Encryptor.apply(plaintext, keyAES128);
      decryptedData = aesECB128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
    } else if (MODE == AESMode::CBC) {
      aesCBC128Encryptor.iv = IV;
      encryptedData = aesCBC128Encryptor.apply(plaintext, keyAES128);
      aesCBC128Decryptor.iv = IV;
      decryptedData = aesCBC128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
    } else if (MODE == AESMode::CTR) {
      std::vector<byte> iv = IV;
      aesCTR128Encryptor.iv = iv;
      encryptedData = aesCTR128Encryptor.apply(plaintext, keyAES128);
      iv = IV;
      aesCTR128Decryptor.iv = iv;
      decryptedData = aesCTR128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
    } else if (MODE == AESMode::OFB) {
      std::vector<byte> iv = IV;
      aesOFB128Encryptor.iv = iv;
      encryptedData = aesOFB128Encryptor.apply(plaintext, keyAES128);
      iv = IV;
      aesOFB128Decryptor.iv = iv;
      decryptedData = aesOFB128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
    } else if (MODE == AESMode::CFB) {
      std::vector<byte> iv = IV;
      aesCFB128Encryptor.iv = iv;
      encryptedData = aesCFB128Encryptor.apply(plaintext, keyAES128);
      iv = IV;
      aesCFB128Decryptor.iv = iv;
      decryptedData = aesCFB128Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES128);
    }
    printResult(std::string("AES(128) ") += model + " -> Encrypted(Hex): ", encryptedData);
    printResult(std::string("AES(128) ") += model + " -> Decrypted(Hex): ", decryptedData);
    tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
  } else if (ks == AES192KS) {
    if (MODE == AESMode::ECB) {
      encryptedData = aesECB192Encryptor.apply(plaintext, keyAES192);
      decryptedData = aesECB192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
    } else if (MODE == AESMode::CBC) {
      aesCBC192Encryptor.iv = IV;
      encryptedData = aesCBC192Encryptor.apply(plaintext, keyAES192);
      aesCBC192Decryptor.iv = IV;
      decryptedData = aesCBC192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
    } else if (MODE == AESMode::CTR) {
      aesCTR192Encryptor.iv = IV;
      encryptedData = aesCTR192Encryptor.apply(plaintext, keyAES192);
      aesCTR192Decryptor.iv = IV;
      decryptedData = aesCTR192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
    } else if (MODE == AESMode::OFB) {
      std::vector<byte> iv = IV;
      aesOFB192Encryptor.iv = iv;
      encryptedData = aesOFB192Encryptor.apply(plaintext, keyAES192);
      iv = IV;
      aesOFB192Decryptor.iv = iv;
      decryptedData = aesOFB192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
    } else if (MODE == AESMode::CFB) {
      std::vector<byte> iv = IV;
      aesCFB192Encryptor.iv = iv;
      encryptedData = aesCFB192Encryptor.apply(plaintext, keyAES192);
      iv = IV;
      aesCFB192Decryptor.iv = iv;
      decryptedData = aesCFB192Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
    }
    printResult(std::string("AES(192) ") += model + " -> Encrypted(Hex): ", encryptedData);
    printResult(std::string("AES(192) ") += model + " -> Decrypted(Hex): ", decryptedData);
    tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
  } else {
    if (MODE == AESMode::ECB) {
      encryptedData = aesECB256Encryptor.apply(plaintext, keyAES256);
      decryptedData = aesECB256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
    } else if (MODE == AESMode::CBC) {
      aesCBC256Encryptor.iv = IV;
      encryptedData = aesCBC256Encryptor.apply(plaintext, keyAES256);
      aesCBC256Decryptor.iv = IV;
      decryptedData = aesCBC256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
    } else if (MODE == AESMode::CTR) {
      aesCTR256Encryptor.iv = IV;
      encryptedData = aesCTR256Encryptor.apply(plaintext, keyAES256);
      aesCTR256Decryptor.iv = IV;
      decryptedData = aesCTR256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
    } else if (MODE == AESMode::OFB) {
      std::vector<byte> iv = IV;
      aesOFB256Encryptor.iv = iv;
      encryptedData = aesOFB256Encryptor.apply(plaintext, keyAES256);
      iv = IV;
      aesOFB256Decryptor.iv = iv;
      decryptedData = aesOFB256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
    } else if (MODE == AESMode::CFB) {
      std::vector<byte> iv = IV;
      aesCFB256Encryptor.iv = iv;
      encryptedData = aesCFB256Encryptor.apply(plaintext, keyAES256);
      iv = IV;
      aesCFB256Decryptor.iv = iv;
      decryptedData = aesCFB256Decryptor.apply(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
    }
    printResult(std::string("AES(256) ") += model + " -> Encrypted(Hex): ", encryptedData);
    printResult(std::string("AES(256) ") += model + " -> Decrypted(Hex): ", decryptedData);
    tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
  }
};

static const uint16_t threshold = cPlaintext.length();
static uint16_t c = 0;

static void execAES128(const AESMode M) {
  c = 0;
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
    keyAES128 = CSPRNG::genSecKeyBlock(128);
    AESUtils::GenerateIvBlock(IV);
    runAesTest(128, M);
  }
  S_THRESHOLD += c;
};

static void execAES192(const AESMode M) {
  c = 0;
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
    keyAES192 = CSPRNG::genSecKeyBlock(192);
    AESUtils::GenerateIvBlock(IV);
    runAesTest(192, M);
  }
  S_THRESHOLD += c;
};

static void execAES256(const AESMode M) {
  c = 0;
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
    keyAES256 = CSPRNG::genSecKeyBlock(256);
    AESUtils::GenerateIvBlock(IV);
    runAesTest(256, M);
  }
  S_THRESHOLD += c;
};

static void run_AES_ECB_test() {
  std::cout << "\n*********** Execute AES ECB Mode ***********\n";
  std::thread([&] { execAES128(AESMode::ECB); }).join();
  std::thread([&] { execAES192(AESMode::ECB); }).join();
  std::thread([&] { execAES256(AESMode::ECB); }).join();
};

static void run_AES_CBC_test() {
  std::cout << "\n*********** Execute AES CBC Mode ***********\n";
  std::thread([&] { execAES128(AESMode::CBC); }).join();
  std::thread([&] { execAES192(AESMode::CBC); }).join();
  std::thread([&] { execAES256(AESMode::CBC); }).join();
};

static void run_AES_CTR_test() {
  std::cout << "\n*********** Execute AES CTR Mode ***********\n";
  std::thread([&] { execAES128(AESMode::CTR); }).join();
  std::thread([&] { execAES192(AESMode::CTR); }).join();
  std::thread([&] { execAES256(AESMode::CTR); }).join();
}

static void run_AES_OFB_test() {
  std::cout << "\n*********** Execute AES OFB Mode ***********\n";
  std::thread([&] { execAES128(AESMode::OFB); }).join();
  std::thread([&] { execAES192(AESMode::OFB); }).join();
  std::thread([&] { execAES256(AESMode::OFB); }).join();
}

static void run_AES_CFB_test() {
  std::cout << "\n*********** Execute AES CFB Mode ***********\n";
  std::thread([&] { execAES128(AESMode::CFB); }).join();
  std::thread([&] { execAES192(AESMode::CFB); }).join();
  std::thread([&] { execAES256(AESMode::CFB); }).join();
}

// run aes in all modes(ECB, CBC, OFB, CTR, CFB, GCM)
static void runGlobal() {

  printPlaintext();

  // std::string data = "abcdefghijklmnopqrst";
  // std::string key = AESUtils::genSecKeyBlock(128);
  // std::vector<byte> IV, iv;
  // AESUtils::GenerateIvBlock(IV);
  // iv = IV;

  // AES_Encryption<128, AESMode::CFB> E;
  // AES_Decryption<128, AESMode::CFB> D;

  // E.iv = iv;
  // auto enc = E.apply(data, key);
  // std::cout << "Encrypted: ";
  // for (auto x : enc)
  //   std::cout << std::hex << std::setw(2) << (int)x << " ";
  // std::cout << "\n";

  // iv = IV;
  // D.iv = iv;
  // auto dec = D.apply(std::string(enc.begin(), enc.end()), key);
  // std::cout << "Decrypted: ";
  // for (auto x : dec)
  //   std::cout << std::hex << std::setw(2) << (int)x << " ";
  // std::cout << "\n";

  run_AES_ECB_test();
  run_AES_CBC_test();
  run_AES_CTR_test();
  run_AES_OFB_test();
  run_AES_CFB_test();

  std::cout << "Tests Finished... total tests passed = " << std::dec << (int)tscore << "/" << (int)S_THRESHOLD << "\n";
};

}; // namespace Test
}; // namespace AesCryptoModule

#endif

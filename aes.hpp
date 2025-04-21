#pragma once
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>  // basically for the CSPRNG operation
#include <iomanip>  // needed to print as hex format
#include <iostream> // required for the CSPRNG function
#include <stdexcept>
#include <string>
#include <thread> // for std::this_thread::sleep_for(...)
#include <type_traits>
#include <vector>

using uint8_t = unsigned char;
using uint16_t = unsigned short int;
using uint32_t = unsigned int;
using uint64_t = unsigned long int;
using size_t = unsigned long int;

#ifndef UINT64_MAX
#define UINT64_MAX (uint64_t)1844674407370955161
#endif

#ifndef __MFAES_BLOCK_CIPHER_lbv01__
#define __MFAES_BLOCK_CIPHER_lbv01__ 0x01

constexpr uint16_t AES128KS = (0b0001 << 0b0111);
constexpr uint16_t AES192KS = 192;
constexpr uint16_t AES256KS = (0b01000000 << 0b010);
constexpr uint8_t AES128_ROUNDS = 10;
constexpr uint8_t AES256_ROUNDS = 14;

using byte = uint8_t;

namespace AesCryptoModule {

/** Apply specific improvements when compiking with GNU Compiler, optimization... */
#ifdef __GNUC__

class PRNG {
private:
  static constexpr size_t N = 624;
  static constexpr size_t M = 397;
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

namespace AESCrypto {

template <uint16_t BlockSz> struct IsValidBlockSize {
  static constexpr bool value = (BlockSz == AES128KS || BlockSz == AES192KS || BlockSz == AES256KS);
};

template <uint16_t BlockSz, typename Enable = void> class AES_Encryption;
template <uint16_t BlockSz, typename Enable = void> class AES_Decryption;
template <uint16_t BlockSz, typename Enable = void> class AesEngine;

using RoundKeysT = std::vector<std::vector<byte>>;
using StateMatrixT = RoundKeysT;

template <uint16_t BlockSz> class AesEngine<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> {
protected:
  static constexpr byte Nk = BlockSz / 32;
  static constexpr byte Nr = BlockSz == AES128KS ? AES128_ROUNDS : (BlockSz == AES192KS ? 12 : AES256_ROUNDS);
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

protected:
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
      temp[0] = __gfmultip14(this->state_matrix[0][i]) ^ __gfmultip11(this->state_matrix[1][i]) ^ __gfmultip13(this->state_matrix[2][i]) ^ __gfmultip9(this->state_matrix[3][i]);
      temp[1] = __gfmultip9(this->state_matrix[0][i]) ^ __gfmultip14(this->state_matrix[1][i]) ^ __gfmultip11(this->state_matrix[2][i]) ^ __gfmultip13(this->state_matrix[3][i]);
      temp[2] = __gfmultip13(this->state_matrix[0][i]) ^ __gfmultip9(this->state_matrix[1][i]) ^ __gfmultip14(this->state_matrix[2][i]) ^ __gfmultip11(this->state_matrix[3][i]);
      temp[3] = __gfmultip11(this->state_matrix[0][i]) ^ __gfmultip13(this->state_matrix[1][i]) ^ __gfmultip9(this->state_matrix[2][i]) ^ __gfmultip14(this->state_matrix[3][i]);
      for (uint8_t j = 0; j < 4; ++j) {
        this->state_matrix[j][i] = temp[j];
      }
    }
  }

  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip2(const byte x) const noexcept { return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00); }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip3(const byte x) const noexcept { return __gfmultip2(x) ^ x; }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip9(const byte x) const noexcept { return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ x; }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip11(const byte x) const noexcept { return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(x) ^ x; }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip13(const byte x) const noexcept {
    return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(__gfmultip2(x)) ^ x;
  }
  __attribute__((hot, nothrow, pure)) inline constexpr byte __gfmultip14(const byte x) const noexcept {
    return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(__gfmultip2(x)) ^ __gfmultip2(x);
  }

  virtual void _execMainRounds() {};
  __attribute__((cold)) virtual void _execFinalRounds() {};
  __attribute__((cold)) virtual void _generateAesConstants() noexcept {};
  virtual void _applyRijndaelTrasformation() {};
  inline void _initMainRounds() {
    for (uint8_t r = 1; r < Nr; ++r) {
      _execMainRounds();
    }
  }

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
};

template <uint16_t BlockSz> class AES_Encryption<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> : public AesEngine<BlockSz> {
public:
  AES_Encryption() noexcept = default;
  AES_Encryption(const AES_Encryption &) noexcept = delete;
  AES_Encryption(AES_Encryption &&) noexcept = delete;

  __attribute__((cold)) const std::vector<byte> call(const std::string &input, const std::string &key) {
    this->_generateAesConstants();
    this->_validateParameters(input, key);
    this->_bindParameters(this->_addPadding(input), key);
    this->_stateInitialization();
    this->_keySchedule();
    std::vector<byte> result;
    this->_applyRijndaelTrasformation(result);
    return result;
  };

  ~AES_Encryption() noexcept override = default;

private:
  void _applyRijndaelTrasformation(std::vector<byte> &out) {
    std::vector<byte> tmpOut(16);
    for (uint8_t i = 0; i < this->parameter.data.size(); i += 16) {
      const std::string dblock(this->parameter.data.begin() + i, this->parameter.data.begin() + i + 16);
      this->_initStateMatrix(dblock);
      this->_addRoundKey(0);
      this->_initMainRounds();
      this->_execFinalRounds();
      this->_setOutput(tmpOut);
      out.insert(out.end(), tmpOut.begin(), tmpOut.end());
    }
  };

  void _generateAesConstants() noexcept override {
    AESUtils::createSBox(AESUtils::SBox);
    AESUtils::createRCon(AESUtils::RCon);
    AESUtils::createMixCols(AESUtils::MixCols);
  }

  void _execMainRounds() override {
    this->_subBytes();
    this->_shiftRows();
    this->_mixColumns();
    this->_addRoundKey(0);
  }

  void _execFinalRounds() override {
    this->_subBytes();
    this->_shiftRows();
    this->_addRoundKey(0);
  }
};
template <uint16_t BlockSz> class AES_Decryption<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> : public AesEngine<BlockSz> {
public:
  AES_Decryption() noexcept = default;
  AES_Decryption(const AES_Decryption &) noexcept = delete;
  AES_Decryption(AES_Decryption &&) noexcept = delete;

  __attribute__((cold)) const std::vector<byte> call(const std::string &input, const std::string &key) {
    this->_generateAesConstants();
    this->_validateParameters(input, key);
    this->_bindParameters(input, key);
    this->_stateInitialization();
    this->_keySchedule();
    std::vector<byte> result;
    this->_applyRijndaelTrasformation(result);
    this->_pkcs7Dettach(result);
    return result;
  }
  ~AES_Decryption() noexcept override = default;

private:
  void _applyRijndaelTrasformation(std::vector<byte> &out) {
    for (uint8_t i = 0; i < this->parameter.data.size(); i += 16) {
      const std::string dblock(this->parameter.data.begin() + i, this->parameter.data.begin() + i + 16);
      this->_initStateMatrix(dblock);
      this->_addRoundKey(0);
      this->_initMainRounds();
      this->_execFinalRounds();
      std::vector<byte> tmp(16);
      this->_setOutput(tmp);
      out.insert(out.end(), tmp.begin(), tmp.end());
    }
  }
  void _generateAesConstants() noexcept override {
    AESUtils::createInvSBox(AESUtils::SBox, AESUtils::InvSBox);
    AESUtils::createRCon(AESUtils::RCon);
    AESUtils::createInvMixCols(AESUtils::InvMixCols);
  }

  void _execMainRounds() override {
    this->_invShiftRows();
    this->_invSubBytes();
    this->_addRoundKey(0);
    this->_invMixColumns();
  }

  void _execFinalRounds() override {
    this->_invShiftRows();
    this->_invSubBytes();
    this->_addRoundKey(0);
  }
};

} // namespace AESCrypto

#endif

/** No GNU compiler... */
#else

class PRNG {
private:
  static constexpr size_t N = 624;
  static constexpr size_t M = 397;
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

  const size_t MersenneTwister(const size_t min, const size_t max) {
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

  void reseed(size_t new_seed) {
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

  static constexpr byte galloisFieldMultiplication(byte a, byte b) noexcept {
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

  static constexpr byte galloisFieldInverse(byte x) noexcept {
    byte y = x;
    for (uint16_t i = 0; i < 4; ++i) {
      y = galloisFieldMultiplication(y, y);
      y = galloisFieldMultiplication(y, x);
    }
    return y;
  }

  static constexpr byte affineTransform(byte x) noexcept {
    byte result = 0x63;
    for (uint16_t i = 0; i < 8; ++i) {
      result ^= (x >> i) & 1 ? (0xF1 >> (7 - i)) & 0xFF : 0;
    }
    return result;
  }

  static constexpr byte createSBoxEntry(byte x) noexcept { return affineTransform(galloisFieldInverse(x)); }

  static constexpr void createSBox(std::array<byte, 256> &sbox) noexcept {
    for (uint16_t i = 0; i < 256; ++i) {
      sbox[i] = createSBoxEntry(static_cast<byte>(i));
    }
  }

  static constexpr void createInvSBox(const std::array<byte, 256> &sbox, std::array<byte, 256> &invSbox) noexcept {
    for (uint16_t i = 0; i < 256; ++i) {
      invSbox[sbox[i]] = static_cast<byte>(i);
    }
  }

  static constexpr void createRCon(std::array<byte, 256> &rcon) noexcept {
    byte c = 1;
    for (uint16_t i = 0; i < 256; ++i) {
      rcon[i] = c;
      c = galloisFieldMultiplication(c, 0x02);
    }
  }

  static constexpr void createMixCols(std::array<std::array<byte, 4>, 4> &mixCols) noexcept {
    mixCols[0] = {0x02, 0x03, 0x01, 0x01};
    mixCols[1] = {0x01, 0x02, 0x03, 0x01};
    mixCols[2] = {0x01, 0x01, 0x02, 0x03};
    mixCols[3] = {0x03, 0x01, 0x01, 0x02};
  }

  static constexpr void createInvMixCols(std::array<std::array<byte, 4>, 4> &invMixCols) noexcept {
    invMixCols[0] = {0x0E, 0x0B, 0x0D, 0x09};
    invMixCols[1] = {0x09, 0x0E, 0x0B, 0x0D};
    invMixCols[2] = {0x0D, 0x09, 0x0E, 0x0B};
    invMixCols[3] = {0x0B, 0x0D, 0x09, 0x0E};
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

namespace AESCrypto {

template <uint16_t BlockSz> struct IsValidBlockSize {
  static constexpr bool value = (BlockSz == AES128KS || BlockSz == AES256KS);
};

template <uint16_t BlockSz, typename Enable = void> class AES_Encryption;
template <uint16_t BlockSz, typename Enable = void> class AES_Decryption;
template <uint16_t BlockSz, typename Enable = void> class AesEngine;

using RoundKeysT = std::vector<std::vector<byte>>;
using StateMatrixT = RoundKeysT;

template <uint16_t BlockSz> class AesEngine<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> {
protected:
  static constexpr byte Nk = BlockSz / 32;
  static constexpr byte Nr = BlockSz == AES128KS ? AES128_ROUNDS : AES256_ROUNDS;
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

protected:
  void _validateParameters(const std::string &input, const std::string &key) {
    this->iSz = input.size();
    this->kSz = key.size();
    if (this->iSz >= UINT64_MAX || this->iSz == 0 || (this->kSz != (AES256KS / 8) && this->kSz != (AES128KS / 8))) [[unlikely]] {
      throw std::invalid_argument("invalid input or key!");
    }
  }

  inline void _bindParameters(const std::string &input, const std::string &key) {
    this->parameter.data.assign(input.begin(), input.end());
    this->parameter.key.assign(key.begin(), key.end());
  }

  inline void _stateInitialization() {
    this->state_matrix.resize(Nr + 1, std::vector<byte>(Nb));
    this->round_keys.resize((Nr + 1) * Nb, std::vector<byte>(Nb));
  }

  inline void _eraseData() noexcept {
    this->state_matrix.clear();
    this->round_keys.clear();
    this->parameter.data.clear();
    this->parameter.key.clear();
  }

  void _keySchedule() {
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

  inline void _keyRotate(std::vector<byte> &data, size_t positions) {
    if (data.empty()) [[unlikely]]
      return;
    positions %= data.size();
    if (positions == 0) [[unlikely]]
      return;

    std::reverse(data.begin(), data.begin() + positions);
    std::reverse(data.begin() + positions, data.end());
    std::reverse(data.begin(), data.end());
  }

  inline void _addRoundKey(size_t round) noexcept {
    for (byte r = 0; r < Nb; ++r) {
      for (byte k = 0; k < Nb; ++k) {
        this->state_matrix[k][r] ^= this->round_keys[round * Nb + r][k];
      }
    }
  }

  inline void _subBytes() noexcept {
    for (auto &row : this->state_matrix) {
      std::transform(row.begin(), row.end(), row.begin(), [](byte b) { return AESUtils::SBox[b]; });
    }
  }

  inline void _invSubBytes() noexcept {
    for (auto &row : this->state_matrix) {
      std::transform(row.begin(), row.end(), row.begin(), [](byte b) { return AESUtils::InvSBox[b]; });
    }
  }

  inline void _shiftRows() noexcept {
    for (uint8_t i = 1; i < Nb; ++i) {
      this->_keyRotate(this->state_matrix[i], i);
    }
  }

  inline void _invShiftRows() noexcept {
    for (uint8_t i = 1; i < Nb; ++i) {
      this->_keyRotate(this->state_matrix[Nb - i], i);
    }
  }

  inline void _mixColumns() noexcept {
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

  inline void _invMixColumns() noexcept {
    for (uint8_t i = 0; i < Nb; ++i) {
      std::array<byte, 4> temp;
      temp[0] = __gfmultip14(this->state_matrix[0][i]) ^ __gfmultip11(this->state_matrix[1][i]) ^ __gfmultip13(this->state_matrix[2][i]) ^ __gfmultip9(this->state_matrix[3][i]);
      temp[1] = __gfmultip9(this->state_matrix[0][i]) ^ __gfmultip14(this->state_matrix[1][i]) ^ __gfmultip11(this->state_matrix[2][i]) ^ __gfmultip13(this->state_matrix[3][i]);
      temp[2] = __gfmultip13(this->state_matrix[0][i]) ^ __gfmultip9(this->state_matrix[1][i]) ^ __gfmultip14(this->state_matrix[2][i]) ^ __gfmultip11(this->state_matrix[3][i]);
      temp[3] = __gfmultip11(this->state_matrix[0][i]) ^ __gfmultip13(this->state_matrix[1][i]) ^ __gfmultip9(this->state_matrix[2][i]) ^ __gfmultip14(this->state_matrix[3][i]);
      for (uint8_t j = 0; j < 4; ++j) {
        this->state_matrix[j][i] = temp[j];
      }
    }
  }

  inline constexpr byte __gfmultip2(const byte x) const noexcept { return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00); }
  inline constexpr byte __gfmultip3(const byte x) const noexcept { return __gfmultip2(x) ^ x; }
  inline constexpr byte __gfmultip9(const byte x) const noexcept { return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ x; }
  inline constexpr byte __gfmultip11(const byte x) const noexcept { return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(x) ^ x; }
  inline constexpr byte __gfmultip13(const byte x) const noexcept { return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(__gfmultip2(x)) ^ x; }
  inline constexpr byte __gfmultip14(const byte x) const noexcept { return __gfmultip2(__gfmultip2(__gfmultip2(x))) ^ __gfmultip2(__gfmultip2(x)) ^ __gfmultip2(x); }

  virtual void _execMainRounds() {};
  virtual void _execFinalRounds() {};
  virtual void _generateAesConstants() noexcept {};
  virtual void _applyRijndaelTrasformation() {};
  inline void _initMainRounds() {
    for (uint8_t r = 1; r < Nr; ++r) {
      _execMainRounds();
    }
  }

  inline void _initStateMatrix(const std::string &bytes) noexcept {
    for (byte r = 0; r < Nb; ++r) {
      for (byte c = 0; c < Nb; ++c) {
        this->state_matrix[r][c] = bytes[r + Nb * c];
      }
    }
  }

  inline void _setOutput(std::vector<byte> &out) noexcept {
    for (uint8_t i = 0; i < 4; ++i) {
      for (uint8_t j = 0; j < Nb; ++j) {
        out[i + 4 * j] = this->state_matrix[i][j];
      }
    }
  }

  inline std::string _pkcs7Attach(const std::string &input, size_t blockSize) noexcept {
    uint8_t paddingSize = blockSize - (input.size() % blockSize);
    std::string padded(input);
    padded.reserve(input.size() + paddingSize);
    while (padded.size() < input.size() + paddingSize) {
      padded.push_back(static_cast<char>(paddingSize));
    }
    return padded;
  }

  inline void _pkcs7Dettach(std::vector<uint8_t> &data) noexcept {
    if (data.empty()) [[unlikely]] {
      return;
    }
    const uint8_t paddingSize = data.back();
    if (paddingSize > BlockSz / 8) [[unlikely]] {
      return;
    }
    data.erase(data.end() - paddingSize, data.end());
  }

  inline const std::string _addPadding(const std::string &input) noexcept {
    if (input.length() % 16 == 0) [[unlikely]] {
      return input;
    }
    const std::string paddedInput = this->_pkcs7Attach(input, BlockSz / 8);
    this->iSz = paddedInput.size();
    return paddedInput;
  }
};

template <uint16_t BlockSz> class AES_Encryption<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> : public AesEngine<BlockSz> {
public:
  AES_Encryption() noexcept = delete;
  AES_Encryption(const AES_Encryption &) noexcept = delete;
  AES_Encryption(AES_Encryption &&) noexcept = delete;

  AES_Encryption(const std::string &input, std::vector<byte> &out, const std::string &key) {
    this->_generateAesConstants();
    this->_validateParameters(input, key);
    this->_bindParameters(this->_addPadding(input), key);
    this->_stateInitialization();
    this->_keySchedule();
    this->_applyRijndaelTrasformation(out);
  };

  ~AES_Encryption() noexcept override = default;

private:
  void _applyRijndaelTrasformation(std::vector<byte> &out) {
    std::vector<byte> tmpOut(16);
    for (uint8_t i = 0; i < this->parameter.data.size(); i += 16) {
      const std::string dblock(this->parameter.data.begin() + i, this->parameter.data.begin() + i + 16);
      this->_initStateMatrix(dblock);
      this->_addRoundKey(0);
      this->_initMainRounds();
      this->_execFinalRounds();
      this->_setOutput(tmpOut);
      out.insert(out.end(), tmpOut.begin(), tmpOut.end());
    }
  };

  void _generateAesConstants() noexcept override {
    AESUtils::createSBox(AESUtils::SBox);
    AESUtils::createRCon(AESUtils::RCon);
    AESUtils::createMixCols(AESUtils::MixCols);
  }

  void _execMainRounds() override {
    this->_subBytes();
    this->_shiftRows();
    this->_mixColumns();
    this->_addRoundKey(0);
  }

  void _execFinalRounds() override {
    this->_subBytes();
    this->_shiftRows();
    this->_addRoundKey(0);
  }
};
template <uint16_t BlockSz> class AES_Decryption<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> : public AesEngine<BlockSz> {
public:
  AES_Decryption() noexcept = delete;
  AES_Decryption(const AES_Decryption &) noexcept = delete;
  AES_Decryption(AES_Decryption &&) noexcept = delete;

  AES_Decryption(const std::string &input, std::vector<byte> &out, const std::string &key) {
    this->_generateAesConstants();
    this->_validateParameters(input, key);
    this->_bindParameters(input, key);
    this->_stateInitialization();
    this->_keySchedule();
    this->_applyRijndaelTrasformation(out);
    this->_pkcs7Dettach(out);
  }
  ~AES_Decryption() noexcept override = default;

private:
  void _applyRijndaelTrasformation(std::vector<byte> &out) {
    for (uint8_t i = 0; i < this->parameter.data.size(); i += 16) {
      const std::string dblock(this->parameter.data.begin() + i, this->parameter.data.begin() + i + 16);
      this->_initStateMatrix(dblock);
      this->_addRoundKey(0);
      this->_initMainRounds();
      this->_execFinalRounds();
      std::vector<byte> tmp(16);
      this->_setOutput(tmp);
      out.insert(out.end(), tmp.begin(), tmp.end());
    }
  }
  void _generateAesConstants() noexcept override {
    AESUtils::createInvSBox(AESUtils::SBox, AESUtils::InvSBox);
    AESUtils::createRCon(AESUtils::RCon);
    AESUtils::createInvMixCols(AESUtils::InvMixCols);
  }

  void _execMainRounds() override {
    this->_invShiftRows();
    this->_invSubBytes();
    this->_addRoundKey(0);
    this->_invMixColumns();
  }

  void _execFinalRounds() override {
    this->_invShiftRows();
    this->_invSubBytes();
    this->_addRoundKey(0);
  }
};

} // namespace AESCrypto

#endif

namespace Test {

  class CSPRNG;

// implementing slightly more secure version of a PRNG for unix like OSs, because i dont know how to do that for windows ...
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

#else
// windows will use a less efficient version of CSPRNG , why? because im not a windows user...

class CSPRNG {
  public:
  explicit CSPRNG() noexcept {};
  ~CSPRNG() noexcept = default;
  static const std::string genSecKeyBlock(const uint16_t ks) {
    return AESUtils::genSecKeyBlock(ks);
  };
};

#endif

static const std::string cPlaintext("this is a secret message to deliver!");
static std::string plaintext(cPlaintext.begin(), cPlaintext.begin() + 1);
static std::string keyAES128(CSPRNG::genSecKeyBlock(128)); // not the best security out there...
static std::string keyAES192(CSPRNG::genSecKeyBlock(192)); // to be honest i had some issues with making the 192 variant work for some reason...
static std::string keyAES256(CSPRNG::genSecKeyBlock(256)); // same shit... but im simulating a key generator, you would use a CSPRNG for this purpose

static size_t tscore = 3; // for 3 test cases(128, 192, 256) starting from index 0
static size_t S_THRESHOLD = 0;

static constexpr size_t exec_delay = 100; // set the delay between each execution(ms)

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
  } else if (ks == AES192KS) {
    encryptedData = aes192Encryptor.call(plaintext, keyAES192);
    decryptedData = aes192Decryptor.call(std::string(encryptedData.begin(), encryptedData.end()), keyAES192);
    printResult("AES192 Encrypted(Hex): ", encryptedData);
    printResult("AES192 Decrypted(Hex): ", decryptedData);
    tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
  } else {
    encryptedData = aes256Encryptor.call(plaintext, keyAES256);
    decryptedData = aes256Decryptor.call(std::string(encryptedData.begin(), encryptedData.end()), keyAES256);
    printResult("AES256 Encrypted(Hex): ", encryptedData);
    printResult("AES256 Decrypted(Hex): ", decryptedData);
    tscore += std::string(decryptedData.begin(), decryptedData.end()) == plaintext ? 1 : 0;
  }
};

void run() {

  printPlaintext();
  // test case for all aes Key sizes, run a loop of size plaintext.length() for each key size,
  // starting from index 1 up to pt.size, to test how the implementation behaves on different
  // data lengths, each iteration will generate a new key using my custom created CSPRNG
  // class(not the best thing you will see btw... but it works so far), and through
  // each iteration the plaintext(data) will be the previous one plus 1 more byte from
  // the original data.
  const uint16_t threshold = cPlaintext.length();
  uint16_t c = 0;
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
    keyAES128 = CSPRNG::genSecKeyBlock(128);
    runAesTest(128);
  }
  S_THRESHOLD += c; // updating threshold of score counter ...

  c = 0; // reset iteration counter for the next case
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
    keyAES192 = CSPRNG::genSecKeyBlock(192);
    runAesTest(192);
  }
  S_THRESHOLD += c;

  c = 0;
  while (++c < threshold) {
    plaintext = std::string(cPlaintext.begin(), cPlaintext.begin() + c);
    keyAES256 = CSPRNG::genSecKeyBlock(256);
    runAesTest(256);
  }
  S_THRESHOLD += c;
  std::cout << "Test Execution Finished... total tests passed = " << std::dec << (int)tscore << "/" << (int)S_THRESHOLD << "\n";
};

}; // namespace Test
};

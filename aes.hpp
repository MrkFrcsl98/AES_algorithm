#pragma once
#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
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
constexpr uint16_t AES256KS = (0b01000000 << 0b010);
constexpr uint8_t AES128_ROUNDS = 10;
constexpr uint8_t AES256_ROUNDS = 14;

using byte = uint8_t;

/** For GNU Compiler, optimization... */
#ifdef __GNUC__

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
  __attribute__((cold)) void _validateParameters(const std::string &input, const std::string &key) {
    this->iSz = input.size();
    this->kSz = key.size();
    if (this->iSz >= UINT64_MAX || this->iSz == 0 || (this->kSz != (AES256KS / 8) && this->kSz != (AES128KS / 8))) [[unlikely]] {
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
      padded.push_back(static_cast<char>(paddingSize));
    }
    return padded;
  }

  __attribute__((cold, nothrow)) inline void _pkcs7Dettach(std::vector<uint8_t> &data) noexcept {
    if (data.empty()) [[unlikely]] {
      return;
    }
    const uint8_t paddingSize = data.back();
    if (paddingSize > BlockSz / 8) [[unlikely]] {
      return;
    }
    data.erase(data.end() - paddingSize, data.end());
  }

  __attribute__((cold, nothrow)) inline const std::string _addPadding(const std::string &input) noexcept {
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

/** No GNU compiler... */
#else

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

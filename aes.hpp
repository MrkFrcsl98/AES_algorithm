#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#ifndef __MFAES_BLOCK_CIPHER_lbv01__
#define __MFAES_BLOCK_CIPHER_lbv01__ 0x01

constexpr uint16_t AES128KS = (0b0001 << 0b0111);
constexpr uint16_t AES256KS = (0b01000000 << 0b010);

using byte = uint8_t;

inline constexpr byte galloisFieldMultiplication(byte a, byte b) noexcept {
  byte p = 0;
  for (int i = 0; i < 8; ++i) {
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

inline constexpr byte galloisFieldInverse(byte x) noexcept {
  byte y = x;
  for (int i = 0; i < 4; ++i) {
    y = galloisFieldMultiplication(y, y);
    y = galloisFieldMultiplication(y, x);
  }
  return y;
}

inline constexpr byte affineTransform(byte x) noexcept {
  byte result = 0x63;
  for (int i = 0; i < 8; ++i) {
    result ^= (x >> i) & 1 ? (0xF1 >> (7 - i)) & 0xFF : 0;
  }
  return result;
}

inline constexpr byte createSBoxEntry(byte x) noexcept { return affineTransform(galloisFieldInverse(x)); }

inline constexpr void createSBox(std::array<byte, 256> &sbox) noexcept {
  for (int i = 0; i < 256; ++i) {
    sbox[i] = createSBoxEntry(static_cast<byte>(i));
  }
}

inline constexpr void createInvSBox(const std::array<byte, 256> &sbox, std::array<byte, 256> &invSbox) noexcept {
  for (int i = 0; i < 256; ++i) {
    invSbox[sbox[i]] = static_cast<byte>(i);
  }
}

inline constexpr void createRCon(std::array<byte, 256> &rcon) noexcept {
  byte c = 1;
  for (int i = 0; i < 256; ++i) {
    rcon[i] = c;
    c = galloisFieldMultiplication(c, 0x02);
  }
}

inline constexpr void createMixCols(std::array<std::array<byte, 4>, 4> &mixCols) noexcept {
  mixCols[0] = {0x02, 0x03, 0x01, 0x01};
  mixCols[1] = {0x01, 0x02, 0x03, 0x01};
  mixCols[2] = {0x01, 0x01, 0x02, 0x03};
  mixCols[3] = {0x03, 0x01, 0x01, 0x02};
}

inline constexpr void createInvMixCols(std::array<std::array<byte, 4>, 4> &invMixCols) noexcept {
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

constexpr unsigned short int Nb = (0b0001 << 0b0010);
constexpr unsigned short int AES128_BLOCK_CIPHER = (0b0001 << 0b0111);

#endif

struct AesDtConvFmt {
  std::vector<uint16_t> data;
  std::vector<uint16_t> key;
};

#ifdef __MFAES_BLOCK_CIPHER_lbv01__

namespace AESCrypto {

template <uint16_t BlockSz> struct IsValidBlockSize {
  static constexpr bool value = (BlockSz == AES128KS || BlockSz == AES256KS);
};

template <uint16_t BlockSz, typename Enable = void> class AES_Encryption;
template <uint16_t BlockSz, typename Enable = void> class AES_Decryption;
template <uint16_t BlockSz, typename Enable = void> class AesEngine;

using rkBlockT = std::vector<std::vector<byte>>;
using stateMtxT = rkBlockT;

template <uint16_t BlockSz> class AesEngine<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> {
protected:
  static constexpr byte Nk = BlockSz / 32;
  static constexpr byte Nr = BlockSz == AES128KS ? 10 : (BlockSz == AES256KS ? 14 : 0);
  size_t iSz;
  size_t kSz;
  AesDtConvFmt parameter;
  rkBlockT round_keys;
  stateMtxT state_matrix;

public:
  AesEngine() noexcept = default;
  AesEngine(const AesEngine &) noexcept = delete;
  AesEngine(AesEngine &&) noexcept = delete;
  AesEngine(const std::string &input, const std::string &key) {
    _validateParameter(input, key);
    _dataInitialization(input, key);
    _initializeRkeysAndStateMatrix();
    _keySchedule();
  }
  virtual ~AesEngine() noexcept { _internMemRelease(); }

protected:
  void _validateParameter(const std::string &input, const std::string &key) {
    iSz = input.size();
    kSz = key.size();
    if (iSz == 0 || kSz == 0 || kSz > (AES256KS / 8)) {
      throw std::invalid_argument("invalid input or key!");
    }
  }

  inline void _dataInitialization(const std::string &input, const std::string &key) {
    parameter.data.assign(input.begin(), input.end());
    parameter.key.assign(key.begin(), key.end());
  }

  inline void _initializeRkeysAndStateMatrix() {
    state_matrix.resize(Nr + 1, std::vector<byte>(Nb));
    round_keys.resize((Nr + 1) * Nb, std::vector<byte>(Nb));
  }

  inline void _internMemRelease() noexcept {
    state_matrix.clear();
    round_keys.clear();
  }

  void _keySchedule() {
    for (byte i = 0; i < Nk; ++i) {
      for (byte j = 0; j < Nb; ++j) {
        round_keys[i][j] = parameter.key[i * Nb + j];
      }
    }
    for (uint16_t i = Nk; i < ((Nr + 1) * Nb); ++i) {
      std::vector<byte> TRK = round_keys[i - 1];
      if (i % Nk == 0) {
        _roundKeyRotation(TRK, 1);
        std::transform(TRK.begin(), TRK.end(), TRK.begin(), [](byte b) { return SBox[b]; });
        TRK[0] ^= RCon[i / Nk];
      } else if (Nk > 6 && (i % Nk == 4)) {
        std::transform(TRK.begin(), TRK.end(), TRK.begin(), [](byte b) { return SBox[b]; });
      }
      for (byte j = 0; j < TRK.size(); ++j) {
        round_keys[i][j] = round_keys[i - Nk][j] ^ TRK[j];
      }
    }
  }

  inline void _roundKeyRotation(std::vector<byte> &data, size_t positions) {
    if (data.empty())
      return;
    positions %= data.size();
    if (positions == 0)
      return;

    std::reverse(data.begin(), data.begin() + positions);
    std::reverse(data.begin() + positions, data.end());
    std::reverse(data.begin(), data.end());
  }

  inline void _addRoundKey(size_t round) noexcept {
    for (byte r = 0; r < Nb; ++r) {
      for (byte k = 0; k < Nb; ++k) {
        state_matrix[k][r] ^= round_keys[round * Nb + r][k];
      }
    }
  }

  inline void _subBytes() noexcept {
    for (auto &row : state_matrix) {
      std::transform(row.begin(), row.end(), row.begin(), [](byte b) { return SBox[b]; });
    }
  }

  inline void _invSubBytes() noexcept {
    for (auto &row : state_matrix) {
      std::transform(row.begin(), row.end(), row.begin(), [](byte b) { return InvSBox[b]; });
    }
  }

  inline void _shiftRows() noexcept {
    for (int i = 1; i < Nb; ++i) {
      _roundKeyRotation(state_matrix[i], i);
    }
  }

  inline void _invShiftRows() noexcept {
    for (int i = 1; i < Nb; ++i) {
      _roundKeyRotation(state_matrix[Nb - i], i);
    }
  }

  inline void _mixColumns() noexcept {
    for (int i = 0; i < Nb; ++i) {
      std::array<byte, 4> temp;
      temp[0] = __gfmultip2(state_matrix[0][i]) ^ __gfmultip3(state_matrix[1][i]) ^ state_matrix[2][i] ^ state_matrix[3][i];
      temp[1] = state_matrix[0][i] ^ __gfmultip2(state_matrix[1][i]) ^ __gfmultip3(state_matrix[2][i]) ^ state_matrix[3][i];
      temp[2] = state_matrix[0][i] ^ state_matrix[1][i] ^ __gfmultip2(state_matrix[2][i]) ^ __gfmultip3(state_matrix[3][i]);
      temp[3] = __gfmultip3(state_matrix[0][i]) ^ state_matrix[1][i] ^ state_matrix[2][i] ^ __gfmultip2(state_matrix[3][i]);
      for (int j = 0; j < 4; ++j) {
        state_matrix[j][i] = temp[j];
      }
    }
  }

  inline void _invMixColumns() noexcept {
    for (int i = 0; i < Nb; ++i) {
      std::array<byte, 4> temp;
      temp[0] = __gfmultip14(state_matrix[0][i]) ^ __gfmultip11(state_matrix[1][i]) ^ __gfmultip13(state_matrix[2][i]) ^ __gfmultip9(state_matrix[3][i]);
      temp[1] = __gfmultip9(state_matrix[0][i]) ^ __gfmultip14(state_matrix[1][i]) ^ __gfmultip11(state_matrix[2][i]) ^ __gfmultip13(state_matrix[3][i]);
      temp[2] = __gfmultip13(state_matrix[0][i]) ^ __gfmultip9(state_matrix[1][i]) ^ __gfmultip14(state_matrix[2][i]) ^ __gfmultip11(state_matrix[3][i]);
      temp[3] = __gfmultip11(state_matrix[0][i]) ^ __gfmultip13(state_matrix[1][i]) ^ __gfmultip9(state_matrix[2][i]) ^ __gfmultip14(state_matrix[3][i]);
      for (int j = 0; j < 4; ++j) {
        state_matrix[j][i] = temp[j];
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
  inline void _initMainRounds() {
    for (int r = 1; r < Nr; ++r) {
      _execMainRounds();
    }
  }

  inline void _setStateFromBytes(const std::string &bytes) noexcept {
    for (byte r = 0; r < Nb; ++r) {
      for (byte c = 0; c < Nb; ++c) {
        state_matrix[r][c] = bytes[r + Nb * c];
      }
    }
  }

  inline void _setOutputFromState(std::vector<byte> &out) noexcept {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < Nb; ++j) {
        out[i + 4 * j] = state_matrix[i][j];
      }
    }
  }

  inline std::string _pkcs7Attach(const std::string &input, size_t blockSize) {
    size_t paddingSize = blockSize - (input.size() % blockSize);
    std::string padded(input);
    padded.reserve(input.size() + paddingSize);
    while (padded.size() < input.size() + paddingSize) {
      padded.push_back(static_cast<char>(paddingSize));
    }
    return padded;
  }

  inline void _pkcs7Dettach(std::vector<uint8_t> &data) {
    if (data.empty()) {
      throw std::invalid_argument("Data is empty, cannot remove padding.");
    }
    size_t paddingSize = data.back();
    if (paddingSize > data.size()) {
      throw std::invalid_argument("Invalid padding size.");
    }
    data.erase(data.end() - paddingSize, data.end());
  }
};

template <uint16_t BlockSz> class AES_Encryption<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> : public AesEngine<BlockSz> {
public:
  AES_Encryption() noexcept = delete;
  AES_Encryption(const AES_Encryption &) noexcept = delete;
  AES_Encryption(AES_Encryption &&) noexcept = delete;

  AES_Encryption(const std::string &input, std::vector<byte> &out, const std::string &key) {
    this->_generateAesConstants();
    this->_validateParameter(input, key);
    std::string paddedInput = this->_pkcs7Attach(input, BlockSz / 8);

    this->iSz = paddedInput.size();
    this->_dataInitialization(paddedInput, key);
    this->_initializeRkeysAndStateMatrix();
    this->_keySchedule();

    std::vector<byte> tmpOut(16);
    for (size_t i = 0; i < this->parameter.data.size(); i += 16) {
      std::string dblock(this->parameter.data.begin() + i, this->parameter.data.begin() + i + 16);
      this->_setStateFromBytes(dblock);
      this->_addRoundKey(0);
      this->_initMainRounds();
      this->_execFinalRounds();
      this->_setOutputFromState(tmpOut);
      out.insert(out.end(), tmpOut.begin(), tmpOut.end());
    }
  };

  ~AES_Encryption() noexcept override = default;

private:
  void _generateAesConstants() noexcept override {
    createSBox(SBox);
    createRCon(RCon);
    createMixCols(MixCols);
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
    this->_validateParameter(input, key);
    this->_dataInitialization(input, key);
    this->_initializeRkeysAndStateMatrix();
    this->_keySchedule();

    for (size_t i = 0; i < this->parameter.data.size(); i += 16) {
      std::string dblock(this->parameter.data.begin() + i, this->parameter.data.begin() + i + 16);
      this->_setStateFromBytes(dblock);
      this->_addRoundKey(0);
      this->_initMainRounds();
      this->_execFinalRounds();
      std::vector<byte> tmp(16);
      this->_setOutputFromState(tmp);
      out.insert(out.end(), tmp.begin(), tmp.end());
    }

    this->_pkcs7Dettach(out);
  }
  ~AES_Decryption() noexcept override = default;

private:
  void _generateAesConstants() noexcept override {
    createInvSBox(SBox, InvSBox);
    createRCon(RCon);
    createInvMixCols(InvMixCols);
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

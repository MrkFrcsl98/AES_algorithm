#pragma once
#include <stdexcept>
#include <type_traits>
#ifndef __MFAES_BLOCK_CIPHER_lbv01__
#define __MFAES_BLOCK_CIPHER_lbv01__ 0x01

#define __AES128KS__ (0b0001 << 0b0111)
#define __AES192KS__ (0b00110000 << 0b010)
#define __AES256KS__ (0b01000000 << 0b010)

/*************************************** TYPE DEFS *************************************\
\***************************************************************************************/
typedef unsigned char __uint8T;
typedef unsigned short int __uint16T;
typedef unsigned int __uint32T;
typedef unsigned long int __uint64T;
typedef unsigned long long int __uint128T;
typedef const char *__ccptrT;
typedef bool __bitT;

__attribute__((hot, always_inline, nothrow, pure, leaf)) inline constexpr __uint8T gfMul(__uint8T a, __uint8T b) noexcept {
  __uint8T p = 0;
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
};

__attribute__((hot, always_inline, nothrow, pure, leaf)) inline constexpr __uint8T gfInv(__uint8T x) noexcept {
  __uint8T y = x;
  for (int i = 0; i < 4; ++i) {
    y = gfMul(y, y);
    y = gfMul(y, x);
  }
  return y;
};

__attribute__((hot, always_inline, nothrow, pure, leaf)) inline constexpr __uint8T affineTransform(__uint8T x) noexcept {
  __uint8T result = 0x63;
  for (int i = 0; i < 8; ++i) {
    result ^= (x >> i) & 1 ? (0xF1 >> (7 - i)) & 0xFF : 0;
  }
  return result;
};

__attribute__((hot, always_inline, nothrow, pure, leaf)) inline constexpr __uint8T createSBoxEntry(__uint8T x) noexcept { return affineTransform(gfInv(x)); }

__attribute__((cold, always_inline, nothrow, leaf)) inline constexpr void createSBox(__uint8T sbox[256]) noexcept {
  for (int i = 0; i < 256; ++i) {
    sbox[i] = createSBoxEntry(static_cast<__uint8T>(i));
  }
};

__attribute__((cold, always_inline, nothrow, leaf)) inline constexpr void createInvSBox(const __uint8T sbox[256], __uint8T invSbox[256]) noexcept {
  for (int i = 0; i < 256; ++i) {
    invSbox[sbox[i]] = static_cast<__uint8T>(i);
  }
};

__attribute__((cold, always_inline, nothrow, leaf)) inline constexpr void createRCon(__uint8T rcon[256]) noexcept {
  __uint8T c = 1;
  for (int i = 0; i < 256; ++i) {
    rcon[i] = c;
    c = gfMul(c, 0x02);
  }
};

__attribute__((cold, always_inline, nothrow, leaf)) inline constexpr void createMixCols(__uint8T mixCols[4][4]) noexcept {
  mixCols[0][0] = 0x02;
  mixCols[0][1] = 0x03;
  mixCols[0][2] = 0x01;
  mixCols[0][3] = 0x01;
  mixCols[1][0] = 0x01;
  mixCols[1][1] = 0x02;
  mixCols[1][2] = 0x03;
  mixCols[1][3] = 0x01;
  mixCols[2][0] = 0x01;
  mixCols[2][1] = 0x01;
  mixCols[2][2] = 0x02;
  mixCols[2][3] = 0x03;
  mixCols[3][0] = 0x03;
  mixCols[3][1] = 0x01;
  mixCols[3][2] = 0x01;
  mixCols[3][3] = 0x02;
}

__attribute__((cold, always_inline, nothrow, leaf)) inline constexpr void createInvMixCols(__uint8T invMixCols[4][4]) noexcept {
  invMixCols[0][0] = 0x0E;
  invMixCols[0][1] = 0x0B;
  invMixCols[0][2] = 0x0D;
  invMixCols[0][3] = 0x09;
  invMixCols[1][0] = 0x09;
  invMixCols[1][1] = 0x0E;
  invMixCols[1][2] = 0x0B;
  invMixCols[1][3] = 0x0D;
  invMixCols[2][0] = 0x0D;
  invMixCols[2][1] = 0x09;
  invMixCols[2][2] = 0x0E;
  invMixCols[2][3] = 0x0B;
  invMixCols[3][0] = 0x0B;
  invMixCols[3][1] = 0x0D;
  invMixCols[3][2] = 0x09;
  invMixCols[3][3] = 0x0E;
};

static __uint8T SBox[256];
static __uint8T InvSBox[256];
static __uint8T RCon[256];
static __uint8T MixCols[4][4];
static __uint8T InvMixCols[4][4];

static constexpr unsigned short int Nb = (0b0001 << 0b0010);

static constexpr unsigned short int AES128_BLOCK_CIPHER = (0b0001 << 0b0111);

#endif

/*************************************** STRUCTURES ************************************\
\***************************************************************************************/

template <typename T> struct Sequence {
  __uint64T size{0};
  T *data{nullptr};

  inline Sequence() noexcept {};

  inline Sequence(__uint64T s) noexcept { this->size = s; };

  inline Sequence(const Sequence<T> &o) noexcept { *this = o; };

  inline Sequence(Sequence<T> &&o) noexcept { *this = std::move(o); };

  const Sequence<T> &operator=(const Sequence<T> &o) noexcept {
    if (o.data == nullptr || o.size == 0) [[unlikely]]
      return *this;
    if (this->data == nullptr) [[likely]] {
      this->data = (T *)malloc(o.size * sizeof(T));
    }
    while (this->size < o.size) {
      data[this->size] = o.data[this->size];
      ++this->size;
    }
    return *this;
  };

  const Sequence<T> &operator=(Sequence<T> &&o) noexcept {
    if (o.data == nullptr || o.size == 0) [[unlikely]]
      return *this;
    if (this->data == nullptr) [[likely]] {
      this->data = (T *)malloc(o.size * sizeof(T));
    }

    while (this->size < o.size) {
      this->data[this->size] = o[this->size];
      o.data[this->size] = '\0';
      ++this->size;
    }
    free(o.data);
    o.data = nullptr;
    o.size = 0;
    return *this;
  };

  __attribute__((warn_unused_result, always_inline, pure)) const T operator[](const __uint64T i) const noexcept {
    if (i < size)
      return data[i];
    else
      return T{};
  };

  __attribute__((warn_unused_result, always_inline, pure)) T &operator[](const __uint64T i) noexcept { return data[i < size ? i : i % size]; };

  __attribute__((warn_unused_result, always_inline, pure)) const bool operator==(const Sequence<T> &o) const noexcept {
    if (this->size != o.size)
      return false;
    if (o.size > 0) [[likely]] {
      __uint64T c{0};
      do {
        if (this->data[c] != o.data[c])
          return false;
      } while (c++ < o.size && c < this->size);
    }
    return true;
  };

  __attribute__((warn_unused_result, always_inline, pure)) const bool operator>(const Sequence<T> &o) const noexcept { return this->size > o.size; };
  __attribute__((warn_unused_result, always_inline, pure)) const bool operator>=(const Sequence<T> &o) const noexcept { return this->size > o.size; };
  __attribute__((warn_unused_result, always_inline, pure)) const bool operator<(const Sequence<T> &o) const noexcept { return this->size > o.size; };
  __attribute__((warn_unused_result, always_inline, pure)) const bool operator<=(const Sequence<T> &o) const noexcept { return this->size > o.size; };

  __attribute__((always_inline)) inline void reverse_sequence() noexcept {
    T *tmp_seq = (T *)malloc(this->size * sizeof(T));
    __uint64T s = 0;
    while (s < size) {
      tmp_seq[s] = data[s];
      ++s;
    }
    __uint64T tc{0};
    do {
      data[tc] = tmp_seq[(size - 1) - tc];
    } while (++tc < size);
    free(tmp_seq);
  };

  __attribute__((always_inline)) inline void realloc_byte(const __uint64T i, const T n) noexcept {
    if (i >= size)
      return;
    data[i] = n;
  };

  inline ~Sequence() noexcept {
    if (this->data != nullptr) {
      free(this->data);
    }
    size = 0;
  }
};

typedef struct {
  struct Sequence<__uint16T> __inp_raw{};
  struct Sequence<__uint16T> __key_raw{};
} __AesDtConvFmt;

#ifdef __MFAES_BLOCK_CIPHER_lbv01__

/********************************** AES NAMESPACE **************************************\
\***************************************************************************************/

namespace AESCrypto {

__attribute__((cold, pure, warn_unused_result, nonnull)) inline const __uint64T getByteSize(const char* input) noexcept {
    if (input == nullptr || *input == '\0') [[unlikely]]
      return 0;
    __uint64T size{0};
    __uint8T c = (*input) % 0xFF;
    do {
      ++size;
    } while ((c = (*(++input) % 0xFF)) != '\0' && size < __UINT64_MAX__ - 0x1);
    return size;
  };

template <__uint16T BlockSz> struct IsValidBlockSize {
  static const bool value = (BlockSz == __AES128KS__ || BlockSz == __AES192KS__ || BlockSz == __AES256KS__);
};

template <__uint16T BlockSz, typename Enable = void> class AES_Encryption;
template <__uint16T BlockSz, typename Enable = void> class AES_Decryption;
template <__uint16T BlockSz, typename Enable = void> class AesEngine;

typedef struct Sequence<struct Sequence<__uint8T>> __rkBlockT;
typedef __rkBlockT __stateMtxT;

template <__uint16T BlockSz> class AesEngine<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> {

protected:
  const __uint8T _Nk = BlockSz / 32;                                                       // number of 32-bit words in the key
  const __uint8T _Nr = BlockSz == __AES128KS__ ? 10 : (BlockSz == __AES192KS__ ? 12 : 14); // number of rounds
  __uint64T _iSz;                                                                          // input size in bytes
  __uint64T _kSz;                                                                          // key size in bytes
  __AesDtConvFmt _dfmt;                                                                    // data format structure, raw data and binary data from key and input
  __rkBlockT _rkeys;                                                                       // round keys, one key for each round of encryption/decryption
  __stateMtxT _stateMtx;                                                                   // state matrix, current 128-bit block of data being encrypted

public:
  inline explicit AesEngine() noexcept = default;
  inline AesEngine(const AesEngine &_c) noexcept = delete;
  inline AesEngine(const AesEngine &&_c) noexcept = delete;
  inline AesEngine(__ccptrT input, __ccptrT key) {};
  inline ~AesEngine() noexcept {
    this->_internMemRelease(); // free roundKeys
  };

protected:

  template <typename T> __attribute__((nonnull, warn_unused_result, pure)) inline const Sequence<T> _genBlockSequence(__ccptrT seq, const __uint64T n) noexcept {
    struct Sequence<T> sequence;                // new sequence structure
    sequence.data = (T *)malloc(n * sizeof(T)); // allocate new memory for the sequence of bytes
    sequence.size = 0;                          // initialize size attribute to 0
    __uint16T c = (*seq);
    do {
      sequence.data[sequence.size++] = (T)c; // store current index value into new sequence structure
    } while ((c = *(++seq)) != '\0' && sequence.size < n); // until encounter terminator byte or size >= n
    return sequence; // return new sequence structure
  };

  __attribute__((hot, stack_protect, nonnull)) inline void _roundKeyRotation(__uint8T *data, __uint64T size, __uint64T positions) {
    if (size == 0)
      return;          // No rotation needed for empty array
    positions %= size; // Handle cases where positions >= size
    if (positions == 0)
      return;
    // In-place rotation using the reverse method
    auto reverse = [](auto *arr, auto start, auto end) {
      while (start < end)
        std::swap(arr[start++], arr[end--]);
    };
    reverse(data, 0, positions - 1);
    reverse(data, positions, size - 1);
    reverse(data, 0, size - 1);
  };

  __attribute__((cold)) inline void _argValidate(__ccptrT input, __ccptrT key) {
    if ((this->_iSz = getByteSize(input)) >= __UINT64_MAX__ || this->_iSz == 0 || (this->_kSz = getByteSize(key)) > (__AES256KS__ / 8) ||
        this->_kSz == 0) [[unlikely]] {
      throw std::invalid_argument("invalid input or key!");
    }
  };

  __attribute__((cold, nonnull)) inline void _dataInitialization(__ccptrT input, __ccptrT key) {
    this->_dfmt.__inp_raw = this->_genBlockSequence<__uint16T>(input, this->_iSz);
    this->_dfmt.__key_raw = this->_genBlockSequence<__uint16T>(key, this->_kSz);
  };

  inline void _allocateAndInitializeSequence(Sequence<__uint8T> &sequence, __uint64T size) {
    sequence.size = size;
    sequence.data = static_cast<__uint8T *>(malloc(size * sizeof(__uint8T)));
    for (__uint64T j = 0; j < size; ++j) {
      sequence.data[j] = 0;
    }
  };

  __attribute__((cold, stack_protect)) inline void _initRkeysAndStateBlocks() {
    this->_stateMtx.size = (this->_Nr + 1);
    this->_stateMtx.data = static_cast<Sequence<__uint8T> *>(malloc(this->_stateMtx.size * sizeof(Sequence<__uint8T>)));
    for (int f = 0; f < this->_stateMtx.size; ++f) {
      _allocateAndInitializeSequence(this->_stateMtx[f], Nb * sizeof(__uint8T));
    }

    this->_rkeys.size = (this->_Nr + 1) * Nb;
    this->_rkeys.data = static_cast<Sequence<__uint8T> *>(malloc(this->_rkeys.size * sizeof(Sequence<__uint8T>)));
    for (int f = 0; f < this->_rkeys.size; ++f) {
      _allocateAndInitializeSequence(this->_rkeys[f], Nb * sizeof(__uint8T));
    }
  }

  __attribute__((cold, stack_protect, nothrow)) inline void _internMemRelease() noexcept {
    for (int f = 0; f < this->_stateMtx.size;) {
      free(this->_stateMtx[f++].data);
    }
    for (int f = 0; f < this->_rkeys.size;) {
      free(this->_rkeys[f++].data);
    }
  };

  __attribute__((cold)) void _keySchedule() {

    for (__uint8T i = 0; i < this->_Nk; ++i) {
      for (__uint8T j = 0; j < Nb; ++j) {
        this->_rkeys[i][j] = this->_dfmt.__key_raw[i * Nb + j];
      }
    }

    for (__uint16T i = this->_Nk; i < ((this->_Nr + 1) * Nb); ++i) {
      Sequence<__uint8T> TRK(this->_rkeys[i - 1]);
      if (TRK.size == 0) [[unlikely]]
        throw std::runtime_error("key scheduling initialization failure due to bad round key values!");
      if (i % this->_Nk == 0) {
        this->_roundKeyRotation(TRK.data, TRK.size, 1);
        for (__uint16T b = 0; b < TRK.size; ++b) {
          TRK[b] = SBox[TRK[b]];
        }
        TRK[0] ^= RCon[i / this->_Nk];
      } else if (this->_Nk > 6 && (i % this->_Nk == 4)) {
        for (__uint16T b = 0; b < TRK.size; ++b) {
          TRK[b] = SBox[TRK[b]];
        }
      }
      for (__uint16T j = 0; j < TRK.size; ++j) {
        this->_rkeys[i][j] = this->_rkeys[i - this->_Nk][j] ^ TRK[j];
      }
    }
  };

  __attribute__((hot, always_inline, nothrow)) inline void _addRoundKey() noexcept {
    for (__uint8T r{0}; r < Nb; ++r) {
      for (__uint8T k{0}; k < Nb; ++k) {
        this->_stateMtx[k][r] ^= this->_rkeys[r][k];
      }
    }
  };

  __attribute__((hot, always_inline, nothrow)) inline void _subBytes() noexcept {
    for (__uint8T r{0}; r < this->_stateMtx.size; ++r) {
      for (__uint8T i{0}; i < this->_stateMtx[r].size; ++i) {
        this->_stateMtx[r][i] = SBox[this->_stateMtx[r][i]];
      }
    }
  };

  __attribute__((hot, always_inline, nothrow)) inline void _invSubBytes() noexcept {
    for (__uint8T r{0}; r < this->_stateMtx.size; ++r) {
      for (__uint8T i{0}; i < this->_stateMtx[r].size; ++i) {
        this->_stateMtx[r][i] = InvSBox[this->_stateMtx[r][i]];
      }
    }
  };

  __attribute__((hot, always_inline, nothrow)) inline void _shiftRows() noexcept {
    for (int i = 1; i < Nb; ++i) {
      this->_roundKeyRotation(this->_stateMtx[i].data, this->_stateMtx[i].size, i);
    }
  };

  __attribute__((hot, always_inline, nothrow)) inline void _invShiftRows() noexcept {
    for (int i = 1; i < Nb; ++i) {
      this->_roundKeyRotation(this->_stateMtx[Nb - i].data, this->_stateMtx[Nb - i].size, i);
    }
  };

  __attribute__((hot, nothrow, always_inline)) inline void _mixColumns() noexcept {
    for (int i = 0; i < Nb; ++i) {
      __uint8T temp[4];
      temp[0] = mul2(this->_stateMtx[0][i]) ^ mul3(this->_stateMtx[1][i]) ^ this->_stateMtx[2][i] ^ this->_stateMtx[3][i];
      temp[1] = this->_stateMtx[0][i] ^ mul2(this->_stateMtx[1][i]) ^ mul3(this->_stateMtx[2][i]) ^ this->_stateMtx[3][i];
      temp[2] = this->_stateMtx[0][i] ^ this->_stateMtx[1][i] ^ mul2(this->_stateMtx[2][i]) ^ mul3(this->_stateMtx[3][i]);
      temp[3] = mul3(this->_stateMtx[0][i]) ^ this->_stateMtx[1][i] ^ this->_stateMtx[2][i] ^ mul2(this->_stateMtx[3][i]);
      for (int j = 0; j < 4; ++j) {
        this->_stateMtx[j][i] = temp[j];
      }
    }
  }

  __attribute__((hot, always_inline, nothrow)) inline void _invMixColumns() noexcept {
    for (int i = 0; i < Nb; ++i) {
      __uint8T temp[4];
      temp[0] = mul14(this->_stateMtx[0][i]) ^ mul11(this->_stateMtx[1][i]) ^ mul13(this->_stateMtx[2][i]) ^ mul9(this->_stateMtx[3][i]);
      temp[1] = mul9(this->_stateMtx[0][i]) ^ mul14(this->_stateMtx[1][i]) ^ mul11(this->_stateMtx[2][i]) ^ mul13(this->_stateMtx[3][i]);
      temp[2] = mul13(this->_stateMtx[0][i]) ^ mul9(this->_stateMtx[1][i]) ^ mul14(this->_stateMtx[2][i]) ^ mul11(this->_stateMtx[3][i]);
      temp[3] = mul11(this->_stateMtx[0][i]) ^ mul13(this->_stateMtx[1][i]) ^ mul9(this->_stateMtx[2][i]) ^ mul14(this->_stateMtx[3][i]);
      for (int j = 0; j < 4; ++j) {
        this->_stateMtx[j][i] = temp[j];
      }
    }
  };

  __attribute__((hot, always_inline, nothrow)) constexpr __uint8T mul2(const __uint8T x) const noexcept { return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00); }
  __attribute__((hot, always_inline, nothrow)) constexpr __uint8T mul3(const __uint8T x) const noexcept { return mul2(x) ^ x; }
  __attribute__((hot, always_inline, nothrow)) constexpr __uint8T mul9(const __uint8T x) const noexcept { return mul2(mul2(mul2(x))) ^ x; }
  __attribute__((hot, always_inline, nothrow)) constexpr __uint8T mul11(const __uint8T x) const noexcept { return mul2(mul2(mul2(x))) ^ mul2(x) ^ x; }
  __attribute__((hot, always_inline, nothrow)) constexpr __uint8T mul13(const __uint8T x) const noexcept { return mul2(mul2(mul2(x))) ^ mul2(mul2(x)) ^ x; }
  __attribute__((hot, always_inline, nothrow)) constexpr __uint8T mul14(const __uint8T x) const noexcept { return mul2(mul2(mul2(x))) ^ mul2(mul2(x)) ^ mul2(x); }

  __attribute__((hot)) virtual void _execMainRounds() {};
  __attribute__((hot)) virtual void _execFinalRounds() {};
  __attribute__((cold, nothrow)) virtual void _generateAesConstants() noexcept {};

  __attribute__((cold)) inline void _initMainRounds() {
    for (int r = 1; r < this->_Nr; ++r) {
      this->_execMainRounds();
    }
  };
  __attribute__((cold, nothrow)) inline void _setStateFromBytes(__ccptrT bytes) noexcept {
    for (__uint8T r = 0; r < Nb; ++r) {
      for (__uint8T c = 0; c < Nb; ++c) {
        this->_stateMtx[r][c] = bytes[r + Nb * c];
      }
    }
  };
  __attribute__((cold, nothrow)) inline void _setOutputFromState(__uint8T *out) noexcept {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < Nb; ++j) {
        out[i + 4 * j] = this->_stateMtx[i][j];
      }
    }
  };
};

template <__uint16T BlockSz> class AES_Encryption<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> : public AesEngine<BlockSz> {
public:
  inline explicit AES_Encryption() noexcept = delete;
  inline AES_Encryption(const AES_Encryption &_c) noexcept = delete;
  inline AES_Encryption(const AES_Encryption &&_c) noexcept = delete;

  inline AES_Encryption(__ccptrT input, __ccptrT key) {
    this->_generateAesConstants();
    this->_argValidate(input, key);
    this->_dataInitialization(input, key);
    this->_initRkeysAndStateBlocks();
    this->_keySchedule();
  };

  Sequence<__uint8T> invoke() {
    Sequence<__uint8T> out;
    const __uint8T psz = (BlockSz / 0x8) - (this->_iSz % (BlockSz / 0x8));
    out.size = this->_iSz + psz + 0x1;
    out.data = (__uint8T *)malloc(sizeof(__uint8T) * out.size);
    __uint64T _ctr{0};
    while (_ctr < out.size) {
      if (_ctr < this->_iSz) {
        out[_ctr] = this->_dfmt.__inp_raw[_ctr];
      } else {
        out[_ctr] = static_cast<__uint8T>(psz);
      }
      ++_ctr;
    }

    if ((out.size - 1) % 16 == 0) [[likely]] {
      for (int i = 0; i < out.size - 0x1; i += 0x10) {
        unsigned char dblock[0x10], outblock[0x10];
        for (int c = 0; c < 0x10; c++) {
          dblock[c] = out[c + i];
        }
        
        this->_setStateFromBytes(reinterpret_cast<__ccptrT>(dblock));
        this->_addRoundKey();
        this->_initMainRounds();
        this->_execFinalRounds();
        this->_setOutputFromState(outblock);
        for (int x = 0; x < 0x10; x++) {
          out[x + i] = outblock[x];
        }
      }
      out[out.size - 1] = '\0';
    }
    return out;
  };

  inline ~AES_Encryption() noexcept = default;

private:
  __attribute__((cold, nothrow)) virtual void _generateAesConstants() noexcept {
    createSBox(SBox);
    createRCon(RCon);
    createMixCols(MixCols);
  };
  __attribute__((hot)) virtual void _execMainRounds() {
    this->_subBytes();
    this->_shiftRows();
    this->_mixColumns();
    this->_addRoundKey();
  };

  __attribute__((hot)) virtual void _execFinalRounds() {
    this->_subBytes();
    this->_shiftRows();
    this->_addRoundKey();
  };
};

template <__uint16T BlockSz> class AES_Decryption<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> : public AesEngine<BlockSz> {
public:
  inline explicit AES_Decryption() noexcept = delete;
  inline AES_Decryption(const AES_Decryption &_c) noexcept = delete;
  inline AES_Decryption(const AES_Decryption &&_c) noexcept = delete;

  inline AES_Decryption(__ccptrT input, __ccptrT key) {
    this->_generateAesConstants();
    this->_argValidate(input, key);
    this->_dataInitialization(input, key);
    this->_initRkeysAndStateBlocks();
    this->_keySchedule();
  };

  Sequence<__uint8T> invoke() {
    Sequence<__uint8T> out;
    out.size = this->_iSz;
    out.data = (__uint8T *)malloc(sizeof(__uint8T) * out.size);

    for (int i = 0; i < this->_dfmt.__inp_raw.size; i += 0x10) {
      unsigned char dblock[0x10], outblock[0x10];
      for(int c = 0; c < 0x10; c++) {
        dblock[c] = this->_dfmt.__inp_raw[c+i];
      }
      
      this->_setStateFromBytes(reinterpret_cast<__ccptrT>(dblock));
      this->_addRoundKey();
      this->_initMainRounds();
      this->_execFinalRounds();
      this->_setOutputFromState(outblock);
      for(int x = 0; x < 0x10; x++) {
        out[i+x] = outblock[x];
      } 
    }
    Sequence<__uint8T> _r;
    _r.size = out.size+0x1;
    const char PV = out[out.size-1];
    char crv = PV;
    __uint8T _PC = out.size - 0x1;
    while((crv = out[_PC--]) == PV && --_r.size > (BlockSz / 0x08)) {
    }
    _r.data = (__uint8T*)malloc(sizeof(__uint8T) * _r.size);
    _PC = 0;
    while(_PC < _r.size) {
      _r[_PC] = out[_PC];
      ++_PC;
    }
    _r[_r.size-0x1] = '\0';
    return _r;
  };

  inline ~AES_Decryption() noexcept = default;

private:
  __attribute__((cold, nothrow)) virtual void _generateAesConstants() noexcept {
    createInvSBox(SBox, InvSBox);
    createRCon(RCon);
    createInvMixCols(InvMixCols);
  };
  __attribute__((hot)) virtual void _execMainRounds() {
    this->_invShiftRows();
    this->_invSubBytes();
    this->_addRoundKey();
    this->_invMixColumns();
  };

  __attribute__((hot)) virtual void _execFinalRounds() {
    this->_invShiftRows();
    this->_invSubBytes();
    this->_addRoundKey();
  };
};
}; // namespace AESCrypto

#endif

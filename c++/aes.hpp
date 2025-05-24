#ifndef AES_CIPHER_CXX_H
#define AES_CIPHER_CXX_H 1

#define AES_ENABLE_PARALLEL_MODE 1 // for parallel execution, if not defined, will use serial mode!

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef AES_ENABLE_PARALLEL_MODE
#include <execution>
#include <future>
#endif

namespace AES
{

using byte = uint8_t;
constexpr uint16_t AES128KS = 0x80 / 0x8;  // 128
constexpr uint16_t AES192KS = 0xC0 / 0x8;  // 192
constexpr uint16_t AES256KS = 0x100 / 0x8; // 256
constexpr size_t BLOCK_SIZE = 16;

enum class Mode
{
    ECB,
    CBC,
    CFB,
    OFB,
    CTR
};


class SecureByteBlock {
    std::vector<byte> data;
public:
    SecureByteBlock(std::vector<byte>&& d) : data(std::move(d)) {}
    SecureByteBlock(const std::vector<byte>& d) : data(d) {}

    std::string toString() const {
        return std::string(data.begin(), data.end());
    }
    std::vector<byte> toVector() const {
        return data;
    }
    size_t size() const {
        return data.size();
    }
};

class SecureByteGenerator {
public:
    static SecureByteBlock GenKeyBlock(size_t size) {
        if (size != 16 && size != 24 && size != 32)
            throw std::invalid_argument("Invalid AES key size (must be 16, 24, or 32 bytes)");
        return SecureByteBlock(randomBytes(size));
    }

    static SecureByteBlock GenIvBlock(size_t size = 16) {
        return SecureByteBlock(randomBytes(size));
    }

private:
    static std::vector<byte> randomBytes(size_t size) {
        std::vector<byte> buf(size);
        std::random_device rd;
        std::uniform_int_distribution<unsigned short> dis(0, 255);
        for (auto& b : buf) b = static_cast<byte>(dis(rd));
        return buf;
    }
};



namespace Utils
{

inline std::string PKCS7Pad(const std::string &input, size_t blockSize = BLOCK_SIZE)
{
    uint8_t padLen = blockSize - (input.size() % blockSize);
    std::string out(input);
    out.append(padLen, static_cast<char>(padLen));
    return out;
}
inline void PKCS7Unpad(std::vector<byte> &data)
{
    if (data.empty())
        return;
    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > BLOCK_SIZE || padLen > data.size())
        return;
    for (size_t i = 0; i < padLen; ++i)
        if (data[data.size() - 1 - i] != padLen)
            return;
    data.resize(data.size() - padLen);
}
inline bool IsValidKeySize(size_t keylen)
{
    return keylen == (AES128KS) || keylen == (AES192KS) || keylen == (AES256KS);
}

} // namespace Utils

namespace Detail
{

constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
    0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
    0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
    0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
    0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
    0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
    0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
constexpr uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
    0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66,
    0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
    0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91,
    0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
    0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
    0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
constexpr AES::byte Rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

inline void SubBytes(byte *state)
{
    for (int i = 0; i < 16; ++i)
        state[i] = sbox[state[i]];
}
inline void InvSubBytes(byte *state)
{
    for (int i = 0; i < 16; ++i)
        state[i] = inv_sbox[state[i]];
}
inline void ShiftRows(byte *state)
{
    byte tmp[16];
    tmp[0] = state[0];
    tmp[4] = state[4];
    tmp[8] = state[8];
    tmp[12] = state[12];
    tmp[1] = state[5];
    tmp[5] = state[9];
    tmp[9] = state[13];
    tmp[13] = state[1];
    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];
    tmp[3] = state[15];
    tmp[7] = state[3];
    tmp[11] = state[7];
    tmp[15] = state[11];
    std::copy(tmp, tmp + 16, state);
}
inline void InvShiftRows(byte *state)
{
    byte tmp[16];
    tmp[0] = state[0];
    tmp[4] = state[4];
    tmp[8] = state[8];
    tmp[12] = state[12];
    tmp[1] = state[13];
    tmp[5] = state[1];
    tmp[9] = state[5];
    tmp[13] = state[9];
    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];
    tmp[3] = state[7];
    tmp[7] = state[11];
    tmp[11] = state[15];
    tmp[15] = state[3];
    std::copy(tmp, tmp + 16, state);
}
inline byte xtime(byte x)
{
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0);
}
inline byte mul(byte x, byte y)
{
    byte r = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (y & 1)
            r ^= x;
        byte h = x & 0x80;
        x <<= 1;
        if (h)
            x ^= 0x1B;
        y >>= 1;
    }
    return r;
}
inline void MixColumns(byte *state)
{
    for (int i = 0; i < 4; ++i)
    {
        byte *col = state + 4 * i;
        byte a = col[0], b = col[1], c = col[2], d = col[3];
        col[0] = mul(a, 2) ^ mul(b, 3) ^ c ^ d;
        col[1] = a ^ mul(b, 2) ^ mul(c, 3) ^ d;
        col[2] = a ^ b ^ mul(c, 2) ^ mul(d, 3);
        col[3] = mul(a, 3) ^ b ^ c ^ mul(d, 2);
    }
}
inline void InvMixColumns(byte *state)
{
    for (int i = 0; i < 4; ++i)
    {
        byte *col = state + 4 * i;
        byte a = col[0], b = col[1], c = col[2], d = col[3];
        col[0] = mul(a, 0x0e) ^ mul(b, 0x0b) ^ mul(c, 0x0d) ^ mul(d, 0x09);
        col[1] = mul(a, 0x09) ^ mul(b, 0x0e) ^ mul(c, 0x0b) ^ mul(d, 0x0d);
        col[2] = mul(a, 0x0d) ^ mul(b, 0x09) ^ mul(c, 0x0e) ^ mul(d, 0x0b);
        col[3] = mul(a, 0x0b) ^ mul(b, 0x0d) ^ mul(c, 0x09) ^ mul(d, 0x0e);
    }
}
inline void AddRoundKey(byte *state, const byte *roundKey)
{
    for (int i = 0; i < 16; ++i)
        state[i] ^= roundKey[i];
}
inline void KeyExpansion(const byte *key, byte *roundKeys, int keysize)
{
    int Nk = keysize / 4;
    int Nr = (keysize == 16) ? 10 : (keysize == 24) ? 12 : 14;
    std::copy(key, key + keysize, roundKeys);
    int bytesGenerated = keysize;
    int rconIdx = 1;
    byte temp[4];
    while (bytesGenerated < 16 * (Nr + 1))
    {
        for (int i = 0; i < 4; ++i)
            temp[i] = roundKeys[bytesGenerated - 4 + i];
        if (bytesGenerated % keysize == 0)
        {
            byte t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[rconIdx++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        }
        else if (keysize > 24 && bytesGenerated % keysize == 16)
        {
            for (int i = 0; i < 4; ++i)
                temp[i] = sbox[temp[i]];
        }
        for (int i = 0; i < 4; ++i)
        {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - keysize] ^ temp[i];
            ++bytesGenerated;
        }
    }
}
inline void XORBlock(std::vector<byte> &a, const std::vector<byte> &b)
{
    for (size_t i = 0; i < a.size(); ++i)
        a[i] ^= b[i];
}

} // namespace Detail

class Engine
{
  public:
    size_t keysize, rounds;
    std::vector<byte> key, iv, roundKeys;
    Mode mode;

    Engine(const std::vector<byte> &key_, Mode mode_, const std::vector<byte> &iv_ = {}) : key(key_), mode(mode_), iv(iv_)
    {
        keysize = key.size();
        if (keysize == 16)
            rounds = 10;
        else if (keysize == 24)
            rounds = 12;
        else if (keysize == 32)
            rounds = 14;
        else
            throw std::invalid_argument("Invalid AES key size");
        roundKeys.resize(16 * (rounds + 1));
        Detail::KeyExpansion(key.data(), roundKeys.data(), keysize);
    }

    void EncryptBlock(const byte in[BLOCK_SIZE], byte out[BLOCK_SIZE]) const
    {
        byte state[16];
        std::copy(in, in + 16, state);
        Detail::AddRoundKey(state, roundKeys.data());
        for (size_t round = 1; round < rounds; ++round)
        {
            Detail::SubBytes(state);
            Detail::ShiftRows(state);
            Detail::MixColumns(state);
            Detail::AddRoundKey(state, &roundKeys[16 * round]);
        }
        Detail::SubBytes(state);
        Detail::ShiftRows(state);
        Detail::AddRoundKey(state, &roundKeys[16 * rounds]);
        std::copy(state, state + 16, out);
    }

    void DecryptBlock(const byte in[BLOCK_SIZE], byte out[BLOCK_SIZE]) const
    {
        byte state[16];
        std::copy(in, in + 16, state);
        Detail::AddRoundKey(state, &roundKeys[16 * rounds]);
        for (size_t round = rounds - 1; round > 0; --round)
        {
            Detail::InvShiftRows(state);
            Detail::InvSubBytes(state);
            Detail::AddRoundKey(state, &roundKeys[16 * round]);
            Detail::InvMixColumns(state);
        }
        Detail::InvShiftRows(state);
        Detail::InvSubBytes(state);
        Detail::AddRoundKey(state, roundKeys.data());
        std::copy(state, state + 16, out);
    }
};

// --------- Parallel/Serial Implementations for Each Mode ---------

// ---- ECB ----
inline void ECB_Encrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = in.size() / BLOCK_SIZE;
    out.resize(num_blocks * BLOCK_SIZE);
    std::vector<std::array<byte, BLOCK_SIZE>> blocks(num_blocks);
    for (size_t i = 0; i < num_blocks; ++i)
        std::copy_n(in.data() + i * BLOCK_SIZE, BLOCK_SIZE, blocks[i].data());

#ifdef AES_ENABLE_PARALLEL_MODE
    std::for_each(std::execution::par, blocks.begin(), blocks.end(), [&](auto &block) {
        byte encrypted[BLOCK_SIZE];
        aes.EncryptBlock(block.data(), encrypted);
        std::copy_n(encrypted, BLOCK_SIZE, block.data());
    });
#else
    for (auto &block : blocks)
    {
        byte encrypted[BLOCK_SIZE];
        aes.EncryptBlock(block.data(), encrypted);
        std::copy_n(encrypted, BLOCK_SIZE, block.data());
    }
#endif

    for (size_t i = 0; i < num_blocks; ++i)
        std::copy_n(blocks[i].data(), BLOCK_SIZE, out.data() + i * BLOCK_SIZE);
}
inline void ECB_Encrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = in.size() / BLOCK_SIZE;
    out.resize(num_blocks * BLOCK_SIZE);
    for (size_t i = 0; i < num_blocks; ++i)
    {
        aes.EncryptBlock(in.data() + i * BLOCK_SIZE, out.data() + i * BLOCK_SIZE);
    }
}
inline void ECB_Decrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = in.size() / BLOCK_SIZE;
    out.resize(num_blocks * BLOCK_SIZE);
    std::vector<std::array<byte, BLOCK_SIZE>> blocks(num_blocks);
    for (size_t i = 0; i < num_blocks; ++i)
        std::copy_n(in.data() + i * BLOCK_SIZE, BLOCK_SIZE, blocks[i].data());

#ifdef AES_ENABLE_PARALLEL_MODE
    std::for_each(std::execution::par, blocks.begin(), blocks.end(), [&](auto &block) {
        byte decrypted[BLOCK_SIZE];
        aes.DecryptBlock(block.data(), decrypted);
        std::copy_n(decrypted, BLOCK_SIZE, block.data());
    });
#else
    for (auto &block : blocks)
    {
        byte decrypted[BLOCK_SIZE];
        aes.DecryptBlock(block.data(), decrypted);
        std::copy_n(decrypted, BLOCK_SIZE, block.data());
    }
#endif

    for (size_t i = 0; i < num_blocks; ++i)
        std::copy_n(blocks[i].data(), BLOCK_SIZE, out.data() + i * BLOCK_SIZE);
}
inline void ECB_Decrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = in.size() / BLOCK_SIZE;
    out.resize(num_blocks * BLOCK_SIZE);
    for (size_t i = 0; i < num_blocks; ++i)
    {
        aes.DecryptBlock(in.data() + i * BLOCK_SIZE, out.data() + i * BLOCK_SIZE);
    }
}

// ---- CBC ----
inline void CBC_Encrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    std::vector<byte> prev(aes.iv);
    for (size_t i = 0; i < in.size(); i += BLOCK_SIZE)
    {
        std::vector<byte> block(in.begin() + i, in.begin() + i + BLOCK_SIZE);
        AES::Detail::XORBlock(block, prev);
        byte outblock[BLOCK_SIZE];
        aes.EncryptBlock(block.data(), outblock);
        out.insert(out.end(), outblock, outblock + BLOCK_SIZE);
        prev.assign(outblock, outblock + BLOCK_SIZE);
    }
}
inline void CBC_Encrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    std::vector<byte> prev(aes.iv);
    for (size_t i = 0; i < in.size(); i += BLOCK_SIZE)
    {
        std::vector<byte> block(in.begin() + i, in.begin() + i + BLOCK_SIZE);
        AES::Detail::XORBlock(block, prev);
        byte outblock[BLOCK_SIZE];
        aes.EncryptBlock(block.data(), outblock);
        out.insert(out.end(), outblock, outblock + BLOCK_SIZE);
        prev.assign(outblock, outblock + BLOCK_SIZE);
    }
}
inline void CBC_Decrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = in.size() / BLOCK_SIZE;
    out.resize(num_blocks * BLOCK_SIZE);
    std::vector<byte> prev(aes.iv);
    for (size_t i = 0; i < num_blocks; ++i)
    {
        byte block[BLOCK_SIZE], decrypted[BLOCK_SIZE];
        std::copy(in.begin() + i * BLOCK_SIZE, in.begin() + (i + 1) * BLOCK_SIZE, block);
        aes.DecryptBlock(block, decrypted);
        for (size_t j = 0; j < BLOCK_SIZE; ++j)
        {
            out[i * BLOCK_SIZE + j] = decrypted[j] ^ prev[j];
        }
        std::copy(block, block + BLOCK_SIZE, prev.begin());
    }
}
inline void CBC_Decrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    std::vector<byte> prev(aes.iv);
    for (size_t i = 0; i < in.size(); i += BLOCK_SIZE)
    {
        byte block[BLOCK_SIZE], decrypted[BLOCK_SIZE];
        std::copy(in.begin() + i, in.begin() + i + BLOCK_SIZE, block);
        aes.DecryptBlock(block, decrypted);
        std::vector<byte> decblock(decrypted, decrypted + BLOCK_SIZE);
        AES::Detail::XORBlock(decblock, prev);
        out.insert(out.end(), decblock.begin(), decblock.end());
        prev.assign(block, block + BLOCK_SIZE);
    }
}

// ---- CFB ----
inline void CFB_Encrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = (in.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    out.resize(in.size());
    std::array<byte, BLOCK_SIZE> prev;
    std::copy_n(aes.iv.data(), BLOCK_SIZE, prev.data());
    for (size_t i = 0; i < num_blocks; ++i)
    {
        byte keystream[BLOCK_SIZE];
        aes.EncryptBlock(prev.data(), keystream);
        size_t block_size = std::min(BLOCK_SIZE, in.size() - i * BLOCK_SIZE);
        std::vector<byte> block(in.begin() + i * BLOCK_SIZE, in.begin() + i * BLOCK_SIZE + block_size);
        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= keystream[j];
        std::fill(prev.begin(), prev.end(), 0);
        std::copy_n(block.data(), block_size, prev.data());
        std::copy_n(block.data(), block_size, out.data() + i * BLOCK_SIZE);
    }
}
inline void CFB_Encrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    std::vector<byte> prev(aes.iv);
    for (size_t i = 0; i < in.size(); i += BLOCK_SIZE)
    {
        byte keystream[BLOCK_SIZE];
        aes.EncryptBlock(prev.data(), keystream);
        size_t block_size = std::min(BLOCK_SIZE, in.size() - i);
        std::vector<byte> block(in.begin() + i, in.begin() + i + block_size);
        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= keystream[j];
        out.insert(out.end(), block.begin(), block.end());
        prev.assign(block.begin(), block.end());
    }
}
inline void CFB_Decrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = (in.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    out.resize(in.size());
    std::array<byte, BLOCK_SIZE> prev;
    std::copy_n(aes.iv.data(), BLOCK_SIZE, prev.data());
    for (size_t i = 0; i < num_blocks; ++i)
    {
        byte keystream[BLOCK_SIZE];
        aes.EncryptBlock(prev.data(), keystream);
        size_t block_size = std::min(BLOCK_SIZE, in.size() - i * BLOCK_SIZE);
        std::vector<byte> block(in.begin() + i * BLOCK_SIZE, in.begin() + i * BLOCK_SIZE + block_size);
        std::vector<byte> cipherblock(block);
        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= keystream[j];
        std::fill(prev.begin(), prev.end(), 0);
        std::copy_n(cipherblock.data(), block_size, prev.data());
        std::copy_n(block.data(), block_size, out.data() + i * BLOCK_SIZE);
    }
}
inline void CFB_Decrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    std::vector<byte> prev(aes.iv);
    for (size_t i = 0; i < in.size(); i += BLOCK_SIZE)
    {
        byte keystream[BLOCK_SIZE];
        aes.EncryptBlock(prev.data(), keystream);
        size_t block_size = std::min(BLOCK_SIZE, in.size() - i);
        std::vector<byte> block(in.begin() + i, in.begin() + i + block_size);
        std::vector<byte> cipherblock(block);
        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= keystream[j];
        out.insert(out.end(), block.begin(), block.end());
        prev.assign(cipherblock.begin(), cipherblock.end());
    }
}

// ---- OFB ----
inline void OFB_Encrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = (in.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    out.resize(in.size());
    std::vector<std::array<byte, BLOCK_SIZE>> keystreams(num_blocks);
    std::array<byte, BLOCK_SIZE> prev;
    std::copy_n(aes.iv.data(), BLOCK_SIZE, prev.data());
    for (size_t i = 0; i < num_blocks; ++i)
    {
        aes.EncryptBlock(prev.data(), keystreams[i].data());
        prev = keystreams[i];
    }
    std::vector<size_t> indices(num_blocks);
    for (size_t i = 0; i < num_blocks; ++i)
        indices[i] = i;
#ifdef AES_ENABLE_PARALLEL_MODE
    std::for_each(std::execution::par, indices.begin(), indices.end(), [&](size_t i) {
        size_t offset = i * BLOCK_SIZE;
        size_t chunk = std::min(BLOCK_SIZE, in.size() - offset);
        for (size_t j = 0; j < chunk; ++j)
            out[offset + j] = in[offset + j] ^ keystreams[i][j];
    });
#else
    for (size_t i : indices)
    {
        size_t offset = i * BLOCK_SIZE;
        size_t chunk = std::min(BLOCK_SIZE, in.size() - offset);
        for (size_t j = 0; j < chunk; ++j)
            out[offset + j] = in[offset + j] ^ keystreams[i][j];
    }
#endif
}
inline void OFB_Encrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    std::array<byte, BLOCK_SIZE> prev;
    std::copy_n(aes.iv.data(), BLOCK_SIZE, prev.data());
    for (size_t i = 0; i < in.size(); i += BLOCK_SIZE)
    {
        byte keystream[BLOCK_SIZE];
        aes.EncryptBlock(prev.data(), keystream);
        prev = *reinterpret_cast<std::array<byte, BLOCK_SIZE> *>(keystream);
        size_t chunk = std::min(BLOCK_SIZE, in.size() - i);
        for (size_t j = 0; j < chunk; ++j)
            out.push_back(in[i + j] ^ keystream[j]);
    }
}
inline void OFB_Decrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    OFB_Encrypt_Parallel(aes, in, out);
}
inline void OFB_Decrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    OFB_Encrypt_Serial(aes, in, out);
}

// ---- CTR ----
inline void CTR_Encrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = (in.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    out.resize(in.size());
    std::vector<std::array<byte, BLOCK_SIZE>> keystreams(num_blocks);
    std::vector<std::array<byte, BLOCK_SIZE>> counters(num_blocks);

    std::vector<byte> counter(aes.iv);
    for (size_t i = 0; i < num_blocks; ++i)
    {
        std::copy_n(counter.data(), BLOCK_SIZE, counters[i].data());
        for (int k = BLOCK_SIZE - 1; k >= 0; --k)
            if (++counter[k])
                break;
    }
#ifdef AES_ENABLE_PARALLEL_MODE
    std::for_each(std::execution::par, counters.begin(), counters.end(), [&](auto &ctr) {
        byte keystream[BLOCK_SIZE];
        aes.EncryptBlock(ctr.data(), keystream);
        std::copy_n(keystream, BLOCK_SIZE, keystreams[&ctr - counters.data()].data());
    });
#else
    for (size_t i = 0; i < num_blocks; ++i)
    {
        byte keystream[BLOCK_SIZE];
        aes.EncryptBlock(counters[i].data(), keystream);
        std::copy_n(keystream, BLOCK_SIZE, keystreams[i].data());
    }
#endif
    for (size_t i = 0; i < num_blocks; ++i)
    {
        size_t offset = i * BLOCK_SIZE;
        size_t chunk = std::min(BLOCK_SIZE, in.size() - offset);
        for (size_t j = 0; j < chunk; ++j)
            out[offset + j] = in[offset + j] ^ keystreams[i][j];
    }
}
inline void CTR_Encrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    size_t num_blocks = (in.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    out.resize(in.size());
    std::vector<byte> counter(aes.iv);
    for (size_t i = 0; i < num_blocks; ++i)
    {
        byte keystream[BLOCK_SIZE];
        aes.EncryptBlock(counter.data(), keystream);
        size_t offset = i * BLOCK_SIZE;
        size_t chunk = std::min(BLOCK_SIZE, in.size() - offset);
        for (size_t j = 0; j < chunk; ++j)
            out[offset + j] = in[offset + j] ^ keystream[j];
        for (int k = BLOCK_SIZE - 1; k >= 0; --k)
            if (++counter[k])
                break;
    }
}
inline void CTR_Decrypt_Parallel(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    CTR_Encrypt_Parallel(aes, in, out);
}
inline void CTR_Decrypt_Serial(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out)
{
    CTR_Encrypt_Serial(aes, in, out);
}
// --- Result class ---
class Result
{
    std::vector<byte> data;

  public:
    Result(std::vector<byte> dat) : data(std::move(dat))
    {
    }
    std::vector<byte> toVector() const
    {
        return data;
    }
    std::string toString() const
    {
        return std::string(data.begin(), data.end());
    }
    std::string toHex() const
    {
        std::ostringstream oss;
        for (auto b : data)
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        return oss.str();
    }
    std::string toBase64() const
    {
        static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        int val = 0, valb = -6;
        for (byte c : data)
        {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0)
            {
                out.push_back(tbl[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6)
            out.push_back(tbl[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4)
            out.push_back('=');
        return out;
    }
    std::string toAscii() const
    {
        std::string out;
        for (byte b : data)
            out += (std::isprint(b) ? static_cast<char>(b) : '.');
        return out;
    }
};

// --- Mode structs with Parallel/Serial API ---

inline std::vector<byte> IVToVector(const std::string &iv)
{
    return std::vector<byte>(iv.begin(), iv.end());
}

struct ECB
{
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::ECB, {});
        std::string padded = Utils::PKCS7Pad(plaintext);
        std::vector<byte> in(padded.begin(), padded.end()), out;
        ECB_Encrypt_Parallel(aes, in, out);
        return Result(std::move(out));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::ECB, {});
        std::string padded = Utils::PKCS7Pad(plaintext);
        std::vector<byte> in(padded.begin(), padded.end()), out;
        ECB_Encrypt_Serial(aes, in, out);
        return Result(std::move(out));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::ECB, {});
        std::vector<byte> out;
        ECB_Decrypt_Parallel(aes, ciphertext, out);
        Utils::PKCS7Unpad(out);
        return Result(std::move(out));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::ECB, {});
        std::vector<byte> out;
        ECB_Decrypt_Serial(aes, ciphertext, out);
        Utils::PKCS7Unpad(out);
        return Result(std::move(out));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key);
#else
        return SerialEncryption(plaintext, key);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key);
#else
        return SerialDecryption(ciphertext, key);
#endif
    }
};

struct CBC
{
    // String IV overloads
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
        return ParallelEncryption(plaintext, key, IVToVector(iv));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
        return SerialEncryption(plaintext, key, IVToVector(iv));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
        return ParallelDecryption(ciphertext, key, IVToVector(iv));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
        return SerialDecryption(ciphertext, key, IVToVector(iv));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key, iv);
#else
        return SerialEncryption(plaintext, key, iv);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key, iv);
#else
        return SerialDecryption(ciphertext, key, iv);
#endif
    }

    // Vector IV API
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            iv = SecureByteGenerator::GenIvBlock().toVector();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CBC, iv);
        std::string padded = Utils::PKCS7Pad(plaintext);
        std::vector<byte> in(padded.begin(), padded.end()), out;
        CBC_Encrypt_Parallel(aes, in, out);
        return Result(std::move(out));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            iv = SecureByteGenerator::GenIvBlock().toVector();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CBC, iv);
        std::string padded = Utils::PKCS7Pad(plaintext);
        std::vector<byte> in(padded.begin(), padded.end()), out;
        CBC_Encrypt_Serial(aes, in, out);
        return Result(std::move(out));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            throw std::invalid_argument("IV required for CBC mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CBC, iv);
        std::vector<byte> out;
        CBC_Decrypt_Parallel(aes, ciphertext, out);
        Utils::PKCS7Unpad(out);
        return Result(std::move(out));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            throw std::invalid_argument("IV required for CBC mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CBC, iv);
        std::vector<byte> out;
        CBC_Decrypt_Serial(aes, ciphertext, out);
        Utils::PKCS7Unpad(out);
        return Result(std::move(out));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key, iv);
#else
        return SerialEncryption(plaintext, key, iv);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key, iv);
#else
        return SerialDecryption(ciphertext, key, iv);
#endif
    }
};

struct CFB
{
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
        return ParallelEncryption(plaintext, key, IVToVector(iv));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
        return SerialEncryption(plaintext, key, IVToVector(iv));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
        return ParallelDecryption(ciphertext, key, IVToVector(iv));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
        return SerialDecryption(ciphertext, key, IVToVector(iv));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key, iv);
#else
        return SerialEncryption(plaintext, key, iv);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key, iv);
#else
        return SerialDecryption(ciphertext, key, iv);
#endif
    }
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            iv = SecureByteGenerator::GenIvBlock().toVector();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CFB, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end()), out;
        CFB_Encrypt_Parallel(aes, in, out);
        return Result(std::move(out));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            iv = SecureByteGenerator::GenIvBlock().toVector();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CFB, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end()), out;
        CFB_Encrypt_Serial(aes, in, out);
        return Result(std::move(out));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            throw std::invalid_argument("IV required for CFB mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CFB, iv);
        std::vector<byte> out;
        CFB_Decrypt_Parallel(aes, ciphertext, out);
        return Result(std::move(out));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            throw std::invalid_argument("IV required for CFB mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CFB, iv);
        std::vector<byte> out;
        CFB_Decrypt_Serial(aes, ciphertext, out);
        return Result(std::move(out));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key, iv);
#else
        return SerialEncryption(plaintext, key, iv);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key, iv);
#else
        return SerialDecryption(ciphertext, key, iv);
#endif
    }
};

struct OFB
{
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
        return ParallelEncryption(plaintext, key, IVToVector(iv));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
        return SerialEncryption(plaintext, key, IVToVector(iv));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
        return ParallelDecryption(ciphertext, key, IVToVector(iv));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
        return SerialDecryption(ciphertext, key, IVToVector(iv));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key, iv);
#else
        return SerialEncryption(plaintext, key, iv);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key, iv);
#else
        return SerialDecryption(ciphertext, key, iv);
#endif
    }
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            iv = SecureByteGenerator::GenIvBlock().toVector();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::OFB, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end()), out;
        OFB_Encrypt_Parallel(aes, in, out);
        return Result(std::move(out));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            iv = SecureByteGenerator::GenIvBlock().toVector();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::OFB, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end()), out;
        OFB_Encrypt_Serial(aes, in, out);
        return Result(std::move(out));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            throw std::invalid_argument("IV required for OFB mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::OFB, iv);
        std::vector<byte> out;
        OFB_Decrypt_Parallel(aes, ciphertext, out);
        return Result(std::move(out));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            throw std::invalid_argument("IV required for OFB mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::OFB, iv);
        std::vector<byte> out;
        OFB_Decrypt_Serial(aes, ciphertext, out);
        return Result(std::move(out));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key, iv);
#else
        return SerialEncryption(plaintext, key, iv);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key, iv);
#else
        return SerialDecryption(ciphertext, key, iv);
#endif
    }
};

struct CTR
{
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
        return ParallelEncryption(plaintext, key, IVToVector(iv));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
        return SerialEncryption(plaintext, key, IVToVector(iv));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
        return ParallelDecryption(ciphertext, key, IVToVector(iv));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
        return SerialDecryption(ciphertext, key, IVToVector(iv));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key, iv);
#else
        return SerialEncryption(plaintext, key, iv);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, const std::string &iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key, iv);
#else
        return SerialDecryption(ciphertext, key, iv);
#endif
    }
    static Result ParallelEncryption(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            iv = SecureByteGenerator::GenIvBlock().toVector();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CTR, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end()), out;
        CTR_Encrypt_Parallel(aes, in, out);
        return Result(std::move(out));
    }
    static Result SerialEncryption(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            iv = SecureByteGenerator::GenIvBlock().toVector();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CTR, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end()), out;
        CTR_Encrypt_Serial(aes, in, out);
        return Result(std::move(out));
    }
    static Result ParallelDecryption(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            throw std::invalid_argument("IV required for CTR mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CTR, iv);
        std::vector<byte> out;
        CTR_Decrypt_Parallel(aes, ciphertext, out);
        return Result(std::move(out));
    }
    static Result SerialDecryption(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
        if (!Utils::IsValidKeySize(key.size()))
            throw std::invalid_argument("Invalid key size");
        if (iv.empty())
            throw std::invalid_argument("IV required for CTR mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CTR, iv);
        std::vector<byte> out;
        CTR_Decrypt_Serial(aes, ciphertext, out);
        return Result(std::move(out));
    }
    static Result Encrypt(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {})
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelEncryption(plaintext, key, iv);
#else
        return SerialEncryption(plaintext, key, iv);
#endif
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv)
    {
#ifdef AES_ENABLE_PARALLEL_MODE
        return ParallelDecryption(ciphertext, key, iv);
#else
        return SerialDecryption(ciphertext, key, iv);
#endif
    }
};

} // namespace AES

#endif // AES_CIPHER_CXX_H

#pragma once
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <stdint.h>

constexpr uint16_t AES128KS = 0x80;
constexpr uint16_t AES192KS = 0xC0;
constexpr uint16_t AES256KS = 0x100;
constexpr uint8_t AES128_ROUNDS = 0x0A;
constexpr uint8_t AES192_ROUNDS = 0x0C;
constexpr uint8_t AES256_ROUNDS = 0x0E;
constexpr uint8_t IV_BLOCK_SIZE = 0x10;
constexpr uint8_t AES_BLOCK_SIZE = 0x10;

using byte = uint8_t;

namespace AES {

namespace Utils {

inline std::string SecureKeyBlock(uint16_t key_size) {
    if (key_size != AES128KS && key_size != AES256KS && key_size != AES192KS)
        throw std::invalid_argument("invalid key size");
    std::string seckey(key_size / 8, 0);
    std::random_device rd;
    std::uniform_int_distribution<unsigned short> dis(0, 255);
    for (auto &ch : seckey)
        ch = static_cast<char>(dis(rd));
    return seckey;
}
inline std::vector<byte> SecureIVBlock(uint16_t size = IV_BLOCK_SIZE) {
    std::vector<byte> iv(size, 0);
    std::random_device rd;
    std::uniform_int_distribution<unsigned short> dis(0, 255);
    for (auto &b : iv)
        b = static_cast<byte>(dis(rd));
    return iv;
}
inline std::string PKCS7Pad(const std::string &input, size_t blockSize = AES_BLOCK_SIZE) {
    uint8_t padLen = blockSize - (input.size() % blockSize);
    std::string out(input);
    out.append(padLen, static_cast<char>(padLen));
    return out;
}
inline void PKCS7Unpad(std::vector<byte> &data) {
    if (data.empty()) return;
    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > AES_BLOCK_SIZE) return;
    data.resize(data.size() - padLen);
}
} // namespace Utils

enum class Mode {
    ECB = 0,
    CBC,
    CFB,
    OFB,
    CTR
};

inline bool IsValidKeySize(size_t keylen) {
    return keylen == (AES128KS / 8) || keylen == (AES192KS / 8) || keylen == (AES256KS / 8);
}

// -- SBOX, INV SBOX, RCON, and helpers --
namespace Detail {
constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
constexpr uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
constexpr byte Rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

inline void SubBytes(byte* state) {
    for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}
inline void InvSubBytes(byte* state) {
    for (int i = 0; i < 16; ++i) state[i] = inv_sbox[state[i]];
}
inline void ShiftRows(byte* state) {
    byte tmp[16];
    tmp[ 0] = state[ 0]; tmp[ 4] = state[ 4]; tmp[ 8] = state[ 8]; tmp[12] = state[12];
    tmp[ 1] = state[ 5]; tmp[ 5] = state[ 9]; tmp[ 9] = state[13]; tmp[13] = state[ 1];
    tmp[ 2] = state[10]; tmp[ 6] = state[14]; tmp[10] = state[ 2]; tmp[14] = state[ 6];
    tmp[ 3] = state[15]; tmp[ 7] = state[ 3]; tmp[11] = state[ 7]; tmp[15] = state[11];
    std::copy(tmp, tmp+16, state);
}
inline void InvShiftRows(byte* state) {
    byte tmp[16];
    tmp[ 0] = state[ 0]; tmp[ 4] = state[ 4]; tmp[ 8] = state[ 8]; tmp[12] = state[12];
    tmp[ 1] = state[13]; tmp[ 5] = state[ 1]; tmp[ 9] = state[ 5]; tmp[13] = state[ 9];
    tmp[ 2] = state[10]; tmp[ 6] = state[14]; tmp[10] = state[ 2]; tmp[14] = state[ 6];
    tmp[ 3] = state[ 7]; tmp[ 7] = state[11]; tmp[11] = state[15]; tmp[15] = state[ 3];
    std::copy(tmp, tmp+16, state);
}
inline byte xtime(byte x) { return (x << 1) ^ ((x & 0x80) ? 0x1B : 0); }
inline byte mul(byte x, byte y) {
    byte r = 0;
    for (int i = 0; i < 8; ++i) {
        if (y & 1) r ^= x;
        byte h = x & 0x80;
        x <<= 1;
        if (h) x ^= 0x1B;
        y >>= 1;
    }
    return r;
}
inline void MixColumns(byte* state) {
    for (int i = 0; i < 4; ++i) {
        byte* col = state + 4*i;
        byte a = col[0], b = col[1], c = col[2], d = col[3];
        col[0] = mul(a,2) ^ mul(b,3) ^ c ^ d;
        col[1] = a ^ mul(b,2) ^ mul(c,3) ^ d;
        col[2] = a ^ b ^ mul(c,2) ^ mul(d,3);
        col[3] = mul(a,3) ^ b ^ c ^ mul(d,2);
    }
}
inline void InvMixColumns(byte* state) {
    for (int i = 0; i < 4; ++i) {
        byte* col = state + 4*i;
        byte a = col[0], b = col[1], c = col[2], d = col[3];
        col[0] = mul(a,0x0e) ^ mul(b,0x0b) ^ mul(c,0x0d) ^ mul(d,0x09);
        col[1] = mul(a,0x09) ^ mul(b,0x0e) ^ mul(c,0x0b) ^ mul(d,0x0d);
        col[2] = mul(a,0x0d) ^ mul(b,0x09) ^ mul(c,0x0e) ^ mul(d,0x0b);
        col[3] = mul(a,0x0b) ^ mul(b,0x0d) ^ mul(c,0x09) ^ mul(d,0x0e);
    }
}
inline void AddRoundKey(byte* state, const byte* roundKey) {
    for (int i = 0; i < 16; ++i) state[i] ^= roundKey[i];
}
inline void KeyExpansion(const byte* key, byte* roundKeys, int keysize) {
    int Nk = keysize / 4;
    int Nr = (keysize == 16) ? 10 : (keysize == 24) ? 12 : 14;
    std::copy(key, key + keysize, roundKeys);
    int bytesGenerated = keysize;
    int rconIdx = 1;
    byte temp[4];
    while (bytesGenerated < 16*(Nr+1)) {
        for (int i = 0; i < 4; ++i)
            temp[i] = roundKeys[bytesGenerated-4+i];
        if (bytesGenerated % keysize == 0) {
            byte t = temp[0];
            temp[0]=sbox[temp[1]]^Rcon[rconIdx++];
            temp[1]=sbox[temp[2]];
            temp[2]=sbox[temp[3]];
            temp[3]=sbox[t];
        } else if (keysize > 24 && bytesGenerated % keysize == 16) {
            for (int i = 0; i < 4; ++i) temp[i] = sbox[temp[i]];
        }
        for (int i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated-keysize] ^ temp[i];
            ++bytesGenerated;
        }
    }
}
} // namespace Detail

class Engine {
public:
    size_t keysize;
    size_t rounds;
    std::vector<byte> key;
    std::vector<byte> iv;
    Mode mode;
    std::vector<byte> roundKeys;

    Engine(const std::vector<byte> &key_, Mode mode_, const std::vector<byte> &iv_ = {})
        : key(key_), mode(mode_), iv(iv_) {
        keysize = key.size();
        if (keysize == 16) rounds = 10;
        else if (keysize == 24) rounds = 12;
        else if (keysize == 32) rounds = 14;
        else throw std::invalid_argument("Invalid AES key size");
        roundKeys.resize(16 * (rounds + 1));
        Detail::KeyExpansion(key.data(), roundKeys.data(), keysize);
    }

    void EncryptBlock(const byte in[AES_BLOCK_SIZE], byte out[AES_BLOCK_SIZE]) const {
        byte state[16];
        std::copy(in, in+16, state);
        Detail::AddRoundKey(state, roundKeys.data());
        for (size_t round = 1; round < rounds; ++round) {
            Detail::SubBytes(state);
            Detail::ShiftRows(state);
            Detail::MixColumns(state);
            Detail::AddRoundKey(state, &roundKeys[16*round]);
        }
        Detail::SubBytes(state);
        Detail::ShiftRows(state);
        Detail::AddRoundKey(state, &roundKeys[16*rounds]);
        std::copy(state, state+16, out);
    }

    void DecryptBlock(const byte in[AES_BLOCK_SIZE], byte out[AES_BLOCK_SIZE]) const {
        byte state[16];
        std::copy(in, in+16, state);
        Detail::AddRoundKey(state, &roundKeys[16*rounds]);
        for (size_t round = rounds-1; round > 0; --round) {
            Detail::InvShiftRows(state);
            Detail::InvSubBytes(state);
            Detail::AddRoundKey(state, &roundKeys[16*round]);
            Detail::InvMixColumns(state);
        }
        Detail::InvShiftRows(state);
        Detail::InvSubBytes(state);
        Detail::AddRoundKey(state, roundKeys.data());
        std::copy(state, state+16, out);
    }
};

namespace Detail {

inline void XORBlock(std::vector<byte> &a, const std::vector<byte> &b) {
    for (size_t i = 0; i < a.size(); ++i)
        a[i] ^= b[i];
}
inline void ECB_Encrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    for (size_t i = 0; i < in.size(); i += AES_BLOCK_SIZE) {
        byte block[16];
        aes.EncryptBlock(&in[i], block);
        out.insert(out.end(), block, block + 16);
    }
}
inline void ECB_Decrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    for (size_t i = 0; i < in.size(); i += AES_BLOCK_SIZE) {
        byte block[16];
        aes.DecryptBlock(&in[i], block);
        out.insert(out.end(), block, block + 16);
    }
}
inline void CBC_Encrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    std::vector<byte> prev(aes.iv);
    for (size_t i = 0; i < in.size(); i += AES_BLOCK_SIZE) {
        std::vector<byte> block(in.begin() + i, in.begin() + i + AES_BLOCK_SIZE);
        XORBlock(block, prev);
        byte outblock[16];
        aes.EncryptBlock(block.data(), outblock);
        out.insert(out.end(), outblock, outblock + 16);
        prev.assign(outblock, outblock+16);
    }
}
inline void CBC_Decrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    std::vector<byte> prev(aes.iv);
    for (size_t i = 0; i < in.size(); i += AES_BLOCK_SIZE) {
        byte block[16], decrypted[16];
        std::copy(in.begin() + i, in.begin() + i + 16, block);
        aes.DecryptBlock(block, decrypted);
        std::vector<byte> decblock(decrypted, decrypted+16);
        XORBlock(decblock, prev);
        out.insert(out.end(), decblock.begin(), decblock.end());
        prev.assign(block, block+16);
    }
}
inline void CFB_Encrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    std::vector<byte> prev(aes.iv);
    size_t len = in.size();
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte keystream[AES_BLOCK_SIZE];
        aes.EncryptBlock(prev.data(), keystream);

        size_t block_size = std::min(len - i, (size_t)AES_BLOCK_SIZE);
        std::vector<byte> block(in.begin() + i, in.begin() + i + block_size);

        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= keystream[j];

        out.insert(out.end(), block.begin(), block.end());
        prev.assign(block.begin(), block.end());
        if (block_size < AES_BLOCK_SIZE) break;
    }
}
inline void CFB_Decrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    std::vector<byte> prev(aes.iv);
    size_t len = in.size();
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte keystream[AES_BLOCK_SIZE];
        aes.EncryptBlock(prev.data(), keystream);

        size_t block_size = std::min(len - i, (size_t)AES_BLOCK_SIZE);
        std::vector<byte> block(in.begin() + i, in.begin() + i + block_size);
        std::vector<byte> cipherblock(block);

        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= keystream[j];

        out.insert(out.end(), block.begin(), block.end());
        prev.assign(cipherblock.begin(), cipherblock.end());
        if (block_size < AES_BLOCK_SIZE) break;
    }
}
inline void OFB_Encrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    std::vector<byte> prev(aes.iv);
    size_t len = in.size();
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte keystream[AES_BLOCK_SIZE];
        aes.EncryptBlock(prev.data(), keystream);
        prev.assign(keystream, keystream + AES_BLOCK_SIZE);

        size_t block_size = std::min(len - i, (size_t)AES_BLOCK_SIZE);
        std::vector<byte> block(in.begin() + i, in.begin() + i + block_size);

        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= keystream[j];

        out.insert(out.end(), block.begin(), block.end());
    }
}
inline void OFB_Decrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    OFB_Encrypt(aes, in, out);
}
inline void CTR_Encrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    std::vector<byte> counter(aes.iv);
    size_t len = in.size();
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte keystream[AES_BLOCK_SIZE];
        aes.EncryptBlock(counter.data(), keystream);

        size_t block_size = std::min(len - i, (size_t)AES_BLOCK_SIZE);
        std::vector<byte> block(in.begin() + i, in.begin() + i + block_size);

        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= keystream[j];

        out.insert(out.end(), block.begin(), block.end());

        for (int k = AES_BLOCK_SIZE - 1; k >= 0; --k) {
            if (++counter[k]) break;
        }
    }
}
inline void CTR_Decrypt(const Engine &aes, const std::vector<byte> &in, std::vector<byte> &out) {
    CTR_Encrypt(aes, in, out);
}
} // namespace Detail

class Result {
    std::vector<byte> data;
public:
    Result(std::vector<byte> dat) : data(std::move(dat)) {}
    std::vector<byte> toVector() const {
        return data;
    }
    std::string toString() const {
        return std::string(data.begin(), data.end());
    }
    std::string toHex() const {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return oss.str();
    }
    std::string toBase64() const {
        static const char b64_table[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        int val=0, valb=-6;
        for (byte c : data) {
            val = (val<<8) + c;
            valb += 8;
            while (valb>=0) {
                out.push_back(b64_table[(val>>valb)&0x3F]);
                valb-=6;
            }
        }
        if (valb>-6) out.push_back(b64_table[((val<<8)>>(valb+8))&0x3F]);
        while (out.size()%4) out.push_back('=');
        return out;
    }
    std::string toAscii() const {
        std::string out;
        for (byte b : data) {
            if (std::isprint(b))
                out += static_cast<char>(b);
            else
                out += '.';
        }
        return out;
    }
};

// -------- Mode wrappers as structs --------
struct ECB {
    static Result Encrypt(const std::string &plaintext, const std::string &key) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::ECB, {});
        std::string padded = Utils::PKCS7Pad(plaintext);
        std::vector<byte> in(padded.begin(), padded.end());
        std::vector<byte> out;
        Detail::ECB_Encrypt(aes, in, out);
        return Result(std::move(out));
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::ECB, {});
        std::vector<byte> out;
        Detail::ECB_Decrypt(aes, ciphertext, out);
        Utils::PKCS7Unpad(out);
        return Result(std::move(out));
    }
};

struct CBC {
    static Result Encrypt(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {}) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        if (iv.empty()) iv = Utils::SecureIVBlock();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CBC, iv);
        std::string padded = Utils::PKCS7Pad(plaintext);
        std::vector<byte> in(padded.begin(), padded.end());
        std::vector<byte> out;
        Detail::CBC_Encrypt(aes, in, out);
        return Result(std::move(out));
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        if (iv.empty()) throw std::invalid_argument("IV required for CBC mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CBC, iv);
        std::vector<byte> out;
        Detail::CBC_Decrypt(aes, ciphertext, out);
        Utils::PKCS7Unpad(out);
        return Result(std::move(out));
    }
};

struct CFB {
    static Result Encrypt(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {}) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        if (iv.empty()) iv = Utils::SecureIVBlock();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CFB, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end());
        std::vector<byte> out;
        Detail::CFB_Encrypt(aes, in, out);
        return Result(std::move(out));
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        if (iv.empty()) throw std::invalid_argument("IV required for CFB mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CFB, iv);
        std::vector<byte> out;
        Detail::CFB_Decrypt(aes, ciphertext, out);
        return Result(std::move(out));
    }
};

struct OFB {
    static Result Encrypt(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {}) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        if (iv.empty()) iv = Utils::SecureIVBlock();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::OFB, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end());
        std::vector<byte> out;
        Detail::OFB_Encrypt(aes, in, out);
        return Result(std::move(out));
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        if (iv.empty()) throw std::invalid_argument("IV required for OFB mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::OFB, iv);
        std::vector<byte> out;
        Detail::OFB_Decrypt(aes, ciphertext, out);
        return Result(std::move(out));
    }
};

struct CTR {
    static Result Encrypt(const std::string &plaintext, const std::string &key, std::vector<byte> iv = {}) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        if (iv.empty()) iv = Utils::SecureIVBlock();
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CTR, iv);
        std::vector<byte> in(plaintext.begin(), plaintext.end());
        std::vector<byte> out;
        Detail::CTR_Encrypt(aes, in, out);
        return Result(std::move(out));
    }
    static Result Decrypt(const std::vector<byte> &ciphertext, const std::string &key, std::vector<byte> iv) {
        if (!IsValidKeySize(key.size())) throw std::invalid_argument("Invalid key size");
        if (iv.empty()) throw std::invalid_argument("IV required for CTR mode");
        std::vector<byte> keyvec(key.begin(), key.end());
        Engine aes(keyvec, Mode::CTR, iv);
        std::vector<byte> out;
        Detail::CTR_Decrypt(aes, ciphertext, out);
        return Result(std::move(out));
    }
};

} // namespace AES

# AES Algorithm

 

The goal of this AES implementation is to provide an understanding of how AES works, AES internal mathematical operations, and its fundamental concepts that make AES so efficient, this has been written in c++ instead of C, this 
is because writing this in C would require an enormous amount of code and you will get lost before reaching the KeySchedule operation.

Note that the code i've written is not intended to be efficient or secure, it just demonstrated AES operations.

I suppose that who is reading this already has some basic knowledge of c++ programming, i tried to not use too complex concepts or esoteric c++ programming, but you are required 
to be familar with basic c++ programming paradigms like OOP(object oriented programming) or template specialization techniques, as these techniques made the code shorter and more comprehensive.

AES aka Rijndale, is a symmetric block cipher algorithm that was developed by the US in 2001 and approved by NIST(national-institute-of-standards-and-technology) to become the AES specification
for the encryption of electronic data.

Before AES, DES(Data-Encryption-Standard) was used to encrypt digital data, DES uses a feistel network and it worked fine for some time, but soon vulnerabilities were found in DES, one being a short key size(64bit), so AES was developed 
to address these issues.

If you want to see also how `DES` works, i have another project [here](https://github.com/MrkFrcsl98/DES_algorithm) that implements DES from scratch, of course, educational purposes only, 
do not even think about using it in real life scenarios because i did not implement any security measures and is not even efficient, it just demonstrates how DES works. 

Rijndael, which is the AES underlying block cipher algorithm, is a symmetric block cipher algorithm that specifies different key and block sizes, but for AES, NIST approved 
the block size to be 128bits and 3 different key sizes(128, 192 and 256 bits). 

AES unlike DES which uses a feistel network structure, it uses a susbtitution-permutation-network and is efficient both in hardware and software.

Unlike DES which uses a fixed number of rounds(16), AES number of rounds depend on the key size used:

| KEYSIZE | ROUNDS |
|---------|--------|
| 128     | 10     |
| 192     | 12     |
| 256     | 14     |

AES defines several constanst(lookup tables) used by AES key operations to generate roundkeys, substitute bytes, etc...
These tables are defined as follows:

| Constant    | SIZE(bytes) |
|-------------|-------------|
| Sbox        | 256         |
| InvSBox     | 256         |
| MixCols     | 16          |
| InvMixCols  | 16          |
| Rcon        | 256         |

These constants are extremely important for AES to work correctly, if a single byte within one of these tables is corrupted or incorrect, AES will fail.
These lookup tables are constructed using a combination of gallois field multiplications and affine transformations.
Additionally there is another important constant value defined by AES, this is the `Nb` constant, which specifies the number of columns in the state
array, and is always set to `4` for AES, this means that the state array is always represented by a 4*4 matrix of bytes.

Additionally AES defines 2 more constants, one is called `Nk` and the other `Nr`.

**Nk** defines the number of 32bit words in the encryption key, these can be 4 for 128bit key, 6 for 192bit key and 8 for 256bit key, but this can be calculated 
like this: `KEY_SIZE / 32`.

**Nr** defines the number of rounds for AES based on the key size, as already said, for 128 bit key, there are a total of 10 rounds, for  192 bit key, there are 
a total of 12 rounds, etc...


Various operations are used to perform AES(Rijndael) encryption and decryption, these operations are:

### For Encryption Aes performs the following operations:

- KeyExpansion
- SubBytes
- ShiftRows
- MixColumns
- AddRoundKey
  
### For Decryption:

- KeyExpansion
- InvShiftRows
- InvSubBytes
- AddRoundKey
- InvMixColumns

One important aspect of these flow of operations, is that the above operations are performed during all rounds except the last round, where the mixColumn and InvMixColumn operations are omitted.

### KeyExpansion
AES starts with the KeyExpansion operation, which generates all required round keys.
The keyExpansion process uses a keyscheduling mechanism to generate round keys aka subkeys using the original key, the number of total subkeys depends on the number of rounds which also depends on the key size(128, 192, 256) -> (10+1, 12+1, 14+1).
Each subkey is 128 bits long, and must be unique for each round.
But wait... why is there 10+1(for 128 bits) instead of 10 subkeys?
Well, the additional(+1) subkey is required for the initial xor operation with the plaintext before the first round of encryption, that's it.
The keyExpansion process takes the original key, and it generates a sequence of roundkeys using substitution box(Sbox) and round constant(Rcon) tables and
and performs several operations like key rotation, several transformations and xor operations on the subkey.


```cpp
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
```

### Padding
As i said, AES works on fixed block size which is 128bits(16 bytes), the data must be multiple of the block size in order for AES to work correctly, 
what happens if the data is not a multiple of the block size? well... you need to implement a padding scheme, a common scheme is PKCS#7, which is a standard developed by the RSA laboratories.
PKCS#7 calculates the total number of bytes to append to the last 16byte block in order to make it a multiple of 16(block size).
The process is very simple, if the last block is 14 bytes long and the required block size is 16 bytes, the total number of bytes to append is 2 in order to
make it a multiple of 16, so PKCS#7 will append 2 bytes all with the value of `2`, if the block size was 12, then would append 4 bytes all with value of `4`.
For example:

`Data = abcdefghijklmn` 14 bytes

in binary this is: `01100001 01100010 01100011 01100100 01100101 01100110 01100111 01101000 01101001 01101010 01101011 01101100 01101101 01101110`

as you can see, we need 2 more bytes to append to the block of data in order to make it a multiple of 16, specifically, we need to append 2 bytes with value of `00000010`, after padding the result block will be:

final block: `01100001 01100010 01100011 01100100 01100101 01100110 01100111 01101000 01101001 01101010 01101011 01101100 01101101 01101110 00000010 00000010`

Now AES can operate on that block of data as it successfully become a multiple of 16.
After decryption, the padding is removed by taking the last byte of the block, and popping from the back of the block until the last byte is not the original last byte anymore.

Block Padding 

```cpp
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
```

Block Unpadding
```cpp
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
```

### Mode Of Operation
AES splits data into 16 byte blocks, each block is then processes by any mode of operation, by default AES employs `ECB`(Electronic-CodeBook) Mode, which 
is the most simple but also weak mode of operation.
The mode of operation specifies how blocks of data are processed, depending on the mode of operation, blocks can be processed in a stream-like manner or fixed-block sizes.
In **ECB** block cipher mode of operation, each block of plaintext is encrypted independently, if a block of plaintext is similar to other blocks, ECB mode
will produce the same ciphertext block, this will lead to pattern recognition or replay attacks due to lack of `diffusion` in the cipher mode.
Depending on the underlying mode of operation, padding will be required or not required, in the case of `ECB`, padding is required.
In ECB padding is required because each block is treated as a fixed 16 bytes block of data, unlike other modes like `CTR`(Counter) mode, which transforms a block cipher into a stream cipher and generates a keystream by encrypting a counter(nonce+counter) value with the key, after generating the keystream, it processes data in 16 byte blocks by xoring the keystream bits with the 16 bytes block, the difference is that the keystream is 16bytes long, and CTR mode operates on blocks of 16 bytes as well, but the way the plaintext/ciphertext block is xored with the keystream allows for arbitrary block sizes.
There are different modes of operation available for AES, some are: **ECB**, **CBC**, **CTR**, **OFB**, **CFB**, **GCM**.
Different modes have different properties(encryption/decryption **Parallelizable**, random read access), parallelizable refers to the ability to process data
simultaneously instead of sequentially.

| Mode | Parallelizable | Parallelizable | Random-Read  | IV  | Counter | Style of Processing |
|------|----------------|----------------|--------------|-----|---------|---------------------|
|      | Encryption     | Decryption     | Access       |     |         |                     |
|      |                |                |              |     |         |                     |
| ECB  | YES            | YES            | YES          | NO  | NO      | Fixed-block-size    |
| CBC  | NO             | YES            | YES          | YES | NO      | Fixed-block-size    |
| OFB  | NO             | NO             | NO           | YES | NO      | Stream-like         |
| CFB  | NO             | YES            | YES          | YES | NO      | Stream-like         |
| CTR  | YES            | YES            | YES          | YES | YES     | Stream-like         |
| GCM  | YES            | YES            | YES          | YES | YES     | Stream-like         |




## How It Works

### AES Components


### Key Generation


## Usage

### Prerequisites

- A C++ compiler supporting C++17 or later.
- Linux/Unix system recommended for the CSPRNG functionality.

### Example Code

```cpp

```

### Test Vectors



## Key Classes and Functions

## Modes Of Operatios

### `AesCryptoModule::ModeOfOperation::ECB_Mode`
Handles ECB(Electronic-Code-Book) mode of operation.

### `AesCryptoModule::ModeOfOperation::CBC_Mode`
Handles CBC(Cipher-Block-Chaining) mode of operation.

### `AesCryptoModule::ModeOfOperation::OFB_Mode`
Handles OFB(Output-Feedback) mode of operation.

### `AesCryptoModule::ModeOfOperation::CFB_Mode`
Handles CFB(Cipher-Feedback) mode of operation.

### `AesCryptoModule::ModeOfOperation::CTR_Mode`
Handles CTR(Counter) mode of operation.

## AES Encryption/Decryption

### `AesCryptoModule::AES_Encryption`
Handles AES encryption for a specified key size (`AES128KS`, `AES192KS` or `AES256KS`).

### `AesCryptoModule::AES_Decryption`
Handles AES decryption for a specified key size.

### `AESUtils`
Utility class for AES-specific operations:
- S-Box generation.
- Rijndael MixColumns and InvMixColumns constants.
- Secure key generation.

### `Test::CSPRNG`
A cryptographically secure pseudo-random number generator for secure key generation.

---

## Limitations

1. **Security**:
   - Does not protect against attacks such as side channel and cache based...
   
2. **CSPRNG on Windows**:
   - Windows uses a fallback Mersenne Twister PRNG, which provides lower entropy.

---

## Contributions

Contributions are welcome! If you encounter issues or have suggestions, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

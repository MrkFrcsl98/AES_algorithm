# AES Algorithm

# Contents

* Disclaimer
* How AES works
* Prerequisites
* Code Components
* Test Vectors
* Usage
* Limitations
* Resources
* Contributions
* License


## ⚠ Disclaimer 🚨

This implementation of the **AES (Advanced Encryption Standard)** algorithm is provided for **educational and demonstration purposes only**.  
It is **not intended** to be secure, efficient, or suitable for production environments.  

👉 **Recommendation:** Use well-established and thoroughly tested cryptographic libraries for robust encryption needs.


## How AES works

The goal of this [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) implementation is to provide an understanding of how [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) works, [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) internal mathematical operations, and its fundamental concepts that make [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) so efficient, this has been written in c++ instead of C, this 
is because writing this in C would require an enormous amount of code and you will get lost before reaching the [KeySchedule](https://en.wikipedia.org/wiki/AES_key_schedule) operation.

Note that the code i've written is not intended to be efficient or secure, it just demonstrated [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) operations.

I suppose that who is reading this already has some basic knowledge of c++ programming, i tried to not use too complex concepts or esoteric c++ programming, but you are required 
to be familar with basic c++ programming paradigms like OOP(object oriented programming) or template specialization techniques, as these techniques made the code shorter and more comprehensive.

AES aka Rijndale, is a symmetric block cipher algorithm that was developed by the US in 2001 and approved by [NIST](https://www.nist.gov/)(national-institute-of-standards-and-technology) to become the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) specification
for the encryption of electronic data.

Before AES, DES(Data-Encryption-Standard) was used to encrypt digital data, DES uses a feistel network and it worked fine for some time, but soon vulnerabilities were found in DES, one being a short key size(64bit), so [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) was developed 
to address these issues.

If you want to see also how `DES` works, i have another project [here](https://github.com/MrkFrcsl98/DES_algorithm) that implements DES from scratch, of course, educational purposes only, 
do not even think about using it in real life scenarios because i did not implement any security measures and is not even efficient, it just demonstrates how DES works. 

Rijndael, which is the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) underlying block cipher algorithm, is a symmetric block cipher algorithm that specifies different key and block sizes, but for AES, [NIST](https://www.nist.gov/) approved 
the block size to be 128bits and 3 different key sizes(128, 192 and 256 bits). 

AES unlike DES which uses a feistel network structure, it uses a susbtitution-permutation-network and is efficient both in hardware and software.

Unlike DES which uses a fixed number of rounds(16), [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) number of rounds depend on the key size used:

| KEYSIZE | ROUNDS |
|---------|--------|
| 128     | 10     |
| 192     | 12     |
| 256     | 14     |

AES defines several constanst(lookup tables) used by [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) key operations to generate roundkeys, substitute bytes, etc...
These tables are defined as follows:

| Constant    | SIZE(bytes) |
|-------------|-------------|
| Sbox        | 256         |
| InvSBox     | 256         |
| MixCols     | 16          |
| InvMixCols  | 16          |
| Rcon        | 256         |

These constants are extremely important for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) to work correctly, if a single byte within one of these tables is corrupted or incorrect, [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) will fail.
These lookup tables are constructed using a combination of gallois field multiplications and affine transformations.
Additionally there is another important constant value defined by AES, this is the `Nb` constant, which specifies the number of columns in the state
array, and is always set to `4` for AES, this means that the state array is always represented by a 4*4 matrix of bytes.

Additionally [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) defines 2 more constants, one is called `Nk` and the other `Nr`.

**Nk** defines the number of 32bit words in the encryption key, these can be 4 for 128bit key, 6 for 192bit key and 8 for 256bit key, but this can be calculated 
like this: `KEY_SIZE / 32`.

**Nr** defines the number of rounds for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) based on the key size, as already said, for 128 bit key, there are a total of 10 rounds, for  192 bit key, there are 
a total of 12 rounds, etc...


Various operations and transformations are performed in AES(Rijndael) encryption and decryption, these operations are:

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
As i said, [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) works on fixed block size which is 128bits(16 bytes), the data must be multiple of the block size in order for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) to work correctly, 
what happens if the data is not a multiple of the block size? well... you need to implement a padding scheme, a common scheme is PKCS#7, which is a standard developed by the RSA laboratories.
PKCS#7 calculates the total number of bytes to append to the last 16byte block in order to make it a multiple of 16(block size).
The process is very simple, if the last block is 14 bytes long and the required block size is 16 bytes, the total number of bytes to append is 2 in order to
make it a multiple of 16, so [PKCS#7](https://en.wikipedia.org/wiki/PKCS_7) will append 2 bytes all with the value of `2`, if the block size was 12, then would append 4 bytes all with value of `4`.
For example:

`Data = abcdefghijklmn` 14 bytes

in binary this is: `01100001 01100010 01100011 01100100 01100101 01100110 01100111 01101000 01101001 01101010 01101011 01101100 01101101 01101110`

as you can see, we need 2 more bytes to append to the block of data in order to make it a multiple of 16, specifically, we need to append 2 bytes with value of `00000010`, after padding the result block will be:

final block: `01100001 01100010 01100011 01100100 01100101 01100110 01100111 01101000 01101001 01101010 01101011 01101100 01101101 01101110 00000010 00000010`

Now [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) can operate on that block of data as it successfully become a multiple of 16.
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
AES splits data into 16 byte blocks, each block is then processes by any mode of operation, by default [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) employs `ECB`(Electronic-CodeBook) Mode, which 
is the most simple but also weak mode of operation, actually, this mode is also called `mode-less` mode, as it is actually just [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) implementation.
The mode of operation specifies how blocks of data are processed, depending on the mode of operation, blocks can be processed in a stream-like manner or fixed-block sizes.
In **ECB** block cipher mode of operation, each block of plaintext is encrypted independently, if a block of plaintext is similar to other blocks, ECB mode
will produce the same ciphertext block, this will lead to pattern recognition or replay attacks due to lack of [diffusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion) in the cipher mode.
Depending on the underlying mode of operation, padding will be required or not required, in the case of `ECB`, padding is required.
In ECB padding is required because each block is treated as a fixed 16 bytes block of data, unlike other modes like `CTR`(Counter) mode, which transforms a block cipher into a stream cipher and generates a keystream by encrypting a counter(nonce+counter) value with the key, after generating the keystream, it processes data in 16 byte blocks by xoring the keystream bits with the 16 bytes block, the difference is that the keystream is 16bytes long, and CTR mode operates on blocks of 16 bytes as well, but the way the plaintext/ciphertext block is xored with the keystream allows for arbitrary block sizes.
There are different modes of operation available for AES, some are: **ECB**, **CBC**, **CTR**, **OFB**, **CFB**, **GCM**.
Different modes have different properties(encryption/decryption **Parallelizable**, random read access), parallelizable refers to the ability to process data
simultaneously instead of sequentially.

| Mode | Parallelizable | Parallelizable | Random-Read  | [IV](https://en.wikipedia.org/wiki/Initialization_vector)  | Counter | Style of Processing |
|------|----------------|----------------|--------------|-----|---------|---------------------|
|      | Encryption     | Decryption     | Access       |     |         |                     |
|      |                |                |              |     |         |                     |
| ECB  | YES            | YES            | YES          | NO  | NO      | Fixed-block-size    |
| CBC  | NO             | YES            | YES          | YES | NO      | Fixed-block-size    |
| OFB  | NO             | NO             | NO           | YES | NO      | Stream-like         |
| CFB  | NO             | YES            | YES          | YES | NO      | Stream-like         |
| CTR  | YES            | YES            | YES          | YES | YES     | Stream-like         |
| GCM  | YES            | YES            | YES          | YES | YES     | Stream-like         |


Pseudo code for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) ECB Encryption/Decryption:
```
BEGIN
    DEFINE BLOCK_SIZE = 16
    FUNCTION AES_ECB_ENCRYPT(plaintext, key)
        SPLIT plaintext INTO blocks OF BLOCK_SIZE
        FOR EACH block IN blocks
            encrypted_block = AES_ENCRYPT(block, key)
            APPEND encrypted_block TO ciphertext
        RETURN ciphertext

    FUNCTION AES_ECB_DECRYPT(ciphertext, key)
        SPLIT ciphertext INTO blocks OF BLOCK_SIZE
        FOR EACH block IN blocks
            decrypted_block = AES_DECRYPT(block, key)
            APPEND decrypted_block TO plaintext
        RETURN plaintext
END
```

Pseudo code for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) CBC Encryption/Decryption
```
BEGIN
    DEFINE BLOCK_SIZE = 16
    FUNCTION AES_CBC_ENCRYPT(plaintext, key, iv)
        SPLIT plaintext INTO blocks OF BLOCK_SIZE
        SET previous_block = iv
        FOR EACH block IN blocks
            xor_block = XOR(block, previous_block)
            encrypted_block = AES_ENCRYPT(xor_block, key)
            APPEND encrypted_block TO ciphertext
            SET previous_block = encrypted_block
        RETURN ciphertext

    FUNCTION AES_CBC_DECRYPT(ciphertext, key, iv)
        SPLIT ciphertext INTO blocks OF BLOCK_SIZE
        SET previous_block = iv
        FOR EACH block IN blocks
            decrypted_block = AES_DECRYPT(block, key)
            xor_block = XOR(decrypted_block, previous_block)
            APPEND xor_block TO plaintext
            SET previous_block = block
        RETURN plaintext
END
```

Pseudo code for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) OFB Encryption/Decryption
```
BEGIN
    DEFINE BLOCK_SIZE = 16
    FUNCTION AES_OFB_ENCRYPT(plaintext, key, iv)
        SPLIT plaintext INTO blocks OF BLOCK_SIZE
        SET feedback = iv
        FOR EACH block IN blocks
            feedback = AES_ENCRYPT(feedback, key)
            xor_block = XOR(block, feedback)
            APPEND xor_block TO ciphertext
        RETURN ciphertext

    FUNCTION AES_OFB_DECRYPT(ciphertext, key, iv)
        SPLIT ciphertext INTO blocks OF BLOCK_SIZE
        SET feedback = iv
        FOR EACH block IN blocks
            feedback = AES_ENCRYPT(feedback, key)
            xor_block = XOR(block, feedback)
            APPEND xor_block TO plaintext
        RETURN plaintext
END
```

Pseudo code for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) CFB Encryption/Decryption
```
BEGIN
    DEFINE BLOCK_SIZE = 16
    FUNCTION AES_CFB_ENCRYPT(plaintext, key, iv)
        SPLIT plaintext INTO blocks OF BLOCK_SIZE
        SET feedback = iv
        FOR EACH block IN blocks
            feedback = AES_ENCRYPT(feedback, key)
            xor_block = XOR(block, feedback)
            APPEND xor_block TO ciphertext
            SET feedback = xor_block
        RETURN ciphertext

    FUNCTION AES_CFB_DECRYPT(ciphertext, key, iv)
        SPLIT ciphertext INTO blocks OF BLOCK_SIZE
        SET feedback = iv
        FOR EACH block IN blocks
            feedback = AES_ENCRYPT(feedback, key)
            xor_block = XOR(block, feedback)
            APPEND xor_block TO plaintext
            SET feedback = block
        RETURN plaintext
END
```


Pseudo code for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) CTR Encryption/Decryption
```
BEGIN
    DEFINE BLOCK_SIZE = 16
    FUNCTION AES_CTR_ENCRYPT(plaintext, key, nonce)
        SPLIT plaintext INTO blocks OF BLOCK_SIZE
        SET counter = 0
        FOR EACH block IN blocks
            counter_block = CONCAT(nonce, counter)
            keystream = AES_ENCRYPT(counter_block, key)
            xor_block = XOR(block, keystream)
            APPEND xor_block TO ciphertext
            INCREMENT counter
        RETURN ciphertext

    FUNCTION AES_CTR_DECRYPT(ciphertext, key, nonce)
        SPLIT ciphertext INTO blocks OF BLOCK_SIZE
        SET counter = 0
        FOR EACH block IN blocks
            counter_block = CONCAT(nonce, counter)
            keystream = AES_ENCRYPT(counter_block, key)
            xor_block = XOR(block, keystream)
            APPEND xor_block TO plaintext
            INCREMENT counter
        RETURN plaintext
END
```

Pseudo code for [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) GCM Encryption/Decryption
```
BEGIN
    DEFINE BLOCK_SIZE = 16
    FUNCTION AES_GCM_ENCRYPT(plaintext, key, iv, additional_data)
        SET gcm_context = INITIALIZE_GCM_CONTEXT(key, iv)
        IF additional_data EXISTS
            UPDATE_AUTHENTICATION_TAG(gcm_context, additional_data)
        SPLIT plaintext INTO blocks OF BLOCK_SIZE
        FOR EACH block IN blocks
            encrypted_block = GCM_ENCRYPT_BLOCK(gcm_context, block)
            APPEND encrypted_block TO ciphertext
        FINALIZE_GCM_CONTEXT(gcm_context)
        RETURN (ciphertext, AUTHENTICATION_TAG(gcm_context))

    FUNCTION AES_GCM_DECRYPT(ciphertext, key, iv, additional_data, auth_tag)
        SET gcm_context = INITIALIZE_GCM_CONTEXT(key, iv)
        IF additional_data EXISTS
            UPDATE_AUTHENTICATION_TAG(gcm_context, additional_data)
        SPLIT ciphertext INTO blocks OF BLOCK_SIZE
        FOR EACH block IN blocks
            decrypted_block = GCM_DECRYPT_BLOCK(gcm_context, block)
            APPEND decrypted_block TO plaintext
        FINALIZE_GCM_CONTEXT(gcm_context)
        IF AUTHENTICATION_TAG(gcm_context) ≠ auth_tag
            RAISE AUTHENTICATION_ERROR
        RETURN plaintext
END
```


`ECB` mode does not require any additional authentication data(**AAD**) unlike `CBC` which requires an **[IV](https://en.wikipedia.org/wiki/Initialization_vector)**(initialization-vector), the [IV](https://en.wikipedia.org/wiki/Initialization_vector) must be of 16 bytes in size and used only once per session.
`ECB` mode and `CBC` mode do not provide integrity and authenticity of data, for this purpose there are other modes.
Other modes like `CTR`, also require an additional value, called the counter, which is usually set to 0, and incremented for each round.
In `CTR` mode the [IV](https://en.wikipedia.org/wiki/Initialization_vector) is actually called [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce), the counter and the nonce are combined and encrypted using AES-ECB to generate a keystream, this keystream will then be xored with the plaintext to produce the first ciphertext block. 
Decryption in `CTR` is identical to encryption, instead of using the plaintext, it xor's the ciphertext with the keystream to recover the plaintext.
None of these modes provide authenticity and integrity of data, if you want authenticity and inegrity of data being processed, you will use a mode called `GCM`(gallois-counter) mode.
`GCM` provides both authenticity and integrity, this is done with an additional value called the `authTag`, which is a special tag used to authenticated the message or data, the tag is appended to the message and then extracted to authenticate it. 
`GCM` uses `CTR` block cipher algorithm at its core, with additional authentication and integrity check mechanisms, GCM is both fast and secure, but more complex to implement.
In other words, the mode of operation defines how blocks of data are processed and if additional authentication data `aad` and `authTag` used in `GCM` mode need to be applied or not.
Depending on the mode of operation, data can be processed in a stream-like manner or in a fixed-size blocks. Modes like `ECB` and `CBC`, process data in a fixed-block size, where each block 
is 128bits(16 bytes) long, these modes of operation require the data to be a multiple of the block size, in the case of `AES`, the block size is always 128bits(16 bytes), and a padding scheme such as [PKCS#7](https://en.wikipedia.org/wiki/PKCS_7) needs to be applied to the data before processing. 
Other modes such as `OFB`or `CTR`, process data in a stream-like style, here, the last block of data does not need to be padded.
In `CTR` mode, a counter and a nonce, are used to generate a keystream, a 16 byte block of data later xored with the block of plaintext, which can be either 16 bytes or shorter. 
The nonce must be 8 bytes long, and the counter must also 8 bytes long, the counter is combined with the nonce and then encrypted using the key in `ECB` mode, as i said, ECB basically is a mode-less mode, and the result is xored with the plaintext or ciphertext depending on the operation begin performed. 
`CBC` mode is very simple mode of operation, the encryption starts with an initial `IV`, the `IV` is a 128bit array of secure random bytes, which must be generated by a [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) function or if there is no possibility of using a [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator), a `PRNG` is used instead, but the last one is very insecure and often generates predictable and deterministic random bytes.
During the first round of encryption, `CBC` xores the [IV](https://en.wikipedia.org/wiki/Initialization_vector) with the first 16 byte block of the plaintext, the result is then encrypted and the `IV`  becomes the encrypted 16 byte block, the 
next round, `CBC` will again repeat this operation, but this time, the [IV](https://en.wikipedia.org/wiki/Initialization_vector) will be the previous encrypted block, the process repeats for all blocks of data until reaching the last block.
For `CBC` decryption operation, the algorithm start again with the original `IV`, be very careful in this step, because the [IV](https://en.wikipedia.org/wiki/Initialization_vector) must be the original value used in the initial round of encryption and not the last encrypted block, wrong usage of the [IV](https://en.wikipedia.org/wiki/Initialization_vector) will lead to errors in decryption, so make sure the original [IV](https://en.wikipedia.org/wiki/Initialization_vector) is not modified by the encryption operation.
The decryption process is similar to encryption, with minor differences, the way data is processed stays the same, but instead of xoring the [IV](https://en.wikipedia.org/wiki/Initialization_vector) with the ciphertext block, first the ciphertext block denoted by `Ci`, is decrypted using the same key, and then the `IV` which during the first round will be the original [IV](https://en.wikipedia.org/wiki/Initialization_vector) also used within the first round of encryption,
is xored with the decrypted block and the `IV` becomes the previous ciphertext block, this process is repeated for all blocks of data.

#### State Matrix Initialization

During each round of encryption, [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) performs a state matrix initialization operation, the state matrix, which is a 4*4 matrix(4 rows and 4 columns) for AES-128, undergoes a [transposition](https://en.wikipedia.org/wiki/Transpose) operation, 
where each byte is of the block is transposed from a linear format into a column-major order, let's say the block of data contains the following bytes: `abcdefghijklmnop`, the state matrix 
will be populated like this: 

```
state_matrix[0][0] = 'a'  (bytes[0 + 4*0])
state_matrix[1][0] = 'b'  (bytes[1 + 4*0])
state_matrix[2][0] = 'c'  (bytes[2 + 4*0])
state_matrix[3][0] = 'd'  (bytes[3 + 4*0])

state_matrix[0][1] = 'e'  (bytes[0 + 4*1])
state_matrix[1][1] = 'f'  (bytes[1 + 4*1])
state_matrix[2][1] = 'g'  (bytes[2 + 4*1])
state_matrix[3][1] = 'h'  (bytes[3 + 4*1])

state_matrix[0][2] = 'i'  (bytes[0 + 4*2])
state_matrix[1][2] = 'j'  (bytes[1 + 4*2])
state_matrix[2][2] = 'k'  (bytes[2 + 4*2])
state_matrix[3][2] = 'l'  (bytes[3 + 4*2])

state_matrix[0][3] = 'm'  (bytes[0 + 4*3])
state_matrix[1][3] = 'n'  (bytes[1 + 4*3])
state_matrix[2][3] = 'o'  (bytes[2 + 4*3])
state_matrix[3][3] = 'p'  (bytes[3 + 4*3])
```

In this code, the specific function responsible for this [transposition](https://en.wikipedia.org/wiki/Transpose) during state matrix initialization is:

```cpp
__attribute__((hot, nothrow)) inline void _initStateMatrix(const std::string &block) noexcept
    {
        for (byte r{0}; r < Nb; ++r)
            for (byte c{0}; c < Nb; ++c)
                this->state_matrix[r][c] = block[r + Nb * c];
    }
```

As you can see, there is no error checking at all, i know it should be, but the only goal of this project is to demostrate [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) implementation, not to provide you with a fully working 
AES cryptography library, for this purpose there are lots of secure and established libraries like `openSSL` or `crypto++` for C/c++.

After state matrix initialization, the method `addRoundKey` is invoked specifying the round as `0` for the argument, during this operation, the state matrix undergoes a transformation where specific byte positions are xored with the current round key aka subkey, during decryption, the value of the parameter which previously was passed as `0`, will be the value of `Nr`, which is the number of rounds.

After this initial addRoundKey execution during encryption, a function called `initMainRounds` will perform [SubBytes](https://en.wikipedia.org/wiki/Rijndael_S-box), `ShiftRows`, [mixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns), and an additional `addRoundKey` operation, 
these sequence of transformations will provide diffusion, [confusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion) and non-linearity into the algorithm, which are essential properties for a secure algorithm.

#### Encryption - SubBytes

First it start with `subBytes` operation, during this operation the previous table we defined as `Sbox`(substitution-box) is used for byte substitution.
The state matrix undergoes a transformation process, which is a non-linear byte substitution operation that provides confusion, again... [confusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion) refers to the process of 
obscuring the relationship between the plaintext and the ciphertext, during `subBytes` execution, state matrix bytes are replaced with specific bytes from the `Sbox` table.
For example, let's say the current byte undergoing the substitution has the value `0x53`, this means that this byte will be replaced with the value from the `Sbox[0x53]`, this is a very simple concept.

```
1. Take a 4x4 matrix (state matrix) as input. Each element in the matrix is a single byte.
   Example State Matrix:
   [a0, a1, a2, a3]
   [a4, a5, a6, a7]
   [a8, a9, aa, ab]
   [ac, ad, ae, af]

2. For each byte in the matrix, perform a substitution using a predefined substitution box (Sbox).
   - The Sbox maps each input byte to a different output byte based on a lookup table.
   - This step improves security by adding non-linearity.

3. Replace each byte in the matrix with the corresponding value from the Sbox.

4. The resulting matrix after substitution is the new state matrix.
   Example:
   [s0, s1, s2, s3]
   [s4, s5, s6, s7]
   [s8, s9, sa, sb]
   [sc, sd, se, sf]
```

#### Encryption - ShiftRows

After [SubBytes](https://en.wikipedia.org/wiki/Rijndael_S-box) operation, the following function to execute is `ShiftRows`.
During ShiftRows operation, the rows of the state matrix are shifted to the left cyclically by `n` positions, the first row stays the same, the second row is shifted to the left
by 1 position, the third row is shifted to the left by 2 positions, and the fourth row is shifted to the left by 3 positions.

The operation looks something like this:

```
Example state matrix:
   [a0, a1, a2, a3]
   [a4, a5, a6, a7]
   [a8, a9, aa, ab]
   [ac, ad, ae, af]

Applying the shift operation:
   [a0, a1, a2, a3]  -> row 0: no shift.
   [a5, a6, a7, a4]  -> row 1: left shift by 1.
   [aa, ab, a8, a9]  -> row 2: left shift by 2.
   [af, ac, ad, ae]  -> row 3: left shift by 3.

The result state matrix will be:
   [a0, a1, a2, a3]
   [a5, a6, a7, a4]
   [aa, ab, a8, a9]
   [af, ac, ad, ae]
```

#### Encryption - MixColumns

After `shiftRows`, `MixColumns` is performed. This function is more complex than the previous 2 operations, as it employs gallois-field multiplication operations.
This operation introduces [diffusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion) by mixing bytes in each column of the state matrix, this is done using matrix multiplication in a finite field(`GF(2^8)`).

Let's say you have a 4*4 state matrix with the value of:

```
[s0, s1, s2, s3]
[s4, s5, s6, s7]
[s8, s9, sa, sb]
[sc, sd, se, sf]
```

here, each column in the matrix is treated as a 4 bye vector and multiplied by a 4*4 matrix in `GF(2^8)`.

Let's say the 4*4 fixed matrix looks like this:

```
[02 03 01 01]
[01 02 03 01]
[01 01 02 03]
[03 01 01 02]
```

This multiplication is performed column-wise, where each byte in the vector is transformed based on finite field arithmetic.
For example, after transformation, the result state matrix will be:

```
[m0, m1, m2, m3]
[m4, m5, m6, m7]
[m8, m9, ma, mb]
[mc, md, me, mf]
```

The entire process can be visualize this this:

```
[s0, s1, s2, s3]
[s4, s5, s6, s7]
[s8, s9, sa, sb]
[sc, sd, se, sf]

Column 0: [s0, s4, s8, sc]  -> [m0, m4, m8, mc]
Column 1: [s1, s5, s9, sd]  -> [m1, m5, m9, md]
Column 2: [s2, s6, sa, se]  -> [m2, m6, ma, me]
Column 3: [s3, s7, sb, sf]  -> [m3, m7, mb, mf]

[m0, m1, m2, m3]
[m4, m5, m6, m7]
[m8, m9, ma, mb]
[mc, md, me, mf]
```

The function in this code responsible for handling this [mixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns) operation is defined as following:

```cpp
 __attribute__((hot, nothrow)) inline void _mixColumns() noexcept
    {
        for (uint64_t i = 0; i < Nb; ++i)
        {
            std::array<byte, 4> temp;
            temp[0] = __gfmultip2(this->state_matrix[0][i]) ^ __gfmultip3(this->state_matrix[1][i]) ^ this->state_matrix[2][i]              ^ this->state_matrix[3][i];
            temp[1] = this->state_matrix[0][i]              ^ __gfmultip2(this->state_matrix[1][i]) ^ __gfmultip3(this->state_matrix[2][i]) ^ this->state_matrix[3][i];
            temp[2] = this->state_matrix[0][i]              ^ this->state_matrix[1][i]              ^ __gfmultip2(this->state_matrix[2][i]) ^ __gfmultip3(this->state_matrix[3][i]);
            temp[3] = __gfmultip3(this->state_matrix[0][i]) ^ this->state_matrix[1][i]              ^ this->state_matrix[2][i]              ^ __gfmultip2(this->state_matrix[3][i]);
            for (uint8_t j = 0; j < 4; ++j)
            {
                this->state_matrix[j][i] = temp[j];
            }
        }
    }
```

I will skip the description of gallois field multiplication, as it requires a lot of mathematics, and it will get boring, so let's just assume you don't care about this arithmetic operation, and jump to the next and last operation within this round of encryption which is the `addRoundKey` operation.

#### Encryption - AddRoundKey

You should be already familiar with this operation, as we talked about it before, so now i will just skip the introduction to it and just let you know that this operation gets called in every round 
of encryption and decryption as the last function, and it just adds more [diffusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion) to the process.

Round operations in [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) look like this:

```cpp
for (uint64_t round = 1; round < Nr; ++round)
        {
            this->_subBytes();
            this->_shiftRows();
            this->_mixColumns();
            this->_addRoundKey(round);
        }
```

**NOTE** the rounds start at 1 not at 0!!!


### Encryption - Final Round

The final round of [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption consists of all the operations within each round but it omits the [mixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns) operation.
You might ask why, well, i did ask why as well when i was learning about this, the reason is that as you might know at this point, [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption and decryption
processes are symmetric, meaning the operations must be reversible, if mixColumns were to be applies also in the last round, it will require an additional step to undo it during decryption.
So, omitting [mixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns) in the last round, ensures that the ciphertext can be decryption without additional operations, if it is not omitted in the last round, it would further mix the 
bytes, making the final decryption step unnecessarily complex and less efficient. 

The final round operations instead look like this:

```cpp
void _finalRound(const uint64_t r) override
    {
        this->_subBytes();
        this->_shiftRows();
        this->_addRoundKey(r);
    }
```

### Decryption

during decryption, the operations are the same with minor changes:

- instead of using `Sbox` table, decryption uses `InvSbox` table.
- instead of using `mixCols` table, decryption uses `InvMixCols` table.

Beside the change in the tables used for the operations(subBytes, mixColumns), there are also some changes in the order of how `subBytes`, `shiftRows`, [mixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns), and `addRoundKey` operations
are performed.
During decryption, [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) still performed the same steps with the usual initial `addRoundKey` operation, `n` rounds of decryption, and the final round of decryption where `invMixColumns` operation is 
omitted.

#### Decryption - Each Round of Decryption
The structure of each round of decryption looks like this:

```cpp
void _execRound(const uint64_t r) override
    {
        this->_invShiftRows();
        this->_invSubBytes();
        this->_addRoundKey(r);
        this->_invMixColumns();
    }
```

#### Decryption - Final Round of Decryption
as in the encryption process, the `invMixColumns` operation is omitted:

```cpp
void _finalRound(const uint64_t r) override
    {
        this->_invShiftRows();
        this->_invSubBytes();
        this->_addRoundKey(r);
    }
```

I want to specify that even if the function names where in encryption are `subBytes` and decryption are `InvSubBytes` are different, in reality, the only difference is that each function uses a different lookup table, the first one uses `Sbox`, the second uses `InvSbox`, but there is no difference in how data is treated.

The last difference in decryption, is that while in encryption process the round of encryption operations is incremented(`++`), in decryption the rounds decrement(`--`), to make it simple to understand, here is a representation of a round:

```cpp
for (uint64_t round = (Nr - 1); round > 0; --round)
        {
            this->_invShiftRows();
            this->_invSubBytes();
            this->_addRoundKey(round);
            this->_invMixColumns();
        }
```



## Prerequisites

- A C++ compiler supporting C++17 or later.
- Linux/Unix system recommended for the [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) functionality.




## Code Components 

There are various components defined within `aes.hpp` header file, these are:

- AesCryptoModule                      -> `namespace encapsulating all header file functions`
- PRNG(Pseudo-Random-Number-Generator) -> `class that generates random bytes, used for key and iv byte generation`
- AESUtils                             -> `class encapsulating general AES utility functions`
- AESMode                              -> `namespace encapsulating various AES modes of operation`
- AESMode::ECB_Mode                    -> `class for ECB mode of operation encryption/decryption operations`
- AESMode::CBC_Mode                    -> `class for CBC mode of operation encryption/decryption operations`
- AESMode::CTR_Mode                    -> `class for CTR mode of operation encryption/decryption operations`
- AESMode::OFB_Mode                    -> `class for OFB mode of operation encryption/decryption operations`
- AESMode::CFB_Mode                    -> `class for CFB mode of operation encryption/decryption operations`
- AES_Encryption                       -> `AES encryption class, handles AES encryption`
- AES_Decryption                       -> `AES decryption class, handles AES decryption`
- AesEngine                            -> `AES Engine class, encapsulates AES operations like SubBytes, ShiftRows, etc...`


## Test Vectors

Additional test vectors can be found within `aes-test.hpp` header file, this includes the following members:

- CSPRNG(Cryptographically-Secure-PRNG) -> `a secure PRNG version i wrote because the PRNG within aes.hpp produces predictable blocks for key/IV`
- execAES128 -> `function to execute AES-128 tests`
- execAES192 -> `function to execute AES-192 tests`
- execAES256 -> `function to execute AES-256 tests`
- run_AES_ECB_test -> `execute test for AES-ECB mode with key size(128, 192 and 256)`
- run_AES_CBC_test -> `execute test for AES-CBC mode with key size(128, 192 and 256)`
- run_AES_CTR_test -> `execute test for AES-CTR mode with key size(128, 192 and 256)`
- run_AES_OFB_test -> `execute test for AES-OFB mode with key size(128, 192 and 256)`
- run_AES_CFB_test -> `execute test for AES-CFB mode with key size(128, 192 and 256)`
- runGlobal -> `execute all above test vectors`

**NOTE** that the CSPRNG version within `aes-test.hpp` works only on linux systems, i did not implement it for windows systems, if you're using windows, the fallback function will be
the one using mersenneTwister PRNG!


## Usage 

Now let's see how to use the code in `aes.hpp` and `aes-test.hpp`, this is the easy part if you reached this point.

First of all, let's say that `AES_Encryption` and `AES_Decryption` both use template specialization to handle different AES key sizes and various modes of operation.
To use `AES_Encryption`/`AES_Decryption` utility classes, you need to include `aes.hpp` header file:

```cpp
#include "aes.hpp"
```

After including the header file, `AES_Encryption` and `AES_Decryption` can be found within `AesCryptoModule` namespace.

You might either extract everything from the namespace:

```cpp
using namespace AesCryptoModule;
```

Or just rename the namespace to a shorter identifier:

```cpp
namespace AES = AesCryptoModule;
```

If you want to use the available test vectors within `aes-test.hpp`, include the header:

```cpp
#include "aes-test.hpp"
```

Test vectors can be found within the namespace `AESTest`, test vectors include:

### Run AES-ECB[128,192,256] tests

this will execute AES-ECB mode in all AES key sizes.

```cpp
run_AES_ECB_test();
```

execute AES-CBC mode...

```cpp
run_AES_CBC_test();
```

AES-CTR mode...

```cpp
run_AES_CTR_test();
```

AES-OFB mode...

```cpp
run_AES_OFB_test();
```

AES-CFB mode...

```cpp
run_AES_CFB_test();
```

Or you can just run all of them...

```cpp
runGlobal();
```


If you do not care about test vectors, but you want to handle encryption and decryption by yourself, then you do not need to include `aes-test.hpp` header, but only include `aes.hpp` header.

Let's see how to encrypt a message using AES-128-ECB:


Include require headers and define main function structure:

```cpp
#include "aes.hpp"
#include <iostream> // for output stream
#include <iomanip> // for hex output

int main(int argc, char** argv)
{
    try{
        // code goes here...
    }catch(const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
        return 1; // return error
    }
  return 0;
}

```

Define required data(message, key, etc...)

```cpp
const uint8_t AES_KEY_SIZE    = 128;                                            // for AES-128 bits
const AES::AESMode AES_MODE   = AES::AESMode::ECB;                              // define the mode of operation
const std::string message     = "some random message to encrypt!";              // this is the message to encrypt
const std::string seckey      = AES::AESUtils::genSecKeyBlock(AES_KEY_SIZE);    // this is the key for AES encryption/decryption
```

Construct AES_Encryption and AES_Decryption objects

```cpp
AES::AES_Encryption<AES_KEY_SIZE, AES_MODE> Encryption; // instantiate AES encryption object
AES::AES_Decryption<AES_KEY_SIZE, AES_MODE> Decryption; // instantiate AES decryption object
```

Ready to encrypt, encrypt message with key

```cpp
const std::vector<byte> ENCRYPTED_DATA = Encryption.apply(message, seckey);                  // encrypt plaintext
```

Recover ciphertext with the same key

```cpp
const std::vector<byte> DECRYPTED_DATA = Decryption.apply(ENCRYPTED_DATA_STR, seckey);       // recover ciphertext
```

Print result...

```cpp
 std::cout << "Encrypted Data(Hex): ";
for(const byte b: ENCRYPTED_DATA) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";

std::cout << std::endl;

std::cout << "Decrypted Data(Hex): ";
for(const byte b: DECRYPTED_DATA) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";

std::cout << std::endl;
```

Full code:

```cpp

#include "aes.hpp"  
#include <iomanip> 
#include <iostream>  

namespace AES = AesCryptoModule;

int main(int argc, char **argv)
{
    try
    {       
        const uint8_t AES_KEY_SIZE    = 128;                                            // for AES-128 bits
        const AES::AESMode AES_MODE   = AES::AESMode::ECB;                              // define the mode of operation
        const std::string message     = "some random message to encrypt!";              // this is the message to encrypt
        const std::string seckey      = AES::AESUtils::genSecKeyBlock(AES_KEY_SIZE);    // this is the key for AES encryption/decryption

        AES::AES_Encryption<AES_KEY_SIZE, AES_MODE> Encryption; // instantiate AES encryption object
        AES::AES_Decryption<AES_KEY_SIZE, AES_MODE> Decryption; // instantiate AES decryption object

        const std::vector<byte> ENCRYPTED_DATA = Encryption.apply(message, seckey);                  // encrypt plaintext

        const std::string ENCRYPTED_DATA_STR(ENCRYPTED_DATA.begin(), ENCRYPTED_DATA.end());          // need to convert to std::string for decryption

        const std::vector<byte> DECRYPTED_DATA = Decryption.apply(ENCRYPTED_DATA_STR, seckey);       // recover ciphertext

        // ------- PRINT RESULT ---------

        std::cout << "Encrypted Data(Hex): ";
        for(const byte b: ENCRYPTED_DATA) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";

        std::cout << std::endl;

        std::cout << "Decrypted Data(Hex): ";
        for(const byte b: DECRYPTED_DATA) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";

        std::cout << std::endl;

    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

```

The above code can be further factorized and simplified to...

```cpp

#include "aes.hpp"
namespace AES = AesCryptoModule;
int main()
{
    const std::string seckey = AES::AESUtils::genSecKeyBlock(128); // this is the key for AES encryption/decryption
    AES::AES_Encryption<128, AES::AESMode::ECB> Encryption;        // instantiate AES encryption object
    AES::AES_Decryption<128, AES::AESMode::ECB> Decryption;        // instantiate AES decryption object
    const std::vector<byte> ENCRYPTED_DATA = Encryption.apply("some random message to encrypt!", seckey);                         // encrypt plaintext
    const std::vector<byte> DECRYPTED_DATA = Decryption.apply(std::string(ENCRYPTED_DATA.begin(), ENCRYPTED_DATA.end()), seckey); // recover ciphertext
    return 0;
}

```


To Use another mode of operation or another key size, just update `AES_MODE` and `AES_KEY_SIZE` variables.

use CBC mode...

```cpp
const AES::AESMode AES_MODE = AES::AESMode::ECB; // ECB mode AKA mode-less mode
const AES::AESMode AES_MODE = AES::AESMode::CBC; // Cipher-Block-Chaninig mode, this requires initialization of IV
const AES::AESMode AES_MODE = AES::AESMode::CTR; // Counter mode, requires nonce, here nonce is IV
const AES::AESMode AES_MODE = AES::AESMode::OFB; // Output Feedback mode, requires IV
const AES::AESMode AES_MODE = AES::AESMode::CFB; // Cipher Feedback mode, require IV
```


To use CBC, CTR, or other modes that require IV, just define another variable called IV or however you like, and call AESUtils::GenIvBlock() function to generate the IV.

```cpp
const std::vector<byte> IV = AES::AESUtils::GenIvBlock(16); // most of the modes like CBC, CTR, OFB, etc.. require the IV to be 16 bytes long.
```

Now just store the value of the IV within Encryption and Decryption objects

```cpp
Encryption.iv = IV;
Decryption.iv = IV;
```

that's it... everything stays the same...


### Here are some screenshots of the results i got on my machine, running all modes of operation and all key sizes...

Result for AES-128[ECB, CBC, CTR, OFB, CFB]
![image](https://github.com/MrkFrcsl98/AES_algorithm/blob/main/rsc/1wqeeqreewqrewrewrewr.png)

Result for AES-192[ECB, CBC, CTR, OFB, CFB]
![image](https://github.com/MrkFrcsl98/AES_algorithm/blob/main/rsc/2rfretertretreterte.png)

Result for AES-256[ECB, CBC, CTR, OFB, CFB]
![image](https://github.com/MrkFrcsl98/AES_algorithm/blob/main/rsc/3rreterregrgrtgry.png)

## Code Security

I need to specify that this code is not secure, and is not efficient, use it for educational purposes only.


## Limitations

1. **Security**:
   - Does not protect against attacks such as side channel and cache based...
   
2. **CSPRNG on Windows**:
   - Windows uses a fallback Mersenne Twister PRNG, which provides lower entropy.


### 🔗 Resources

#### **📚 General Cryptography**
- [Cryptography (Wikipedia)](https://en.wikipedia.org/wiki/Cryptography)  
- [Cryptographic Primitives Overview](https://en.wikipedia.org/wiki/Cryptographic_primitive)  
- [Symmetric-key Cryptography](https://en.wikipedia.org/wiki/Symmetric-key_algorithm)  
- [Public-key Cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)  

#### **🔐 AES (Advanced Encryption Standard)**
- [AES (Wikipedia)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)  
- [NIST AES Specification (FIPS 197)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)  
- [AES Explained (Khan Academy)](https://www.khanacademy.org/computing/computer-science/cryptography/modern-crypt/v/advanced-encryption-standard-aes)  
- [AES Key Sizes and Security](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard)  

#### **🧩 Block Ciphers**
- [Block Cipher (Wikipedia)](https://en.wikipedia.org/wiki/Block_cipher)  
- [Modes of Block Ciphers](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)  
- [ECB vs CBC vs CTR Modes](https://crypto.stackexchange.com/questions/202/what-are-the-differences-between-ecb-cbc-and-ctr-encryption-modes)  
- [Padding in Block Ciphers](https://crypto.stackexchange.com/questions/2996/what-is-padding-and-why-is-it-required)  

#### **📦 Cryptographic Libraries**
- [Crypto++](https://cryptopp.com/)  
- [OpenSSL](https://www.openssl.org/)  
- [Bouncy Castle](https://www.bouncycastle.org/)  
- [Libsodium](https://libsodium.org/)  

#### **📘 Cryptanalysis and Attacks**
- [Cryptanalysis (Wikipedia)](https://en.wikipedia.org/wiki/Cryptanalysis)  
- [Side-channel Attacks](https://en.wikipedia.org/wiki/Side-channel_attack)  
- [Differential Cryptanalysis](https://en.wikipedia.org/wiki/Differential_cryptanalysis)  
- [Linear Cryptanalysis](https://en.wikipedia.org/wiki/Linear_cryptanalysis)  

#### **📄 Additional Learning Resources**
- [Applied Cryptography by Bruce Schneier](https://www.schneier.com/books/applied_cryptography/)  
- [Introduction to Modern Cryptography](https://www.crcpress.com/Introduction-to-Modern-Cryptography/Katz-Lindell/p/book/9780367331757)  
- [Cryptography I (Stanford Online)](https://online.stanford.edu/courses/cs155-cryptography)  

#### **🛠 Tools for Cryptography**
- [Online AES Encryption Tool](https://www.devglan.com/online-tools/aes-encryption-decryption)  
- [CyberChef (The Cyber Swiss Army Knife)](https://gchq.github.io/CyberChef/)  
- [Hash Function Testers](https://passwordsgenerator.net/sha256-hash-generator/)  

---


---

## Contributions

Contributions are welcome! If you encounter issues or have suggestions, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

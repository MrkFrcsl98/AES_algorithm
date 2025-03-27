#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <bitset>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// ----- ABSTRACT -----

// AES(advanced encryption standard) is a symmetric block cipher algorithm, that
// operates on fixed size blocks of data.
// AES is the most widely used algorithm today, is preferred due to its efficiency
// and security properties. AES employs various mathematical operations, including
// Galois Fields. To understand AES, it is important to first understand Galois 
// Fields, AKA finite fields. Galois Fields are mathematical structures, consisting
// of a finite number of elements and follow specific rules for addition, subtraction,
// multiplication, and division.
// A Galois Field is a finite set of elements, denoted as GF(p^n), where "p" is a 
// prime number and "n" is a positive integer, the number of elements in the field
// is given by p^n, and these elements are represented by polynomials of
// degree n-1 with coefficients from the set {0,1,...,p-1}.
// In the context of AES, the galois field used is FG(2^8). This field consists of
// 256 elements, each represented by an 8-bit binary number. Addition and subtraction
// in GF(2^8) are performed using bitwise XOR operations. 
// Multiplication and division are more complex and involve polynomial arithmetic.
// AES operates on a 128-bit block of plaintext. Consisting of several rounds, each
// comprising 4 main transformations: SubBytes, ShiftRows, MixColumns, and AddRoundKey.
// These transformations are applied iteratively to the plaintext using a series of round
// keys derived from the original encryption key.
// During the SubBytes transformation, each byte of the plaintext is substituted with
// a corresponding byte from the AES S-box. The S-box is a substitution table that 
// provides a nonlinear mapping between input and output bytes. 
// This step adds confusion to the encryption process, making it harder for attackers
// to decipher the ciphertext without the key.
// The ShiftRows transformation involves shifting the rows of the state matrix, 
// which represents the current block of data being encrypted. This step ensures that 
// each byte is mixed with data from different columns, increasing diffusion of information
// throughout the block.
// The MixColumns transformation operates on the columns of the state matrix , applying 
// a linear transformation to each column. This step further increases the diffusion
// of information and introduces complexity to the encryption process.
// Finally, the AddRoundKey transformation XORs each byte of the state matrix with
// a corresponding byte from the round key. The round keys are derived from the original
// main key using a key expansion algorithm. This step ensures that each round of 
// encryption uses a different key, enhancing the security of AES.
// By combining 4 transformations in multiple rounds, the AES algorithm achieves a high
// level of security. It is resistant to various cryptographic attacks, including
// differential and linear analysis.

// ------ DETAILED ------
// Galois Field AKA finite fields, play a crucial role in AES, GF is a mathematical
// structure that have properties similar to ordinary arithmetic, but with a finite
// number of elements and with defined addition and multiplication operations.
// They are used in cryptography because they provide a way to
// perform arithmetic operations on binary data efficiently.
// One important concept in Galois field is the notion of a prime field.
// A prime field is a galois field that has a prime number of elements. In the
// context of AES, the the galois field used is GF(2^8), which has 256 elements, this
// means that each element in the field can be represented as by an 8-bit binary number.
// Another important concept in Galois Field is the notion of field operations. Field
// operations, such as addition and multiplication, are defined in such a way that they
// satisfy certain properties, such as closure, associativity, commutativity, and 
// distributivity. These properties ensure that the operations can be performed 
// consistently and efficiently.
// In the context of AES block cipher, Galois Fields are used to perform operations
// on the data blocks during encryption and decryption. 
// AES uses a special kind of Galois Field multiplication, called AES MixColumns operation,
// to mix the columns of the data blocks. This operation provides diffusion and confusion.
// Galois Fields are used to perform mathematical operations on the plaintext and the
// encryption key. AES operates on 128-bit blocks of data, which are represented as
// elements of a Galois Field with 2^8 elements.
// Addition operations in the Galois Field is performed using bitwise XOR, operation that
// returns true if the bits being compared are different, false if they are the same.
// The multiplication operation is performed using a polynomial multiplication algorithm,
// called the Galois Field Multiplication(GFM).
// The GF multiplication is based on the concept of irreducible polynomials, which
// are polynomials that cannot be factored into lower degree polynomials.
// In AES, a specific irreducible polynomial is used to define the Galois Field Multiplication,
// denoted as AES Polynomial and has the form: x^8 + x^4 + x^3 + x + 1.
// By performing addition and multiplication operations in the Galois Field, AES achives
// confusion and diffusion, two essential properties of a secure algorithm.
// Confusion ensures that the relationship between the plaintext and ciphertext is obscured, 
// while diffusion ensures that a change in a single bit affects multiple bits in the ciphertext.
// AES operates on 128 bit blocks of data, these blocks are divided into 4 columns
// and 4 rows, forming a 4*4 matrix. The elements of this matrix are bytes, which
// can be represented as polynomials over GF(2^8).
// In addition to multiplication, AES also utilizes a substitution operation called S-box.
// The S-box is a lookup table that replaces each byte in the 4*4 matrix with a corresponding
// byte from a predefined table.
// AES block cipher operates on 128-bit blocks of data and uses a key of either 128, 192
// or 256 bits. The algorithm consists of several rounds, each rounds performs a series
// of operations on the data and the key, these operations include substitution, permutation
// and linear transformations.
// The substitution step is performed using a substitution box(S-box), that replaces
// each byte of the input with a corresponding byte from a predefined table.
// The S-box is constructed using a combination of mathematical operations, including
// the use of Galois Fields.
// The S-box is designed to have certain cryptographic properties, such as non-linearity
// and resistance to differential and linear attacks. 
// In addition to the S-box, Galois Fields are also used in other parts of AES, such
// as key-expansion, and mix-columns step. The Mix-Columns step involves multiplying
// each column of the data matrix by a fixed matrix, which is constructed using 
// elements from the Galois Field.
// To perform encryption or decryption in AES, the data and key are represented as
// matrices of bytes. Each byte in the matrix is an element of GF(2^8).
// The key-expansion process involves applying various operations on the key, such
// as substitution, permutation, and mixing, which are performed within the Galois Field.
// Substitution is achieved using the SubBytes transformation.
// Permutation is another essential operation, accomplished by ShiftRows and MixColumns
// transformations. The ShiftRow transformation cyclically shifts the bytes in each
// row of the matrix, while the MixColumns transformation performs a matrix
// multiplication on each column. Both of these transformations rely on the properties
// of Galois Fields to achieve diffusion and confusion.
// The MixColumns transformation involves multiplying each column of the matrix by
// a fixed matrix called the Galois Field Matrix.
// The multiplication is performed using an irreducible polynomial.
// The key schedule operation also utilizes Galois Fields. The key-expansion process
// generates a set of round keys from the original key.
// In AES, the data is split into blocks of 128 bits, then a series of mathematical 
// operations including substitutions, permutations and transformations, Galois Fields
// are employed during substitution and transformation steps.
// During substitution, a process called SubBytes transformation is performed, 
// this transformation replaces each byte in the block with a corresponding byte
// from a substitution table known as S-box. 
// The S-box is constructed using a combination of affine transformations and the
// concept of Galois Fields.
// The SubBytes transformation involves two key operations, the multiplicative 
// inverse and the affine transformation.
// The affine transformation is a linear operation that introduces diffusion and 
// non-linearity, it involves applying a matrix multiplication and a bitwise XOR operation
// to the input bytes, the matrix used in the affine transformation is constructed 
// using elements from the Galois Field GF(2^8). 
// Galois Fields are also used in MixColumns transformation, this transformation 
// operates on each column of the block and involves multiplying the column with a 
// fixed matrix. The multiplication operation used in MixColumns is performed using 
// a specific polynomial known as irreducible polynomial, this operation ensures
// that changes in one byte of the block affect multiple bytes in the subsequent rounds.
// The use of Galois Fields allows for the construction of non-linear and diffusion-based
// transformations.
// In the context of AES, a prime field refers to a finite field that is constructed 
// using a prime number as its characteristics, specifically, a prime field is a 
// field whose order is a prime number, in the case of AES, the prime field used 
// is GF(2^8), which is a Galois Field of size 2^8.
// Field operations such as addition and multiplication, play a crucial role in Galois Fields.
// In Galois Fields, addition and multiplication are defined based on specific rules.
// Addition is performed byb adding the coefficients of the polynomials modulo p, 
// this means that if we have two polynomials A(x) and B(x) in GF(p^n), their sum C(x)
// is obtained by adding the coefficients of corresponding terms modulo p.
// For example, in GF(2^8), if "A(x) = x^7 + x^3 + x^2 + 1" and "B(x) = x^5 + x^4 + x^2", 
// their sum C(x) is given by "C(x) = x^7 + x^5 + x^4 + x^3 + x^2 + 1".
// Multiplication in Galois Fields is defined using polynomial multiplication modulo an
// irreducible polynomial of degree n.
// The properties of addition and multiplication in Galois Fields include closure, 
// associativity, commutativity, distributivity and the existence of additive and
// multiplicative identities. Closure ensures that the result of an addition or 
// multiplication operation in the field remains within the field.
// Associativity guarantees that the order of performing multiple additions or multiplications
// does not affect the final result. 
// Commutativity ensures that the order of operands in an addition or multiplication
// operation does not affect the outcome.
// Distributivity allows for the efficient distribution of operations over addition and multiplication.
// The existence of additive and multiplicative identities ensures the presence of neutral elements in the field.
// The MixColumns operation operates on the columns of AES state matrix, which is a
// 4*4 matrix of bytes. Each byte is treated as an element, the MixColumns operation 
// applies a linear transformation to each column individually, resulting in a diffusion of data.
// The linear transformation involves multiplying each byte in a column by a fixed
// polynomial, followed by a reduction step. 
// In the MixColumns operation, the Galois Field multiplication
// is performed using a specific polynomial called the Galois Field Multiplication Polynomial.
// The multiplication is performed by multiplying the byte in the column with the 
// corresponding byte from the Galois Field Multiplication Polynomial, and the 
// reduction step ensures that the result remains within GF(2^8).
// The Galois Field multiplication contributes to the diffusion and confusion in 
// several ways. 
// Firstly, it ensures that every byte in a column is influenced by every other
// byte in that column.
// Secondly, the use Galois Field multiplication introduces non-linearity into
// the MixColumns operation, this non-linearity adds a layer of confusion to the
// process, making it more resistant to various cryptanalytic attacks.
// Each element in GF(2^8) can be represented as an 8-bit binary number, the
// addition operation in GF(2^8) is performed using bitwise XOR, for example, let's
// consider 2 elements in GF(2^8): "A = 10110110" and "B = 01101001", to perform
// the addition A+B , we perform bitwise XOR:
// A    = 10110110
// B    = 01101001
// A+B  = 11011111
// The result, is the sum of A and B in GF(2^8), addition here is commutative, meaning
// that the order of the operands does not affect the result. 
// Subtraction in Galois Fields is performed using bitwise XOR, however, since 
// subtraction is not defined in GF(2^8), it is achieved by performing addition
// with the additive inverse of the second operand.
// The additive inverse of an element A is the element that, when added 
// to A, yields the additive identity element(0).
// For example, let's consider the subtraction A - B, where A = 10110110 and B = 01101001.
// To perform the subtraction, we first find the additive inverse of B, denoted as -B.
// The additive inverse of B is obtained by performing a bitwise XOR with all ones(11111111):
// A  = 10110110
// B  = 01101001
// -B = 01101001 ^ 11111111 = 10010110
// now perform the subtraction by adding A and -B:
// A     = 10110110
// -B    = 10010110
// A - B = 00100000
// The irreducible polynomial plays a fundamental role in the multiplication
// operation in GF(2^8) because it defines the arithmetic rules within the field.
// When multiplying 2 elements in GF(2^8), the irreducible polynomial is used to
// reduce the result to a polynomial of degree less than 8. The reduction is 
// performed using the polynomial division algorithm, where the irreducible 
// polynomial serves as the divisor, this ensures that the multiplication operation
// in GF(2^8) remains within the field and does not overflow.
// Addition and subtraction in GF(2^8) are performed using XOR operations, which
// is equivalent to binary addition without carry, multiplication is performed
// using irreducible polynomials.
// To multiply 2 elements in GF(2^8), we use a multiplication algorithm known as
// the "carry-less multiplication" or "bitwise multiplication" algorithm.
// Let's take two elements in GF(2^8), A and B, represented as binary numbers
// A = a7a6a5a4a3a2a1a0 and B = b7b6b5b4b3b2b1b0. To multiply A and B, we perform the following steps:
// 1. Initialize a result variable, R, to zero.
// 2. For each bit in B, starting from the least significant bit (b0):
// a. If the current bit is 1, XOR R with A.
// b. If the most significant bit of A is 1, left-shift A by one bit and XOR it with the irreducible polynomial, m(x).
// c. Right-shift B by one bit.
// The irreducible polynomial m(x) used in AES is x^8 + x^4 + x^3 + x + 1, which can be represented as 0x1B in
// hexadecimal notation.
// Let's illustrate the multiplication of two elements, A = 10111001 and B = 00011110, in GF(2^8):
// 1. Initialize R = 00000000.
// 2. b0 = 0: No action required.
// 3. b1 = 1: XOR R with A, resulting in R = 10111001.
// a. R = 00000000 XOR 10111001 = 10111001.
// 4. b2 = 1: XOR R with A, resulting in R = 00000001.
// a. R = 10111001 XOR 10111001 = 00000000.
// b. Left-shift A by one bit and XOR with m(x):
// i. A = 01110010 XOR 00011011 = 01101001.
// 5. b3 = 1: XOR R with A, resulting in R = 01101001.
// a. R = 00000000 XOR 01101001 = 01101001.
// 6. b4 = 1: XOR R with A, resulting in R = 01010010.
// a. R = 01101001 XOR 01101001 = 01010010.
// b. Left-shift A by one bit and XOR with m(x):
// i. A = 11010010 XOR 00011011 = 11001001.
// 7. b5 = 0: No action required.
// 8. b6 = 0: No action required.
// 9. b7 = 0: No action required.
// After performing these steps, the final result R is 01010010, which corresponds
// to the product of A and B in GF(2^8).
// Note that multiplication in Galois Field is not commutative, meaning that A * B
// is not equal to B * A.
// The purpose of the SubBytes operation in AES is to provide non-linearity and 
// confusion in the cipher.
// The SubBytes operation involves replacing each byte of the input state matrix
// with a corresponding byte from the S-box, the S-box is constructed using finite
// field arithmetic operations.
// Each byte substitution in the S-box is determined by applying an affine 
// transformation followed by an inversion in the Galois Field GF(2^8).
// The affine transformation involves two steps: a byte-wise substitution and a linear mixing.
// The byte-wise substitution replaces each byte with its multiplicative inverse in GF(2^8),
// except for the byte 0, which is replaced by itself.
// The linear mixing step is achieved by applying a matrix multiplication operation
// using elements from GF(2^8), this operation ehnaces diffusion.
// The MixColumns operation in AES is a column-wise operation that transforms the
// state matrix by multiplying each column with a fixed matrix.
// In MixColumns operation each column of the state matrix is multiplied with a 
// fixed matrix using the Galois Field multiplication. This multiplication provides diffusion and 
// non-linearity to AES, making it resistant to linear and differential cryptanalysis attacks.
// AES consists of several key components, including SubBytes, ShiftRows, MixColumns
// and AddRoundKey operations. These operations are performed in multiple rounds, 
// with the number of rounds determined by the key size, which can be 128, 192 or 256 bits.
// If the key size is 128, it performs 10 rounds, for 192, it performs 12 rounds and for 256 key, 14 rounds.
// During the encryption process, the plaintext is divided into blocks, each block
// undergoes a series of transformations. 
// The SubBytes operation substitutes each byte in the block with a corresponding
// value from a predefined lookup table.
// The ShiftRows operation shifts the bytes in each row of the block, providing diffusion.
// The MixColumns operation applies a matrix multiplication to the columns of the block,
// further enhancing diffusion.
// And the AddRoundKey operation XORs each byte in the block with a round key derived from the main key.
// The decryption process essentially reverses the encryption process, with each operation
// begin inverted.
// One of the primary reasons for the strength of AES is its key length options.
// AES provides a high level of security against side-channel attacks, which are
// attacks that exploit information leaked during encryption process, such as power
// consumption, timing, or electromagnetic radiation.
// AES achieves confidentiality through the use of symmetric encryption, where the
// same key is used for both encryption and decryption.
// AES employs a substitution-permutation network(SPN) structure, which consists
// of multiple rounds of substitution and permutation operations.
// In each round, AES applies a non-linear substitution operation using the S-box.
// Integrity is ensured through the use of a message authentication code(MAC) or
// a cryptographic hash function. A MAC is a cryptographic checksum that is generated
// using a secret key and appended to the data being transmtted.
// During decryption, the data is verified by recomputing the MAC using the same key and comparing it 
// to the received MAC, this ensures that the data has not been tempered with, ensuring integrity.
// AES provides protection against various attacks, including known-plaintext attacks and 
// differential attacks, it achieves this through its key schedule mechanism, which
// generates a set of round keys from the original encryption key, this key-schedule
// operation performs a series of bitwise operations, such as rotations and substitutions to
// generate round keys. This process ensures that even small changes 
// in the original key result in completelly different round keys.
// The key expansion process generates a set of round keys from the original key,
// this process ensures that each round uses a different subkey, the key expansion
// process consists of several steps:
// 1) key expansion initial round: the original encryption key is divided into words, 
// each consisting of four bytesm these words are then used to form the initial round key.
// 2) key expansion subsequent rounds: in each round, a new work is generated based
// on the previous word and a function called the KeyScheduleCore.
// 3) key schedule core: this is a non-linear function that operates on a word, it 
// involves the following steps:
// 3a) RotWord: the bytes of the word are cyclically shifted to the left.
// 3b) SubWord: each byte of the word is replaced with a corresponding byte from the S-box.
// 3c) XOR with Rcon: the leftmost byte of the word is XORed with a round constant, derived from Rijndael finite field.
// 
// After the Expansion process, the encryption process begins. The encryption process 
// consists of several rounds determined by the key size, each round consists of four
// transformation steps applied to the data:
// 1) SubBytes: each byte of the data block is replaced with a corresponding byte from the S-box.
// 2) ShiftRows: the bytes in each row of the data block are shifted cyclically to the left.
// the first row remains unchanged, the second row is shifted by one byte, the third
// row is shifted by 2 bytes, and the fourth row is shifted by 3 bytes.
// This step provides diffusion to the process.
// 3) MixColumns: Each column of the data block is transformed using a matrix multiplication.
// This step enhances diffusion.
// 4) AddRoundKey: the round key for the current round is XORed with the data block, 
// this step adds the current round key to the data, providing confusion.
// The key size in AES refers to the length of the secret key used for encryption and decryption.
// Using 128-bit key, means there are 2^128 possible keys, which is very large number.
// AES operates on a block size of 128-bits and uses a substitution permutation network(SPN) structure.
// The number of rounds affects the diffusion and confusion properties.
// Increasing the number of rounds also increases the complexity of the cipher, which
// means higher security, but it also increases the computational overhead.
// 
 

#define _AES_ENCRYPTION_ALGORITHM_

namespace AES {

};

#include "aes.h"


int main() {
    aes_ctx ctx;
    byte key[32], iv[16];
    byte plaintext[64] = "The quick brown fox";
    byte ciphertext[80], decrypted[80];
    size_t len = strlen((char*)plaintext);
    size_t padded_len = pkcs7_pad(plaintext, len, 16);

    aes_gen_key(key, 32);
    aes_gen_iv(iv, 16);
    aes_init(&ctx, AES256KS);
    aes_key_expansion(&ctx, key);

    // CBC Encrypt/Decrypt example
    aes_cbc_encrypt(&ctx, plaintext, ciphertext, padded_len, iv);
    aes_cbc_decrypt(&ctx, ciphertext, decrypted, padded_len, iv);
    size_t unpad_len = pkcs7_unpad(decrypted, padded_len);

    decrypted[unpad_len] = 0;
    printf("Decrypted: %s\n", decrypted);
    return 0;
}

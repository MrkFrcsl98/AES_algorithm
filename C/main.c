#include <stdio.h>
#include <string.h>
#include "aes.h"

void print_hex(const char* label, const byte* data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; ++i) printf("%02X", data[i]);
    printf("\n");
}

int main() {
    // Example key and IV/nonce
    byte key[16]  = {0};
    byte iv[16]   = {0};
    byte nonce[16]= {0};
    const char* plaintext = "AES Demo Example in All Modes!";
    size_t pt_len = strlen(plaintext);
    size_t padded_len = pt_len + AES_BLOCK_SIZE; // For padding

    // Prepare input buffer (with padding)
    byte input[64]  = {0};
    byte output[64] = {0};
    byte result[64] = {0};
    memcpy(input, plaintext, pt_len);

    // Key and IV
    aes_gen_key(key, sizeof(key));
    aes_gen_iv(iv, sizeof(iv));
    memcpy(nonce, iv, sizeof(iv)); // Use iv as nonce for demo

    // Set up AES context
    aes_ctx ctx;
    aes_init(&ctx, AES128KS);
    aes_key_expansion(&ctx, key);

    // ECB MODE
    size_t plen = pkcs7_pad(input, pt_len, AES_BLOCK_SIZE);
    aes_ecb_encrypt(&ctx, input, output, plen);
    print_hex("ECB Encrypted: ", output, plen);
    aes_ecb_decrypt(&ctx, output, result, plen);
    size_t dec_len = pkcs7_unpad(result, plen);
    printf("ECB Decrypted: %.*s\n\n", (int)dec_len, result);

    // CBC MODE
    memset(output, 0, sizeof(output)); memset(result, 0, sizeof(result));
    byte iv_cbc[16]; memcpy(iv_cbc, iv, 16);
    plen = pkcs7_pad(input, pt_len, AES_BLOCK_SIZE);
    aes_cbc_encrypt(&ctx, input, output, plen, iv_cbc);
    print_hex("CBC Encrypted: ", output, plen);
    memcpy(iv_cbc, iv, 16);
    aes_cbc_decrypt(&ctx, output, result, plen, iv_cbc);
    dec_len = pkcs7_unpad(result, plen);
    printf("CBC Decrypted: %.*s\n\n", (int)dec_len, result);

    // CFB MODE
    memset(output, 0, sizeof(output)); memset(result, 0, sizeof(result));
    byte iv_cfb[16]; memcpy(iv_cfb, iv, 16);
    aes_cfb_encrypt(&ctx, (byte*)plaintext, output, pt_len, iv_cfb);
    print_hex("CFB Encrypted: ", output, pt_len);
    memcpy(iv_cfb, iv, 16);
    aes_cfb_decrypt(&ctx, output, result, pt_len, iv_cfb);
    printf("CFB Decrypted: %.*s\n\n", (int)pt_len, result);

    // OFB MODE
    memset(output, 0, sizeof(output)); memset(result, 0, sizeof(result));
    byte iv_ofb[16]; memcpy(iv_ofb, iv, 16);
    aes_ofb_encrypt(&ctx, (byte*)plaintext, output, pt_len, iv_ofb);
    print_hex("OFB Encrypted: ", output, pt_len);
    memcpy(iv_ofb, iv, 16);
    aes_ofb_encrypt(&ctx, output, result, pt_len, iv_ofb); // OFB encrypt == decrypt
    printf("OFB Decrypted: %.*s\n\n", (int)pt_len, result);

    // CTR MODE
    memset(output, 0, sizeof(output)); memset(result, 0, sizeof(result));
    byte nonce_ctr[16]; memcpy(nonce_ctr, nonce, 16);
    aes_ctr_encrypt(&ctx, (byte*)plaintext, output, pt_len, nonce_ctr);
    print_hex("CTR Encrypted: ", output, pt_len);
    memcpy(nonce_ctr, nonce, 16);
    aes_ctr_encrypt(&ctx, output, result, pt_len, nonce_ctr); // CTR encrypt == decrypt
    printf("CTR Decrypted: %.*s\n\n", (int)pt_len, result);

    return 0;
}

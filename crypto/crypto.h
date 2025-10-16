#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define MAX_MSG_LEN 1024

int load_key_iv(const char* key_path, const char* iv_path, unsigned char* key, unsigned char* iv);
int encrypt_message(const unsigned char* plaintext, int plaintext_len,
                    const unsigned char* key, const unsigned char* iv,
                    unsigned char* ciphertext);
int decrypt_message(const unsigned char* ciphertext, int ciphertext_len,
                    const unsigned char* key, const unsigned char* iv,
                    unsigned char* plaintext);
#endif

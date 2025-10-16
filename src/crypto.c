#include "../crypto/crypto.h"

int load_key_iv(const char* key_path, const char* iv_path, unsigned char* key, unsigned char* iv) {
    FILE* key_file = fopen(key_path, "rb");
    if (!key_file) return -1;
    if (fread(key, 1, AES_KEY_SIZE, key_file) != AES_KEY_SIZE) {
        fclose(key_file);
        return -1;
    }
    fclose(key_file);

    FILE* iv_file = fopen(iv_path, "rb");
    if (!iv_file) return -1;
    if (fread(iv, 1, AES_BLOCK_SIZE, iv_file) != AES_BLOCK_SIZE) {
        fclose(iv_file);
        return -1;
    }
    fclose(iv_file);
    return 0;
}

int encrypt_message(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext) {
    
     // todo : random IV
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto fail;
    int len, ciphertext_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) goto fail;
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) goto fail;
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int decrypt_message(const unsigned char* ciphertext, int ciphertext_len,
                    const unsigned char* key, const unsigned char* iv,
                    unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto fail;
    int len, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) goto fail;
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) goto fail;
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

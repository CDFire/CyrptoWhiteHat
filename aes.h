#ifndef CSCI4230_AES
#define CSCI4230_AES

void Encrypt(const unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key);

void Decrypt(const unsigned char* ciphertext, unsigned char* decryptedText, unsigned char* key);

#endif
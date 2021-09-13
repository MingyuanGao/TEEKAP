#pragma once

/* EVP encryption
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
using byte = unsigned char;
using bytes = std::vector<byte>;
using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE]);
void aes_encrypt(
  const byte key[KEY_SIZE],
  const byte iv[BLOCK_SIZE],
  const bytes& ptext,
  bytes& ctext);
void aes_decrypt(
  const byte key[KEY_SIZE],
  const byte iv[BLOCK_SIZE],
  const bytes& ctext,
  bytes& rtext);


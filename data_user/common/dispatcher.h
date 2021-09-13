// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once
#include <openenclave/enclave.h>
#include <string>
#include "attestation.h"
#include "crypto.h"

extern "C" {
#include "../sss/sss.h"
}

using namespace std;

typedef struct _enclave_config_data
{
    uint8_t* enclave_secret_data;
    const char* other_enclave_public_key_pem;
    size_t other_enclave_public_key_pem_size;
} enclave_config_data_t;


#define ENCRYPTION_KEY_SIZE 256     // AES256-CBC encryption algorithm
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)
class ecall_dispatcher
{
  private:
    bool m_initialized;
    Crypto* m_crypto;
    Attestation* m_attestation;
    string m_name;
    enclave_config_data_t* m_enclave_config;
    unsigned char m_other_enclave_signer_id[32];
	
	// enclave-to-enclave traffic key (AES, 256-bit)
    unsigned char password_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; 
	int generate_enclave_to_enclave_traffic_key(string password);
	
	// data capsule ciphertext
	uint8_t* data_capsule_buffer;
	size_t  data_capsule_buffer_size;
	// decryption key
	unsigned char restored[sss_MLEN];


  public:
    ecall_dispatcher(const char* name, enclave_config_data_t* enclave_config);
    ~ecall_dispatcher();
	
	
    int get_enclave_format_settings(
        const oe_uuid_t* format_id,
        uint8_t** format_settings,
        size_t* format_settings_size);

    int get_evidence_with_public_key(
        const oe_uuid_t* format_id,
        uint8_t* format_settings,
        size_t format_settings_size,
        uint8_t** pem_key,
        size_t* pem_key_size,
        uint8_t** evidence_buffer,
        size_t* evidence_buffer_size);
    int verify_evidence_and_set_public_key(
        const oe_uuid_t* format_id,
        uint8_t* pem_key,
        size_t pem_key_size,
        uint8_t* evidence,
        size_t evidence_size);

    int generate_encrypted_message(uint8_t** data, size_t* size);

    int process_encrypted_message(
        uint8_t* encrypted_data,
        size_t encrypted_data_size);
	
	int encrypt_message_aes(uint8_t* ptext, size_t ptext_size, uint8_t** ctext, size_t* ctext_size);

	int decrypt_message_aes(uint8_t* ctext, size_t ctext_size, uint8_t** ptext, size_t* ptext_size);

	int load_data_capsule(
        uint8_t* encrypted_data,
        size_t encrypted_data_size);

	int reconstruct_decryption_key(size_t num_of_shares, uint8_t* shares, size_t shares_size );
	
	int consume_data();

  private:
    bool initialize(const char* name);
};

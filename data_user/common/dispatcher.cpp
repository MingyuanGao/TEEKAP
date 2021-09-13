// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>

#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>

#include <mbedtls/aes.h>

static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
using byte = unsigned char;
using bytes = std::vector<byte>;

std::string uint8_to_hex_string(const uint8_t *v, const size_t s);


ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(nullptr), m_attestation(nullptr)
{
    m_enclave_config = enclave_config;
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == nullptr)
    {
        goto exit;
    }

    {
        size_t other_enclave_signer_id_size = sizeof(m_other_enclave_signer_id);
        // TODO: the following call is not TEE-agnostic.
        if (oe_sgx_get_signer_id_from_public_key(
                m_enclave_config->other_enclave_public_key_pem,
                m_enclave_config->other_enclave_public_key_pem_size,
                m_other_enclave_signer_id,
                &other_enclave_signer_id_size) != OE_OK)
        {
            goto exit;
        }
    }

    m_attestation = new Attestation(m_crypto, m_other_enclave_signer_id);
    if (m_attestation == nullptr)
    {
        goto exit;
    }
    ret = true;

exit:
    return ret;
}

int ecall_dispatcher::get_enclave_format_settings(
    const oe_uuid_t* format_id,
    uint8_t** format_settings_buffer,
    size_t* format_settings_buffer_size)
{
    uint8_t* format_settings = nullptr;
    size_t format_settings_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    // Generate a format settings so that the enclave that receives this format
    // settings can attest this enclave.
    TRACE_ENCLAVE("get_enclave_format_settings");
    if (m_attestation->get_format_settings(
            format_id, &format_settings, &format_settings_size) == false)
    {
        TRACE_ENCLAVE("get_enclave_format_settings failed");
        goto exit;
    }

    if (format_settings && format_settings_size)
    {
        // Allocate memory on the host and copy the format settings over.
        // TODO: the following code is not TEE-agnostic, as it assumes the
        // enclave can directly write into host memory
        *format_settings_buffer =
            (uint8_t*)oe_host_malloc(format_settings_size);
        if (*format_settings_buffer == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("copying format_settings failed, out of memory");
            goto exit;
        }
        memcpy(*format_settings_buffer, format_settings, format_settings_size);
        *format_settings_buffer_size = format_settings_size;
        oe_verifier_free_format_settings(format_settings);
    }
    else
    {
        *format_settings_buffer = nullptr;
        *format_settings_buffer_size = 0;
    }
    ret = 0;

exit:

    if (ret != 0)
        TRACE_ENCLAVE("get_enclave_format_settings failed.");
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's
 * evidence. The enclave that receives the key will use the evidence to
 * attest this enclave.
 */
int ecall_dispatcher::get_evidence_with_public_key(
    const oe_uuid_t* format_id,
    uint8_t* format_settings,
    size_t format_settings_size,
    uint8_t** pem_key,
    size_t* pem_key_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size)
{
    uint8_t pem_public_key[512];
    uint8_t* evidence = nullptr;
    size_t evidence_size = 0;
    uint8_t* key_buffer = nullptr;
    int ret = 1;

    TRACE_ENCLAVE("get_evidence_with_public_key");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate evidence for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_attestation_evidence(
            format_id,
            format_settings,
            format_settings_size,
            pem_public_key,
            sizeof(pem_public_key),
            &evidence,
            &evidence_size) == false)
    {
        TRACE_ENCLAVE("get_evidence_with_public_key failed");
        goto exit;
    }

    // Allocate memory on the host and copy the evidence over.
    // TODO: the following code is not TEE-agnostic, as it assumes the
    // enclave can directly write into host memory
    *evidence_buffer = (uint8_t*)oe_host_malloc(evidence_size);
    if (*evidence_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying evidence_buffer failed, out of memory");
        goto exit;
    }
    memcpy(*evidence_buffer, evidence, evidence_size);
    *evidence_buffer_size = evidence_size;
    oe_free_evidence(evidence);

    key_buffer = (uint8_t*)oe_host_malloc(512);
    if (key_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying key_buffer failed, out of memory");
        goto exit;
    }
    memcpy(key_buffer, pem_public_key, sizeof(pem_public_key));

    *pem_key = key_buffer;
    *pem_key_size = sizeof(pem_public_key);

    ret = 0;
    TRACE_ENCLAVE("get_evidence_with_public_key succeeded");

exit:
    if (ret != 0)
    {
        if (evidence)
            oe_free_evidence(evidence);
        if (key_buffer)
            oe_host_free(key_buffer);
        if (*evidence_buffer)
            oe_host_free(*evidence_buffer);
    }
    return ret;
}

int ecall_dispatcher::verify_evidence_and_set_public_key(
    const oe_uuid_t* format_id,
    uint8_t* pem_key,
    size_t pem_key_size,
    uint8_t* evidence,
    size_t evidence_size)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the evidence and accompanying key.
    if (m_attestation->attest_attestation_evidence(
            format_id, evidence, evidence_size, pem_key, pem_key_size) == false)
    {
        TRACE_ENCLAVE("verify_evidence_and_set_public_key failed.");
        goto exit;
    }

    memcpy(m_crypto->get_the_other_enclave_public_key(), pem_key, pem_key_size);

    ret = 0;
    TRACE_ENCLAVE("verify_evidence_and_set_public_key succeeded.");

exit:
    return ret;
}

int ecall_dispatcher::generate_encrypted_message(uint8_t** data, size_t* size)
{
    uint8_t encrypted_data_buffer[1024];
    size_t encrypted_data_size;
    uint8_t* host_buffer;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    encrypted_data_size = sizeof(encrypted_data_buffer);
    if (m_crypto->Encrypt(
            m_crypto->get_the_other_enclave_public_key(),
            m_enclave_config->enclave_secret_data,
            ENCLAVE_SECRET_DATA_SIZE,
            encrypted_data_buffer,
            &encrypted_data_size) == false)
    {
        TRACE_ENCLAVE("enclave: generate_encrypted_message failed");
        goto exit;
    }

    // TODO: the following code is not TEE-agnostic, as it assumes the
    // enclave can directly write into host memory
    host_buffer = (uint8_t*)oe_host_malloc(encrypted_data_size);
    if (host_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying host_buffer failed, out of memory");
        goto exit;
    }
    memcpy(host_buffer, encrypted_data_buffer, encrypted_data_size);
    TRACE_ENCLAVE(
        "enclave: generate_encrypted_message: encrypted_data_size = %ld",
        encrypted_data_size);
    *data = host_buffer;
    *size = encrypted_data_size;

    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::process_encrypted_message(
    uint8_t* encrypted_data,
    size_t encrypted_data_size)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    data_size = sizeof(data);
    if (m_crypto->decrypt(
            encrypted_data, encrypted_data_size, data, &data_size))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_enclave_config->enclave_secret_data.
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        TRACE_ENCLAVE("Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            printf("%d ", data[i]);
            if (m_enclave_config->enclave_secret_data[i] != data[i])
            {
                printf(
                    "Expecting [0x%x] but received unexpected value "
                    "[0x%x]\n ",
                    m_enclave_config->enclave_secret_data[i],
                    data[i]);
                ret = 1;
                break;
            }
        }
        printf("\n");
    }
    else
    {
        TRACE_ENCLAVE("Encalve:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    TRACE_ENCLAVE("Decrypted data matches with the enclave internal secret "
                  "data: descryption validation succeeded");
    ret = 0;
exit:
    return ret;
}

// Load data capsule file into enclave
int ecall_dispatcher::load_data_capsule(
    uint8_t* encrypted_data,
    size_t encrypted_data_size)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }
	
	data_capsule_buffer = (uint8_t*)oe_malloc(encrypted_data_size);
	if(data_capsule_buffer == nullptr)
	{
        TRACE_ENCLAVE("DataUserEncalve: Failed to load data capsule into enclave!");
        goto exit;
    }
	
	memcpy(data_capsule_buffer, encrypted_data, encrypted_data_size);
	
	TRACE_ENCLAVE("\nDataUserEnclave: Loaded data capsule into enclave!");
    ret = 0;
exit:
    return ret;
}


// Reconstruct decryption key
int ecall_dispatcher::reconstruct_decryption_key(size_t num_of_shares, uint8_t* shares, size_t shares_size)
{
    int ret = 1;
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        return ret;
    }


    int n = num_of_shares;
    int k = n/2 + 1;

	sss_Share key_shares[n]; // typedef uint8_t sss_Share[sss_SHARE_LEN]
	for(int i = 0; i < n; i++)	{
		for(int j = 0; j < sss_SHARE_LEN; j++) {
			key_shares[i][j] = shares[i*sss_SHARE_LEN+j];
		}
	}
    
	// Combine some of the shares to restore the original secret
	// unsigned char restored[sss_MLEN];
    int tmp = sss_combine_shares(restored, key_shares, k);
    assert(tmp == 0);
    if(tmp==0) {
        TRACE_ENCLAVE("\nDataUserEnclave: Reconstructing decryption key succeeded!");
    }  
	
	//std::string key_hex = uint8_to_hex_string(restored, sss_MLEN);
    //printf("DataUserEnclave: key (hex) = \n %s \n", key_hex.c_str());

	ret = 0;
	return ret;
}


// Consume data
int ecall_dispatcher::consume_data() {
    TRACE_ENCLAVE("\nDataUserEnclave: Decrypting the data capsule ...\n");
	
	byte key[KEY_SIZE];
	memcpy(key, restored, KEY_SIZE);
	
	// TODO: write the mbedtls equivalent of aes_decrypt() 
//	byte iv[BLOCK_SIZE];	
//	memcpy(&iv[0], &data_capsule_buffer[0], BLOCK_SIZE);
//	
//	size_t data_size = data_capsule_buffer_size - BLOCK_SIZE;
//	bytes ctext(data_size);
//	memcpy((byte*)&ctext[0], &data_capsule_buffer[BLOCK_SIZE], data_size);
//  
//	bytes rtext;
//	//aes_decrypt(key,iv,ctext,rtext);
//	
//	mbedtls_aes_context aes;
//	mbedtls_aes_setkey_dec( &aes, key, KEY_SIZE);
//	mbedtls_aes_crypt_cbc( &aes,
//		MBEDTLS_AES_DECRYPT,
//        data_size,           // input data length in bytes,
//        iv, // Initialization vector (updated after use)
//        &ctext[0],
//        &rtext[0]);
	
    TRACE_ENCLAVE("\nDataUserEnclave: Decrypted the data capsule!\n");
    TRACE_ENCLAVE("\nDataUserEnclave: Consuming the data ...\n");
    TRACE_ENCLAVE("\nDataUserEnclave: Done!\n");

	return 0;
}


std::string uint8_to_hex_string(const uint8_t *v, const size_t s) {
   std::stringstream ss;
 
   ss << std::hex << std::setfill('0');
 
   for (int i = 0; i < s; i++) {
     ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
   }
 
   return ss.str();
 }


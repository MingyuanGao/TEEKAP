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
#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>


static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
using byte = unsigned char;

std::string uint8_to_hex_string(const uint8_t *v, const size_t s);
std::vector<uint8_t> hex_string_to_uint8_vec(const string& hex);

int generate_enclave_to_enclave_traffic_key(string password);

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
	string my_password;
    string key_hex_str;
    std::vector<uint8_t> key_vec;
    
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
	
	/* Generate an enclave-to-enclave traffic key
	 * This key should be generated from a shared secret in both enclaves, resulting in 
	 * the same encryption key.
	 *
	 * Alternatively, this key is to be received from the remote enclave securely
	 * if communication is not a bottleneck. 
	 */
	//string my_password("JuryEnclave.signed");
	//my_password = "JuryEnclave.signed";
	//generate_enclave_to_enclave_traffic_key(my_password);

	// For now, we simply hardcode a fixed key in both enclaves
    key_hex_str = "90c530604134663d3f58c4a39a21c07e82498d0131522cccdf5ac8b2f9288f0a";
    key_vec = hex_string_to_uint8_vec(key_hex_str);
    memcpy(&password_key[0], &key_vec[0], key_vec.size());

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


// TODO: use a proper aes_encryption_header_t to reduce duplicated code 
//       Design a good padding scheme
int ecall_dispatcher::encrypt_message_aes(uint8_t* ptext, size_t ptext_size, uint8_t** ctext, size_t* ctext_size) {
    string ptext_hex_str = uint8_to_hex_string(ptext, ptext_size);
	string password_key_hex_str = uint8_to_hex_string(password_key, sizeof(password_key) );
 	string iv_hex_str;
	string ctext_hex_str;
	TRACE_ENCLAVE("encrypt_message_aes: ptext (hex) = %s", ptext_hex_str.c_str() );
    TRACE_ENCLAVE("encrypt_message_aes: AES key (hex) = %s", password_key_hex_str.c_str());


	uint8_t* ptext_buffer;
	uint8_t* ctext_buffer;
	uint8_t* host_buffer;
	int remainder;

	int ret = 1;
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }
	
	remainder = ptext_size % BLOCK_SIZE;
	if( remainder == 0 ) {
		ptext_buffer = (uint8_t*)oe_malloc(ptext_size);
		ctext_buffer = (uint8_t*)oe_malloc(ptext_size);
	} else {
		ptext_buffer = (uint8_t*)oe_malloc(ptext_size + BLOCK_SIZE);
		ctext_buffer = (uint8_t*)oe_malloc(ptext_size + BLOCK_SIZE);
	}
	if (ptext_buffer == nullptr || ctext_buffer == nullptr )
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("allocating ptext_buffer or ctext_buffer failed, out of memory");
        goto exit;
    }
	memcpy(&ptext_buffer[0], &ptext[0], ptext_size);


	host_buffer = (uint8_t*)oe_host_malloc(ptext_size+BLOCK_SIZE); // + iv_size
    if (host_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("allocating host_buffer failed, out of memory");
        goto exit;
    }


	byte iv[BLOCK_SIZE];	
	// TODO: generate random bytes into iv
    memcpy(&host_buffer[0], &iv[0], BLOCK_SIZE);
	iv_hex_str = uint8_to_hex_string(iv, sizeof(iv) );
    TRACE_ENCLAVE("encrypt_message_aes: iv (hex) = %s", iv_hex_str.c_str());

	
	mbedtls_aes_context aes;
	mbedtls_aes_setkey_enc( &aes, password_key, KEY_SIZE*8); // key size is 256 bits
	
	if(remainder == 0) {
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT,
        	ptext_size, // input data length in bytes,
        	iv,         // Initialization vector (updated after use)
        	&ptext_buffer[0],  // input  
			&ctext_buffer[0] ); // output
	} else {
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT,
        	ptext_size+BLOCK_SIZE, // input data length in bytes,
        	iv,         // Initialization vector (updated after use)
        	&ptext_buffer[0],  // input  
			&ctext_buffer[0] ); // output
	}

	
	memcpy(&host_buffer[BLOCK_SIZE], &ctext_buffer[0], ptext_size);
	*ctext = host_buffer;
    *ctext_size = ptext_size + BLOCK_SIZE; // ptext_size + iv_size
	
	ctext_hex_str = uint8_to_hex_string(host_buffer, ptext_size+BLOCK_SIZE);
	TRACE_ENCLAVE("encrypt_message_aes: ctext_size = %ld", ptext_size + BLOCK_SIZE);
	TRACE_ENCLAVE("encrypt_message_aes: ctext = %s \n", ctext_hex_str.c_str() );
 
    ret = 0;
exit:
    return ret;					
}


// For testing only
int ecall_dispatcher::decrypt_message_aes(uint8_t* ctext, size_t ctext_size, uint8_t** ptext, size_t* ptext_size) {
    string ctext_hex_str = uint8_to_hex_string(ctext, ctext_size);
	string password_key_hex_str = uint8_to_hex_string(password_key, sizeof(password_key) );
 	string iv_hex_str;
	string ptext_hex_str;
	TRACE_ENCLAVE("encrypt_message_aes: ctext (hex) = %s", ctext_hex_str.c_str() );
    TRACE_ENCLAVE("encrypt_message_aes: AES key (hex) = %s", password_key_hex_str.c_str());


	uint8_t* ctext_buffer;
	uint8_t* ptext_buffer;
	uint8_t* host_buffer;
	int remainder;

	int ret = 1;
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

	
	byte iv[BLOCK_SIZE];	
	memcpy(&iv[0], &ctext[0], BLOCK_SIZE);
	iv_hex_str = uint8_to_hex_string(iv, sizeof(iv) );
    TRACE_ENCLAVE("decrypt_message_aes: iv (hex) = %s", iv_hex_str.c_str());

	
	ctext_buffer = (uint8_t*)oe_malloc(ctext_size); // ctext_size - iv_size + (possible) BLOCK_SIZE
    if (ctext_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("allocating ctext_buffer failed, out of memory");
        goto exit;
    }
	remainder = (ctext_size - BLOCK_SIZE) % BLOCK_SIZE;
	if(remainder == 0) {
		memcpy(&ctext_buffer[0], &ctext[BLOCK_SIZE], ctext_size - BLOCK_SIZE);
	} else {
		memcpy(&ctext_buffer[0], &ctext[BLOCK_SIZE], ctext_size);
	}


	ptext_buffer = (uint8_t*)oe_malloc(ctext_size - BLOCK_SIZE); // - iv_size
    if (ptext_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("allocating ptext_buffer failed, out of memory");
        goto exit;
    }
	
	host_buffer = (uint8_t*)oe_host_malloc(ctext_size - BLOCK_SIZE); // -iv_size
    if (host_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("allocating host_buffer failed, out of memory");
        goto exit;
    }
	

	mbedtls_aes_context aes;
	mbedtls_aes_setkey_dec( &aes, password_key, KEY_SIZE*8); // key size is 256 bits
	if(remainder == 0) {
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT,
    	    ctext_size - BLOCK_SIZE, // input data length in bytes,
    	    iv,                  // Initialization vector (updated after use)
    	    &ctext_buffer[0], 
			&ptext_buffer[0]);
	} else {
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT,
    	    ctext_size, // input data length in bytes, i.e., ctext_size - BLOCK_SIZE + BLOCK_SIZE 
    	    iv,                  // Initialization vector (updated after use)
    	    &ctext_buffer[0], 
			&ptext_buffer[0]);
	}

	
	memcpy(&host_buffer[0], &ptext_buffer[0], ctext_size - BLOCK_SIZE);
 	
	ptext_hex_str = uint8_to_hex_string(ptext_buffer, ctext_size-BLOCK_SIZE);
	TRACE_ENCLAVE("decrypt_message_aes: ptext_size = %ld", ctext_size - BLOCK_SIZE );
	TRACE_ENCLAVE("decrypt_message_aes: ptext = %s", ptext_hex_str.c_str() );
   
	*ptext = host_buffer;
    *ptext_size = ctext_size - BLOCK_SIZE;
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
	data_capsule_buffer_size = encrypted_data_size;

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
	memcpy(&key[0], restored, KEY_SIZE);
	
	byte iv[BLOCK_SIZE];	
	memcpy(&iv[0], &data_capsule_buffer[0], BLOCK_SIZE);
	
	size_t data_size = data_capsule_buffer_size - BLOCK_SIZE;
	byte ctext[data_size];
	memcpy(&ctext[0], &data_capsule_buffer[BLOCK_SIZE], data_size);

	byte rtext[data_size];

	mbedtls_aes_context aes;
	mbedtls_aes_setkey_dec( &aes, key, KEY_SIZE*8); // key size is 256 bits
	mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT,
        data_size,           // input data length in bytes,
        iv, // Initialization vector (updated after use)
        ctext, 
		rtext);

	TRACE_ENCLAVE("\nDataUserEnclave: Decrypted the data capsule!\n");

    TRACE_ENCLAVE("\nDataUserEnclave: Secret data is : (for demo only) \n--------------------------------------------------\n");
	
	for(int i = 0; i < data_size; i++) {
		printf("%c", (char)rtext[i]);
	}
    
    TRACE_ENCLAVE("\nDataUserEnclave: Consuming the data ...\n");
   	// Data-conuming code goes here	
	// ...	

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


#define HASH_VALUE_SIZE_IN_BYTES 32 // sha256 hashing algorithm
#define ENCRYPTION_KEY_SIZE 256     // AES256-CBC encryption algorithm
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)
#define IV_SIZE 16 // determined by AES256-CBC
#define SALT_SIZE_IN_BYTES IV_SIZE

// This routine uses the mbed_tls library to derive an AES key from the input
// password, producing a password-based key.
// NOTE: This key is used as the enclave-to-enclave traffice key
int generate_password_key(const char* password, unsigned char* salt, unsigned char* key, unsigned int key_size)
{
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t* info_sha;
    int ret = 0;
    mbedtls_md_init(&sha_ctx);

    TRACE_ENCLAVE("generate_password_key");

    memset(key, 0, key_size);
    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == nullptr)
    {
        ret = 1;
        goto exit;
    }

    // setting up hash algorithm context
    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_md_setup() failed with -0x%04x", -ret);
        goto exit;
    }

    // Derive a key from a password using PBKDF2.
    // PBKDF2 (Password-Based Key Derivation Function 2) are key derivation
    // functions with a sliding computational cost, aimed to reduce the
    // vulnerability of encrypted keys to brute force attacks. See
    // (https://en.wikipedia.org/wiki/PBKDF2) for more details.
    ret = mbedtls_pkcs5_pbkdf2_hmac(
        &sha_ctx,                       // Generic HMAC context
        (const unsigned char*)password, // Password to use when generating key
        strlen((const char*)password),  // Length of password
        salt,                           // salt to use when generating key
        SALT_SIZE_IN_BYTES,             // size of salt
        100000,                         // iteration count
        key_size,                       // length of generated key in bytes
        key);                           // generated key
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_pkcs5_pbkdf2_hmac failed with -0x%04x", -ret);
        goto exit;
    }
    TRACE_ENCLAVE("Key based on password successfully generated");
exit:
    mbedtls_md_free(&sha_ctx);
    return ret;
}


int ecall_dispatcher::generate_enclave_to_enclave_traffic_key(string password)
{
    int ret = 0;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES]; // sha256 digest of password
    // This varaible was moved to global variable
	//unsigned char password_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; // password generated key
    unsigned char salt[SALT_SIZE_IN_BYTES];
    const char seed[] = "JuryEnclaveDH-KeyExchange";
 	std::string password_key_hex ;

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    
    mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

    // Initialize CTR-DRBG seed
    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char*)seed,
        strlen(seed));
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_seed() failed with -0x%04x", -ret);
        goto exit;
    }

    // Generate random salt
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, sizeof(salt));
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_random() failed with -0x%04x", -ret);
        goto exit;
    }

    TRACE_ENCLAVE("generate_enclave_to_enclave_traffic_key");
    
	// derive a key from the password using PBDKF2
    ret = generate_password_key(password.c_str(), salt, password_key, sizeof(password_key));
    if (ret != 0)
    {
       TRACE_ENCLAVE("generate_enclave_to_enclave_traffic_key failed!");
       goto exit;
    }
    
 	password_key_hex = uint8_to_hex_string(password_key, sizeof(password_key) );
    TRACE_ENCLAVE("enclave-to-enclave traffic key (hex): %s", password_key_hex.c_str());

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

std::vector<uint8_t> hex_string_to_uint8_vec(const string& hex) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

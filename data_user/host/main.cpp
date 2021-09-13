#include <string>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <future>
#include <iomanip>
#include <chrono>
using namespace std::chrono;
using namespace std::literals::chrono_literals;
using std::cout;
using std::cin;
using std::cerr;
using std::endl;
using std::string;

#include <boost/asio.hpp>
using namespace boost::asio;

#include "../../include/protocol.h"
#include "../api.h"
#include "../evp_encryption.h"

extern "C" {
#include "../../sss/sss.h"
}

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>
#include <stdio.h>
#include "datauser_u.h"


std::vector<std::string> split(std::string strToSplit, char delimeter);
std::string uint8_to_hex_string(const uint8_t *v, const size_t s);
std::vector<uint8_t> hex_string_to_uint8_vec(const string& hex);

string thread_func_request_key_share_token(string node_ip, int http_port, string dc_id);

template <class Container>
void read_bytes(std::ifstream& file, Container& vec)
{
  if (!file.read(reinterpret_cast<char*>(&vec[0]), vec.size()))
  {
    std::abort();
  }
}


// SGX Local Attestation UUID.
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_datauser_enclave(
        enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_attestation_enclave failed. %s", oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}


int main(int argc, char* argv[]) {
 	if (argc != 6) {
    	cerr << "Usage: " << argv[0] << " enclave_path access_committee_leader_ip http_port data_capsule_id data_capsule_file" << endl;
    	return 0;
  	}
	
	char*  enclave_path = argv[1];
	string access_committee_leader_ip = argv[2];
	int access_committee_leader_port = std::stoi(argv[3]);
	string data_capsule_id   = argv[4];
	string data_capsule_file = argv[5];
	cout << "\nArguments provided: \n"
		 << "enclave_path = " << enclave_path << "\n" 
		 << "access_committee_leader_ip = "   << access_committee_leader_ip << "\n" 
		 << "access_committee_leader_port = " << access_committee_leader_port << "\n" 
		 << "data_capsule_id   = " << data_capsule_id << "\n"
		 << "data_capsule_file = " << data_capsule_file << endl << endl;


	/* NOTE:
	 * During enclave initialization, a public-private key pair is generated 
	 * uniformly at random.
	 *
	 * The public key's hash is embedded in the attestation report, which can be verfied 
	 * during the remote attestation to JURY.
	 *
	 * JURY uses this public key to establish a secure and authenticated communication 
	 * channel to this enclave.
	 */
	cout << "\n==== Host: Creating *DataRequesterEnclave* ..." << endl;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
	oe_enclave_t* enclave_a = NULL;
    enclave_a = create_enclave(enclave_path, flags);
    if (enclave_a == NULL)
    {
		cout << "Host: Failed to create enclave!" << endl;
		return 1;
    }
	#ifdef __linux__
    // verify if SGX_AESM_ADDR is successfully set
    if (getenv("SGX_AESM_ADDR"))
    {
        cout << "Host: environment variable SGX_AESM_ADDR is set" << endl;
    }
    else
    {
        cout << "Host: environment variable SGX_AESM_ADDR is not set" << endl;
    }
	#endif
		
	/* 
	 * Generate remote attestation report for Access Committee 
	 */
	// Requesting *JuryEnclave* format settings ...
	oe_result_t result = OE_OK;
    int ret = 1;
    oe_uuid_t* format_id = &sgx_remote_uuid;
    uint8_t* format_settings = NULL;
    size_t format_settings_size = 0;
	result = get_enclave_format_settings(
        enclave_a,
        &ret,
        format_id,
        &format_settings,
        &format_settings_size);
    if ((result != OE_OK) || (ret != 0)) {
        printf("Host: get_format_settings failed. %s\n", oe_result_str(result));
		return 1;
	}
	// convert format_settings (uint8_t*) to hex string
//	string format_settings_hex_str = uint8_to_hex_string(format_settings, format_settings_size); 
//	cout << "DataRequsterEnclave's format_settings: \n" << format_settings_hex_str <<  "\n"
//		 << "Size: " << format_settings_hex_str.size() << endl;

	cout << "\n==== Host: Requesting *DataRequesterEnclave* to generate an *enclave evidence* with public key ..." << endl;
	uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    result = get_evidence_with_public_key(
        enclave_a,
        &ret,
        format_id,
        format_settings,
		format_settings_size,
        &pem_key,
        &pem_key_size,
        &evidence,
        &evidence_size);
    if ((result != OE_OK) || (ret != 0)) {
        printf("Host: get_evidence_with_public_key failed. %s\n", oe_result_str(result));
		
		free(pem_key);
		free(evidence);
		free(format_settings);
		
		return 1;
    }
    printf("Host: DataRequesterEnclave's public key (generated inside enclave): \n%s\n", pem_key);
	// convert evidence (uint8_t*) to hex string
	string requester_enclave_evidence_hex_str = uint8_to_hex_string(evidence, evidence_size); 
	string requester_enclave_pub_key_hex_str = uint8_to_hex_string(pem_key, pem_key_size); 
	//cout << "DataRequsterEnclave's evidence: \n" << requester_enclave_evidence_hex_str <<  "\n"
	//	 << "Size: " << requester_enclave_evidence_hex_str.size() << endl;	
	//cout << "DataRequsterEnclave's public key (hex): \n" << requester_enclave_pub_key_hex_str <<  "\n"
	//	 << "Size: " << requester_enclave_pub_key_hex_str.size() << endl;

	
	cout << "\n==== Host: Establishing a secure channel between *DataRequesterEnclave* and *JuryEnclave* ..." << endl;
	cout << "Host: Sending to *JuryEnclave* our *enclave evidence* with public key ..." << endl;
	// We send our own evidence with public key
	string jury_result = get_leader_enclave_evidence_with_public_key(access_committee_leader_ip, 
			access_committee_leader_port, requester_enclave_evidence_hex_str, requester_enclave_pub_key_hex_str);
	json jury_evidence_with_pub_key = json::parse(jury_result);
	string jury_evidence_hex_str = jury_evidence_with_pub_key["evidence"]; 
	string jury_pub_key_hex_str  = jury_evidence_with_pub_key["pub_key"];
	cout << "Host: Received *JuryEnclave*'s *enclave evidence* with public key ..." << endl;
	//cout << "JuryEnclave's evidence: \n"   << jury_evidence_hex_str <<  "\nSize: " << jury_evidence_hex_str.size() << endl;	
	//cout << "JuryEnclave's public key (hex): " << jury_pub_key_hex_str <<  "\nSize: " << jury_pub_key_hex_str.size() << endl;	

	uint8_t* jury_pub_key = NULL;
    size_t jury_pub_key_size = 0;
    uint8_t* jury_evidence = NULL;
    size_t jury_evidence_size = 0;
	
	std::vector<uint8_t> jury_evidence_vec = hex_string_to_uint8_vec(jury_evidence_hex_str);
	jury_evidence_size = jury_evidence_vec.size();
  	jury_evidence = &jury_evidence_vec[0];

	std::vector<uint8_t> jury_pub_key_vec = hex_string_to_uint8_vec(jury_pub_key_hex_str);
	jury_pub_key_size = jury_pub_key_vec.size();
	jury_pub_key = &jury_pub_key_vec[0];

	cout << "Host: verify_evidence_and_set_public_key in JuryEnclave" << endl;
    result = verify_evidence_and_set_public_key(
        enclave_a,
        &ret,
        format_id,
        jury_pub_key,
        jury_pub_key_size,
        jury_evidence,
        jury_evidence_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf( "Host: verify_evidence_and_set_public_key failed. %s\n", oe_result_str(result));
        if (ret == 0)
            ret = 1;
   		
		return ret;
	}
	cout << "Host: Established secure channel!" << endl;
	free(pem_key);
	free(evidence);
	free(format_settings);


	/*
	 * With successful attestation on each other, we are ready to exchange
	 * data between enclaves, securely via asymmetric encryption
	 *
	 * A symmetric encryption key is exchanged for traffic encryption
	 */
	////////////////////////////////////////////////////////////////	
	// Testing code
	////////////////////////////////////////////////////////////////	
//    uint8_t* encrypted_message = NULL;
//    size_t encrypted_message_size = 0;
//	  printf("Host: Requesting encrypted message from 1st enclave\n");
//    result = generate_encrypted_message(
//        enclave_a, &ret, &encrypted_message, &encrypted_message_size);
//    if ((result != OE_OK) || (ret != 0))
//    {
//        printf(
//            "Host: generate_encrypted_message failed. %s",
//            oe_result_str(result));
//        if (ret == 0)
//            ret = 1;
//		return ret;
//    }
//
//	// Encrypting in one enclave and decrypting in another enclave using asymmetric encryption
//	string ciphertext_hex_str = uint8_to_hex_string(encrypted_message, encrypted_message_size);
//	send_ciphertext(access_committee_leader_ip, access_committee_leader_port, ciphertext_hex_str);	
	
	////////////////////////////////////////////////////////////////	
//	string message_str("HelloJuryEnclave");
//	uint8_t* message = (uint8_t*)message_str.c_str();
//	size_t   message_size = message_str.size();
//	uint8_t* ctext;
//	size_t   ctext_size;
//
//	string message_hex_str = uint8_to_hex_string(message, message_size);
//	cout << "Host: message_hex_str = " << message_hex_str << endl;
//	result = encrypt_message_aes(
//        enclave_a,
//        &ret,
//		message,
//		message_size,
//		&ctext,
//		&ctext_size);
//    if ((result != OE_OK) || (ret != 0))
//    {
//        printf( "Host: encrypt_message_ase() failed. %s\n", oe_result_str(result));
//        if (ret == 0)
//            ret = 1;
//   		
//		return ret;
//	}
//	string ctext_hex_str = uint8_to_hex_string(ctext, ctext_size);
//	cout << "Host: ctext_hex_str = " <<  ctext_hex_str << endl;
//
//	uint8_t* rtext;
//	size_t   rtext_size;
//	result = decrypt_message_aes(
//        enclave_a,
//        &ret,
//		ctext,
//		ctext_size,
//		&rtext,
//		&rtext_size);
//    if ((result != OE_OK) || (ret != 0))
//    {
//        printf( "Host: decrypt_message_ase() failed. %s\n", oe_result_str(result));
//        if (ret == 0)
//            ret = 1;
//   		
//		return ret;
//	}
//	string rtext_hex_str = uint8_to_hex_string( rtext, rtext_size);
//	cout << "Host: rtext_hex_str = " << rtext_hex_str << endl;
//     
//	// Encrypting in one enclave and decrypting in another enclave using symmetric encryption
//	string ciphertext_hex_str = uint8_to_hex_string(ctext, ctext_size);
//	send_ciphertext(access_committee_leader_ip, access_committee_leader_port, ciphertext_hex_str);	
	////////////////////////////////////////////////////////////////	
	

	/* 
	 * Send a request r to access committee leader, where
	 *     r = <dc_id, enclave_evience, nonce>
	 * 
	 * Wait for response from Jury leader
	 * - status_error -> access denied, or data capsule has expired 
	 * - status_ok    -> await for at least k key shares from JURY
	 */
	ip::tcp::iostream ac_stream;
    do {
        ac_stream.clear();
		#ifdef DEBUG_LOG
        cout << "Connecting to Access Committee leader ..." << endl;
		#endif
        ac_stream.connect( access_committee_leader_ip, std::to_string(access_committee_leader_port) );
    } while (!ac_stream);
	#ifdef DEBUG_LOG
    cout << "Connected!" << endl;
	#endif

	json request; 
	request["dc_id"] = data_capsule_id;
	// Jury can extract "mrenclave" from the enclave_evidence 
	request["evidence"] = requester_enclave_evidence_hex_str;  
	int nonce = rand();
	request["nonce"] = std::to_string(nonce);

	ac_stream << req_access_dc << endl;
	ac_stream << request.dump() << endl;
	ac_stream.flush();


	string status;
	ac_stream >> status;
	
	if(status == status_error){ 
		cout << "\n==== Host: The requested *data capsule* has expired or does not exist!\n" << endl;
		return 0;
	}
	
	unsigned char restored[sss_MLEN];
	if(status == status_ok) {
		cout << "\n==== Host: The requested *data capsule* is available!" << endl;
		
		string token_str;
		ac_stream >> token_str;
		long token = std::stol(token_str);
		cout << "token = " << token << endl;
	

		/* NOTE: 
		 * The enclave must be programmed such that user inputs are supplied 
		 * before obtaining key shares
		 * 
		 * Provide user inputs, if any
		 */
		 // We do not have user inputs in this example
		 // ...

		/* Load data capsule into enclave */
		cout << "\n==== Host: Loading data capsule into enclave ... " << endl;
		std::ifstream dc_file(data_capsule_file, std::ios::binary | std::ios::ate);
	  	std::streamsize dc_file_size = dc_file.tellg();
		cout << "dc_file_size = " << dc_file_size << endl;
	  	dc_file.seekg(0, std::ios::beg);
		std::vector<char> buffer(dc_file_size);
		if (dc_file.read(buffer.data(), dc_file_size))
		{
        	result = load_data_capsule(enclave_a, &ret, (uint8_t*)&buffer[0], dc_file_size);
         	if ((result != OE_OK) || (ret != 0)) {
            	if (ret == 0)
            	    ret = 1;
				printf("Host: Load data capsule failed. %s", oe_result_str(result));
				return ret;	
         	}
		}
	

		/* 
		 * Obtain the cluster configration of Access Committee
	     *  - number of nodes
	 	 *  - each node's server_id and endpoint (ip:http_port)
	     *  - leader node's server_id
		 */
		cout << "\n==== Host: Obtaining cluster configuration ..." << endl;
		json cluster_config = get_committee_config(access_committee_leader_ip, access_committee_leader_port);
		int num_of_nodes = cluster_config["num_of_nodes"];
		json endpoints = cluster_config["endpoints"];
		#ifdef DEBUG_LOG
		cout << " - num_of_nodes = " << num_of_nodes << endl;
		cout << " - endpoints = " << endpoints.dump() << endl;
		#endif
		/* 
		 * Compute values for parameters in secret-sharing scheme (n,k)
		 *  - n = num of nodes
		 *  - k = n/2 + 1
		 */
		int n, k; 		
		n = num_of_nodes;
		k = n/2 + 1; 
		cout << "Secret-sharing scheme is: (" << n << "-" << k << ")" << endl;


		/*  
		 * Wait for at least k key shares from Access Committee before we start 
		 * to reconstruct the key
		 *
		 * For each received key share with token, check whether the received token 
		 * matches with previous one
		 */
		cout << "\n==== Host: Waiting for key shares ..." << endl;	
		sleep(1);
		std::future<std::string> key_share_token_future[n];	
		std::string key_shares_hexstr[n];	
		// element.key() => server_id; element.value() => endpoint (ip:port)
		int i = 0;	
		for (auto& element : endpoints.items()) {
			//int server_id = std::stoi( element.key() );
			string endpoint = element.value();
			std::vector<string> v = split(endpoint, ':');
			string node_ip = v[0];
			string node_port = v[1];
			
			int http_port = std::stoi(node_port);	
			#ifdef DEBUG_LOG
			cout << "Node endpoint (ip:http_port) = " << node_ip << ":" << http_port << endl;
			#endif
			key_share_token_future[i] = std::async(std::launch::async, 
					thread_func_request_key_share_token, 
					node_ip, http_port, data_capsule_id);		
			i++;
		}
		for (i = 0; i < n; ++i) {
			string key_share_token_i_jstr = key_share_token_future[i].get();
			json key_share_token_i = json::parse(key_share_token_i_jstr);
			string token_i = key_share_token_i["token"];
			// Check whether tokens match
			if(token_i == token_str) {
				key_shares_hexstr[i] = key_share_token_i["key_share"];
				#ifdef DEBUG_LOG
				cout << "key_shares[" << i << "] = " << key_shares_hexstr[i] << endl;
				cout << "token" << std::stol(token_i) << endl;
				#endif
			}
		}
		 
				
		////////////////////////////////////////////////////////////	
		/* 
		 * Reconstruct the decryption key
		 */	
		//////////////////////////////////
		/// Testing code on the host side	
		//////////////////////////////////
	//	sss_Share shares[n]; // typedef uint8_t sss_Share[sss_SHARE_LEN]
	//	for (int i = 0; i< n; i++) {
	//		string key_share_i_hex_str = key_shares_hexstr[i];
	//		std::vector<uint8_t> key_share_i_uint8_vec = hex_string_to_uint8_vec(key_share_i_hex_str); 
	//		for(int j = 0; j< sss_SHARE_LEN; j++) {
	//			shares[i][j] = key_share_i_uint8_vec.at(j);
	//		}
	//	}
	//	// Combine some of the shares to restore the original secret
	//	//unsigned char restored[sss_MLEN];
	//	int tmp = sss_combine_shares(restored, shares, k);
	//	assert(tmp == 0);
	//	cout << "Host: Decryption key (HEX): \n" << uint8_to_hex_string(restored, sss_MLEN) << endl;
		//////////////////////////////////
		
		cout << "\n==== Host: Requesting DataUserEnclave to reconstruct the decryption key ..." << endl;
		size_t shares_size = n * sss_SHARE_LEN;
		std::vector<uint8_t> shares_vec(shares_size);
		for (int i = 0; i< n; i++) {
			string key_share_i_hex_str = key_shares_hexstr[i];
			std::vector<uint8_t> key_share_i_uint8_vec = hex_string_to_uint8_vec(key_share_i_hex_str); 
			for(int j = 0; j< sss_SHARE_LEN; j++) {
				shares_vec[i*sss_SHARE_LEN + j ] = key_share_i_uint8_vec.at(j);
			}
		}
		
		result = reconstruct_decryption_key(enclave_a, &ret, n, &shares_vec[0], shares_size);
    	if ((result != OE_OK) || (ret != 0)) {
    		if (ret == 0) {
    		    ret = 1;
			}
			printf("Host: Reconstructing decryption key in *DataUserEnclave* failed. %s", oe_result_str(result));
			return ret;	
    	}


		
		////////////////////////////////////////////////////////////	
		/* 
		 * Decrypting the data capsule ...
		 */	
		//////////////////////////////////////
		/// Testing code on the host side	
		//////////////////////////////////////
	//	{
	//	cout << "Host: Decrypting the data capsule ..." << endl; 
	//  	byte key[KEY_SIZE];
	//  	memcpy(key, restored, KEY_SIZE);
	//
	//  	std::ifstream inputfile(data_capsule_file, std::ios::binary | std::ios::ate);
	//  	std::streamsize size = inputfile.tellg();
	//  	inputfile.seekg(0, std::ios::beg);
	//
	//  	byte iv[BLOCK_SIZE];	
	//  	using aes_iv_t = std::array<byte, BLOCK_SIZE>;
	//  	aes_iv_t iv_array;
	//  	read_bytes<aes_iv_t>(inputfile, iv_array);
	//  	memcpy(iv, iv_array.data(), BLOCK_SIZE);
	//
	//  	bytes ctext(size-BLOCK_SIZE);
	//  	read_bytes<bytes>(inputfile, ctext);
	//
	//  	bytes rtext;
	//  	aes_decrypt(key,iv,ctext,rtext);
	//
	//  	std::ofstream fp(data_capsule_file + ".rec", std::ios::binary | std::ios::out);
	//  	fp.write(reinterpret_cast<const char*>(rtext.data()), rtext.size());
	//  	fp.close();
	//	
	//	std::ifstream inputfile_fs( data_capsule_file + ".rec");
	//	if (!inputfile_fs) {
	//		cerr << "Can’t open input file \"" <<  data_capsule_file + ".rec" << "\"" << endl;
	//		return 0;
	//	}
	//	
	//	cout << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"
	//		 << "Here is the secret data: \n"
	//		 << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" << endl;
	//	cout << inputfile_fs.rdbuf() << endl;
	//	}
		//////////////////////////////////

		result = consume_data(enclave_a, &ret);
    	if ((result != OE_OK) || (ret != 0)) {
    		if (ret == 0) {
    		    ret = 1;
			}
			printf("Host: Consume data failed! %s", oe_result_str(result));
			return ret;	
    	}

		return 0;
	}  // end of "if(status == status_ok) " 
}


/// Returns the serialized json object containing key_share and token
string thread_func_request_key_share_token(string node_ip, int http_port, string dc_id)
{
	ip::tcp::iostream key_share_stream;
	do {
		key_share_stream.clear();
		#ifdef DEBUG_LOG
		cout << "Connecting to Access Commitee node " << node_ip << ":" << http_port << "..." << endl;
		#endif
		key_share_stream.connect(node_ip, std::to_string(http_port) );
	} while (!key_share_stream);
	
	#ifdef DEBUG_LOG
	cout << "Connected!" << endl;
	#endif
	
	key_share_stream << req_key_share << endl;
	key_share_stream << dc_id << endl;
	key_share_stream.flush();

	string key_share;
	string token;
	
	key_share_stream >> key_share;
	key_share_stream >> token;
	#ifdef DEBUG_LOG
	cout << "Obtained key_share and token!" << endl;
	cout << " - key_share = " << key_share << endl;
	cout << " - token = " << token << endl;
	#endif

	json key_share_with_token;
	key_share_with_token["key_share"] = key_share;
	key_share_with_token["token"] = token;
	
	return key_share_with_token.dump();	
}

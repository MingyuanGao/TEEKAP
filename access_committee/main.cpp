#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <memory>

#include <boost/asio.hpp>

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "host/juryenclave_u.h"

#include "../include/json.hpp"
using json = nlohmann::json;

using std::cout;
using std::cerr;
using std::cin;
using std::endl;

#include "raft_server.hpp"
using namespace dc_server;


// SGX Local Attestation UUID.
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_juryenclave_enclave(
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


/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
 */
static const oe_claim_t* find_claim(
    const oe_claim_t* claims,
    size_t claims_size,
    const char* name)
{
    for (size_t i = 0; i < claims_size; i++)
    {
        if (strcmp(claims[i].name, name) == 0)
            return &(claims[i]);
    }
    return nullptr;
}


// to make them accessible in tcp server thread
oe_enclave_t* enclave_b = NULL; 
oe_result_t result = OE_OK;
int ret = 1;
oe_uuid_t* format_id = &sgx_remote_uuid;
uint8_t* format_settings = NULL;
size_t format_settings_size = 0;

#include "tcp_server.hpp"

int main(int argc, char* argv[]) {
	if (argc != 6) {
		cerr << "Usage: " << argv[0] << " enclave_path server_id ip_addr raft_port http_port" << endl;
	}
		
	char* enclave_path = argv[1];
	int server_id = std::atoi(argv[2]);
	string ip_addr = argv[3];
	int raft_port = std::atoi(argv[4]);
	int http_port = std::atoi(argv[5]);
	cout << "Arguments provided: " << endl
         << "enclave_path = " << enclave_path << endl 
         << "server_id = " << server_id << endl
         << "ip_addr   = " << ip_addr << endl
         << "raft_port = " << raft_port << endl
         << "http_port = " << http_port << endl << endl;


	// To run the raft cluster on a single machine, raft_port and http_port are added by server_id	
	#ifdef SUPPORT_SINGLE_MACHINE_CLUSTER	
	raft_port += server_id; 
	//http_port += server_id; // done in the function start_tcp_server()
	#endif

	// Do some important checks
    if (server_id < 1) {
        cerr << "wrong server id (should be >= 1): " << server_id << endl
			 << "Usage: " << argv[0] << " server_id ip_addr raft_port http_port" << endl;
		exit(0);
	}
    if (raft_port < 1000) {
        cerr << "wrong port (should be >= 1000): " << raft_port << endl
		     << "Usage: " << argv[0] << " server_id ip_addr raft_port http_port" << endl;
		exit(0);
    }
	
	
	/* 
	 * During enclave initialization, a public-private key pair is generated 
	 * uniformly at random.
	 *
	 * The public key's hash is embedded in the attestation report, which can be verfied 
	 * during the remote attestation to the remote enclave.
	 *
	 * Client uses this public key to establish a secure and authenticated commnication 
	 * channel to JURY's enclave.
	 */
	cout << "\n==== Host: Creating *JuryEnclave* ..." << endl;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
	//oe_enclave_t* enclave_b = NULL;
    enclave_b = create_enclave(enclave_path, flags);
    if (enclave_b == NULL)
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

	
	// Requesting *DataRequesterEnclave* format settings ...
	result = get_enclave_format_settings(
        enclave_b,
        &ret,
        format_id,
        &format_settings,
        &format_settings_size);
    if ((result != OE_OK) || (ret != 0)) {
        printf("Host: get_format_settings failed. %s\n", oe_result_str(result));
		return 1;
	}
	// convert format_settings (uint8_t*) to hex string
//	string jury_enclave_format_settings_hex_str = uint8_to_hex_string(format_settings, format_settings_size); 
//	cout << "JuryEnclave's format_settings: \n" << jury_enclave_format_settings_hex_str << "\n"
//		 << "Size: " << jury_enclave_format_settings_hex_str.size() << endl;


	cout << "\n==== Host: Requesting *JuryEnclave* to generate a targeted *enclave evidence* with public key ... " << endl;
	uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    result = get_evidence_with_public_key(
        enclave_b,
        &ret,
        format_id,
		nullptr,
		0,
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
	printf("Host: JuryEnclave's public key (generated inside enclave): \n%s\n", pem_key);
	// convert evidence (uint8_t*) to hex string 
   	jury_enclave_evidence_hex_str = uint8_to_hex_string(evidence, evidence_size); 
	jury_enclave_pub_key_hex_str  = uint8_to_hex_string(pem_key, pem_key_size);  
//	cout << "Host: JuryEnclave's evidence: \n" << jury_enclave_evidence_hex_str << "\n"
//		 << "Size: " << jury_enclave_evidence_hex_str.size() << endl;
//	cout << "Public key (hex): \n" << jury_enclave_pub_key_hex_str << "\n"
//		 << "Size: " << jury_enclave_pub_key_hex_str.size() << endl;


	///////////////////////////////////////////////////////////////////////
	// set server_id
	stuff.server_id_ = server_id;
	// set server ip address and port
	stuff.addr_ = ip_addr;
	stuff.port_ = raft_port;
    stuff.endpoint_ = stuff.addr_ + ":" + std::to_string(stuff.port_);

    init_raft( cs_new<calc_state_machine>() );
    cout << "Data Capsule Access Committee with Raft" << endl
     	 << "Server ID:     " << stuff.server_id_ << endl
     	 << "Raft Endpoint: " << stuff.endpoint_ << endl;
	
	// Start a TCP server in another thread
	stop_tcp_server = false;	
	std::thread thread_tcp_server(thread_func_tcp_server, server_id, ip_addr, http_port);

	// Interactation loop
	char cmd[1000];
    std::string prompt = "access_committee_node " + std::to_string(stuff.server_id_) + "> ";
    while (true) {
        cout << _CLM_GREEN << prompt << _CLM_END;
		
		cin.getline(cmd, 1000);

        std::vector<std::string> tokens = tokenize(cmd);
        bool cont = do_cmd(tokens);
        if (!cont) break;
    }


	// Stop the TCP server in another thread
	stop_tcp_server = true;
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	exit(0);
}

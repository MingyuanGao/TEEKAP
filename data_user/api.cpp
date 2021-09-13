#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
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


//#include "../include/protocol.h"
#include "api.h"


/* Utility functions */
std::vector<std::string> split(std::string strToSplit, char delimeter);
std::string uint8_to_hex_string(const uint8_t *v, const size_t s);
std::vector<uint8_t> hex_string_to_uint8_vec(const string& hex);


#include "evp_encryption.h"


///////////////////////////////////////////////////////////
// APIs for data users
///////////////////////////////////////////////////////////

/* Get the config of the access committee (i.e., the Raft cluster config)
 *  - number of nodes
 *  - each node's server_id and endpoint (ip:http_port)
 *  - leader node's server_id
 *
 * How to extract the server_id and endpoint
 *    // element.key() => server_id;
 *    // element.value() => endpoint, i.e., ip:port
 *    for (auto& element : endpoints.items()) {
 *        std::cout << element.key() << ":" << element.value() << endl;
 *    }	
 *
 *    // element => endpoint, i.e., ip:port
 *    for (auto& element : endpoints) {
 *        std::cout << element << endl;
 *    }	
 */
json get_committee_config(std::string leader_node_ip, int port) {
	// TODO: FIX this	
	std::string req_cluster_config = "request_cluster_config";
	
	ip::tcp::iostream config_stream;
	do {
		config_stream.clear();
		#ifdef DEBUG_LOG	
		std::cout << "Connecting to Access Commitee Leader ..." << std::endl;
		#endif
		config_stream.connect(leader_node_ip, std::to_string(port) );
		//std::this_thread::sleep_for(std::chrono::milliseconds(100));	
	} while (!config_stream);
	#ifdef DEBUG_LOG	
	std::cout << "Connected!" << std::endl;
	#endif
	
	config_stream << req_cluster_config << std::endl;
	config_stream.flush();
	
	std::string cluster_config_serialized;
	config_stream >> cluster_config_serialized;
	//std::cout << cluster_config_serialized << std::endl;	
	
	json cluster_config = json::parse(cluster_config_serialized);	

#ifdef DEBUG_LOG	
	int leader_id = cluster_config["leader_id"];
	int num_of_nodes = cluster_config["num_of_nodes"];
	json endpoints = cluster_config["endpoints"];
	std::cout << "Obtained cluster configuration: " << std::endl;
	std::cout << " - leader_id = " << leader_id << std::endl;
	std::cout << " - num_of_nodes = " << num_of_nodes << std::endl;
	std::cout << " - endpoints = " << endpoints.dump() << std::endl;
#endif

	return cluster_config;
}


/* 
 * Get the enclave evidence with public key from access committee's leader node
 */
string get_leader_enclave_evidence_with_public_key (string leader_node_ip, int port, string our_evidence, string our_pub_key) {
	// TODO: FIX this	
	string req_enclave_evidence = "request_enclave_evidence_with_public_key";

	ip::tcp::iostream evidence_stream;
	do {
		evidence_stream.clear();
		#ifdef DEBUG_LOG	
		cout << "Connecting to Access Commitee Leader ..." << endl;
		#endif
		evidence_stream.connect(leader_node_ip, std::to_string(port) );
	} while (!evidence_stream);
	#ifdef DEBUG_LOG	
	cout << "Connected!" << endl;
	#endif
	
	evidence_stream << req_enclave_evidence << endl;
	evidence_stream << our_evidence << endl;
	evidence_stream << our_pub_key << endl;	
	evidence_stream.flush();

	string evidence;
	string pub_key;
	evidence_stream >> evidence;
	evidence_stream >> pub_key;

	json evidence_with_pub_key;
	evidence_with_pub_key["evidence"] = evidence;
	evidence_with_pub_key["pub_key"] = pub_key;

	return evidence_with_pub_key.dump();
}


bool send_ciphertext(string leader_node_ip, int port, string ciphertext_hex_str) {
	// TODO: FIX this	
	string req_send_ciphertext = "request_send_ciphertext";	
	string status_ok = "dc_status_ok";

	ip::tcp::iostream ct_stream;
	do {
		ct_stream.clear();
		#ifdef DEBUG_LOG	
		cout << "Connecting to Access Commitee Leader ..." << endl;
		#endif
		ct_stream.connect(leader_node_ip, std::to_string(port) );
	} while (!ct_stream);
	#ifdef DEBUG_LOG	
	cout << "Connected!" << endl;
	#endif
	
	ct_stream << req_send_ciphertext << endl;
	ct_stream << ciphertext_hex_str  << endl;
	ct_stream.flush();
	
	string status;
	ct_stream >> status;

	if(status == status_ok ) {
		return true;
	} 

	return false;
}



/* 
 * Download the data capsule file (i.e., encrypted data) from Storage Server 
 */
bool download_dc_file_from_storage_server(std::string data_capsule_id, std::string server_ip, int port) {
	// TODO: FIX this	
	std::string req_download_file = "request_download_file";
	string status_ok = "dc_status_ok";
	string status_error = "dc_status_ok";

	ip::tcp::iostream data_stream;
	do {
		data_stream.clear();
		cout << "Connecting to Storage Server ..." << endl;
		data_stream.connect( server_ip, std::to_string(port) );
		std::this_thread::sleep_for(std::chrono::milliseconds(100));	
	} while (!data_stream);
	cout << "Connected to Storage Server!" << endl;
	
	data_stream << req_download_file << endl;
	data_stream << data_capsule_id << endl;
	data_stream.flush();
	
	std::ofstream data_fs(data_capsule_id, std::ios::binary);
	data_stream >> data_fs.rdbuf();
	
	string status;
	data_stream >> status;
	//cout << "status = " << status << endl;
	if(status ==  status_error) {
		cout << "Failed to download the data capsule file: " << data_capsule_id << endl;	
		return false;
	}
	
	if(status ==  status_error) {
		cout << "Downloaded the data capsule file: " << data_capsule_id << endl;	
		return true;
	}
}


///////////////////////////////////////////////////////////
// Utility functions 
///////////////////////////////////////////////////////////

/* std::string split implementation using a character as the delimiter */
std::vector<std::string> split(std::string strToSplit, char delimeter)
{
	std::stringstream ss(strToSplit);
	std::string item;
	std::vector<std::string> splittedStrings;
    while(getline(ss, item, delimeter)) {
        splittedStrings.push_back(item);
    }   
    
    return splittedStrings;
}

std::string uint8_to_hex_string(const uint8_t *v, const size_t s) {
  std::stringstream ss;

  ss << std::hex << std::setfill('0');

  for (int i = 0; i < s; i++) {
    ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
  }

  return ss.str();
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


///////////////////////////////////////////////////////////
// EVP encryption
///////////////////////////////////////////////////////////

void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE])
{
  int rc = RAND_bytes(key, KEY_SIZE);
  if (rc != 1)
    throw std::runtime_error("RAND_bytes key failed");

  rc = RAND_bytes(iv, BLOCK_SIZE);
  if (rc != 1)
    throw std::runtime_error("RAND_bytes for iv failed");
}


void aes_encrypt(
  const byte key[KEY_SIZE],
  const byte iv[BLOCK_SIZE],
  const bytes& ptext,
  bytes& ctext)
{
  EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
  int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptInit_ex failed");

  // Recovered text expands upto BLOCK_SIZE
  ctext.resize(ptext.size() + BLOCK_SIZE);
  int out_len1 = (int)ctext.size();

  rc = EVP_EncryptUpdate(
    ctx.get(),
    (byte*)&ctext[0],
    &out_len1,
    (const byte*)&ptext[0],
    (int)ptext.size());
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptUpdate failed");

  int out_len2 = (int)ctext.size() - out_len1;
  rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&ctext[0] + out_len1, &out_len2);
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptFinal_ex failed");

  // Set cipher text size now that we know it
  ctext.resize(out_len1 + out_len2);
}


void aes_decrypt(
  const byte key[KEY_SIZE],
  const byte iv[BLOCK_SIZE],
  const bytes& ctext,
  bytes& rtext)
{
  EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
  int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptInit_ex failed");

  // Recovered text contracts upto BLOCK_SIZE
  rtext.resize(ctext.size());
  int out_len1 = (int)rtext.size();

  rc = EVP_DecryptUpdate(
    ctx.get(),
    (byte*)&rtext[0],
    &out_len1,
    (const byte*)&ctext[0],
    (int)ctext.size());
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptUpdate failed");

  int out_len2 = (int)rtext.size() - out_len1;
  rc = EVP_DecryptFinal_ex(ctx.get(), (byte*)&rtext[0] + out_len1, &out_len2);
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptFinal_ex failed");

  // Set recovered text size now that we know it
  rtext.resize(out_len1 + out_len2);
}

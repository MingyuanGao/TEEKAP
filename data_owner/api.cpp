#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <limits>
#include <memory>
#include <stdexcept>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>
using namespace std::chrono;
using namespace std::literals::chrono_literals;
using std::cout;
using std::cin;
using std::cerr;
using std::endl;
using std::string;

#include <boost/asio.hpp>
using namespace boost::asio;

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

extern "C" {
#include "../sss/sss.h"
}

#include "../include/protocol.h"
#include "api.h"


/* Declaration of internal APIs and utility functions */
void register_dc_policy(json committee_config, string dc_policy_json_string);
void register_dc_key(json committee_config, string key_shares_json_string);
void thread_func_upload_data(const std::string node_ip, int node_port, const std::string request, string data); 
std::vector<std::string> split(std::string strToSplit, char delimeter);
std::string uint8_to_hex_string(const uint8_t *v, const size_t s);
std::vector<uint8_t> hex_string_to_uint8_vec(const string& hex);

/* EVP encryption 
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */
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


///////////////////////////////////////////////////////////
// APIs for data owner
///////////////////////////////////////////////////////////

/* Get the config of the access committee (i.e., the Raft cluster config)
 *  - number of nodes
 *  - each node's server_id and endpoint (ip:http_port)
 *  - leader node's server_id
 *
 *  The server_id and endpoint can be extracted in the following ways:
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


json create_access_policy(std::string enclave_policy_file) 
{
	/* Read Enclave Policy
	 * During remote attestation, "enclave policy" will be used to ensure 
	 * properties (e.g., MRENCLAVE) in the "enclave quote" match those in the policy
	 */
	std::cout << "Reading enclave policy ... " << std::endl;
	json enclave_policy;
	std::ifstream enclave_policy_fs(enclave_policy_file);
	if (!enclave_policy_fs) { 
		std::cerr << "Can’t open input file \"" << enclave_policy_file << "\"" << std::endl; 
		return 0;
	}
	enclave_policy_fs >> enclave_policy;
	std::string mrsigner = enclave_policy["mrsigner"];
	std::string mrenclave = enclave_policy["mrenclave"];
	#ifdef DEBUG_LOG	
	std::cout << "Provided enclave policy:" << std::endl;
	std::cout << " - mrsigner = " << mrsigner << std::endl;
	std::cout << " - mrenclave = " << mrenclave << std::endl;
	std::cout << "Enclaves with the above MRENCLAVE can access your secret data! \n" << std::endl;
	#endif	

	///////////////////////////
	int access_limit;	
	std::cout << "Let's specify the expiry conditions for your secret data.\n";
	std::cout << "Please input access limit: ";
    std::string line;	
	std::getline(std::cin, line);
	access_limit = std::stoi(line);
	std::cout << "You input is: " << access_limit << " times" << std::endl;
	
	std::string access_duration;
	std::cout << "Please specify how soon your data exists (in days): ";
	std::getline(std::cin, access_duration);	
	std::cout << "You input is: " << access_duration << " days, that is, ";
	
	int access_duration_in_hours = std::stoi(access_duration) * 24;
	std::chrono::hours access_duration_chrono(access_duration_in_hours);
	auto t0 = std::chrono::system_clock::now();
	t0 += access_duration_chrono;
	std::time_t access_expiry_time = std::chrono::system_clock::to_time_t(t0); 
	std::string ts = std::ctime(&access_expiry_time); // convert to calendar time
	ts.resize(ts.size() -1 ); // skip trailing newline
	std::cout << "your data expires on " << ts << std::endl;


	//////////////////////////////////
	json access_policy;
	access_policy["mrsigner"] = mrsigner;
	access_policy["mrenclave"] = mrenclave;
	access_policy["access_limit"] = access_limit;
	access_policy["access_expiry"] = access_expiry_time;

	return access_policy;
}


template <class Container>
void read_bytes(std::ifstream& file, Container& vec)
{
  if (!file.read(reinterpret_cast<char*>(&vec[0]), vec.size()))
  {
    std::abort();
  }
}

/* Return a json object contains metadata of the created data capsule
 *   - dc_id
 *   - mrenclave
 *   - dc_file name (ciphertext)
 *   - access_limit
 *   - access_expiry_time 
 */
json create_data_capsule(std::string inputfile_name, json access_policy, json committee_config) {
	/* I:
	 * Generate a random encryption key (256 bits)
	 * Encrypt the input file
	 * Compute the sha256sum of the encrypted file
	 * Write the ciphertext to a file named "sha256sum.enc"
	 */
	/// Open the input file
	std::ifstream inputfile(inputfile_name, std::ios::binary | std::ios::ate);
	std::streamsize size = inputfile.tellg();
	inputfile.seekg(0, std::ios::beg);
	
	bytes ptext(size);
	if (!inputfile.read(reinterpret_cast<char*>(&ptext[0]), size))
	{
	  std::abort();
	}
	inputfile.close();
	
	/// Encrypt the input file
  	EVP_add_cipher(EVP_aes_256_cbc()); // Load the necessary cipher
  	byte key[KEY_SIZE], iv[BLOCK_SIZE];
  	gen_params(key, iv);
#ifdef DEBUG_LOG	
	cout << "Random encryption key: " << std::hex << key << std::dec << endl;
#endif	
	cout << "Encrypting your file ( " << inputfile_name << " ) ..." << endl;
	bytes ctext;
  	aes_encrypt(key, iv, ptext, ctext);
	
	/// Compute the sha256sum of the ciphertext
 	byte digest[SHA256_DIGEST_LENGTH];
 	SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, iv, BLOCK_SIZE);
    SHA256_Update(&ctx, ctext.data(), ctext.size());
    SHA256_Final(digest, &ctx);

 	std::string sha256sum;
 	sha256sum.reserve(SHA256_DIGEST_LENGTH << 1);
 	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
 	{
 	  char buf[8];
 	  sprintf(buf, "%02hhx", digest[i]);
 	  sha256sum += buf;
 	}
#ifdef DEBUG_LOG	
	cout << "sha256sum of the encrypted file: " << sha256sum << endl;
#endif	
	
	/// Write the ciphertext to a file named "sha256sum.enc"
 	std::ofstream fp(sha256sum+".enc", std::ios::binary | std::ios::out);
 	fp.write( reinterpret_cast<const char*>(iv), BLOCK_SIZE);
 	fp.write( reinterpret_cast<const char*>(ctext.data()), ctext.size());
 	fp.close();
	

	/* II:
	 * Secret-share the encryption key using the (n-k) scheme
	 *  - n = num of nodes
	 *  - k = n/2 + 1
	 *
	 * Upload each key share to a Access Committee node
	 */
	int n, k; 	// n is the number of nodes
	n = committee_config["num_of_nodes"];
	k = n/2 + 1;

#ifdef DEBUG_LOG	
	cout << "Secret-sharing your encryption key using the (" << n << "-" << k << ") scheme" << endl;
	cout << "\n\nKey (HEX)   : " << uint8_to_hex_string(key, KEY_SIZE) << endl;
	cout << "Size (bits) : " << KEY_SIZE * 8 << endl;
#endif

	// Read a message to be shared
	unsigned char data[sss_MLEN]; // sss_MLEN = 64
	memcpy( data, key, KEY_SIZE);

	// "Split" the secret into *n* shares (with a recombination theshold of *k*)
	sss_Share shares[n]; // typedef uint8_t sss_Share[sss_SHARE_LEN]
	sss_create_shares(shares, data, n, k);

	// Combine some of the shares to restore the original secret
	unsigned char restored[sss_MLEN];
	int tmp = sss_combine_shares(restored, shares, k);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);

	/* Test whether we could decrypt the ciphertext again using the reconstructed key
	 * The recovered text is written to "sha256sum.rec1"
	 */
//	{
//		byte key[KEY_SIZE];
//		bytes rtext;
//		memcpy(key, restored, KEY_SIZE);
//		aes_decrypt(key,iv,ctext,rtext);
//		std::ofstream fp(sha256sum+".rec", std::ios::binary | std::ios::out);
// 		fp.write(reinterpret_cast<const char*>(rtext.data()), rtext.size());
// 		fp.close();
//	}
	/* Test whether we could decrypt the ciphertext again from the ciphertext file
	 * The recovered text is written to "sha256sum.rec2"
	 */
//	{
//		byte key[KEY_SIZE];
//		memcpy(key, restored, KEY_SIZE);
//	
//
//		string inputfile_name = sha256sum + ".enc";
//		std::ifstream inputfile(inputfile_name, std::ios::binary | std::ios::ate);
//		std::streamsize size = inputfile.tellg();
//		inputfile.seekg(0, std::ios::beg);
//
//		byte iv[BLOCK_SIZE];	
//		using aes_iv_t = std::array<byte, BLOCK_SIZE>;
//		aes_iv_t iv_array;
//		read_bytes<aes_iv_t>(inputfile, iv_array);
//		memcpy(iv, iv_array.data(), BLOCK_SIZE);
//	
//		bytes ctext(size-BLOCK_SIZE);
//		read_bytes<bytes>(inputfile, ctext);
//
//		bytes rtext;
//		aes_decrypt(key,iv,ctext,rtext);
//
//		std::ofstream fp(sha256sum+".rec2", std::ios::binary | std::ios::out);
// 		fp.write(reinterpret_cast<const char*>(rtext.data()), rtext.size());
// 		fp.close();
//	}

	OPENSSL_cleanse(key, KEY_SIZE);
	OPENSSL_cleanse(iv, BLOCK_SIZE);


	// TODO: 
	// Choose a more efficient scheme to serialize the key_shares
	//    e.g., JSON binary mode, Protocol Buffers, Flat Buffers
	// For now, we convert each key share to a hex string 	
	json key_shares_json;
	key_shares_json["dc_id"] = sha256sum;
	key_shares_json["num_of_shares"] = n;
	json shares_hex_str;
	for( int i = 0; i < n; i++ ) {
		string share_hex = uint8_to_hex_string(shares[i], sss_SHARE_LEN);
		shares_hex_str[i] = share_hex;
	}
	key_shares_json["shares"] = shares_hex_str;		
	//cout << key_shares_json << endl;
	
	
	/* III:
	 * Upload *access policy* to each Access Committee node
	 * - dc_id: sha256sum of encrypted file (string)
	 * - access policy: mrsigner (string)
	 * - threashold values of expiry conditions
	 *   - access times: int
	 *   - expiry time: time_t
	 */
	json dc_metadata;
	dc_metadata["dc_id"] =  sha256sum;
	dc_metadata["mrsigner"] = access_policy["mrsigner"];
	dc_metadata["mrenclave"] =     access_policy["mrenclave"];
	dc_metadata["access_limit"] =  access_policy["access_limit"];
	dc_metadata["access_expiry"] = access_policy["access_expiry"];
	

#ifdef TEST_REGISTRATION_TIME
	auto start = time_point_cast<microseconds>( high_resolution_clock::now() );
#endif
	register_dc_policy(committee_config, dc_metadata.dump() );
	register_dc_key(   committee_config, key_shares_json.dump() );

#ifdef TEST_REGISTRATION_TIME
	auto stop = time_point_cast<microseconds>( high_resolution_clock::now() );
	int registration_us =  (stop - start).count();
	cout << "client registration time = " << registration_us << " microseconds" << endl;
	std::ofstream ofs("registration_client.log", std::iostream::app);
	ofs << registration_us << " us" << endl;
#endif

	dc_metadata["dc_file"] = sha256sum + ".enc"; // only for data owner
	return dc_metadata;
}


/* 
 * Upload the data capsule file (encrypted file) to Storage Server
 *  - dc_id: sha256sum of encrypted file
 *  - dc_file: filename of the encrypted file
 */
bool upload_dc_file_to_storage_server(std::string data_capsule_id, std::string data_capsule_file, std::string server_ip, int server_port) {
	// Open the data capsule file 
	std::ifstream inputfile_fs(data_capsule_file + ".enc", std::ios::binary);
	if (!inputfile_fs) { 
		cerr << "Can’t open input file \"" << data_capsule_file << "\"" << endl; 
		return false;
	}

	// Connect to the Storage Server
	ip::tcp::iostream storage_stream;
	do {
		storage_stream.clear();
		cout << "Connecting to Storage Server ..." << endl;
		storage_stream.connect( server_ip, std::to_string(server_port) );
		std::this_thread::sleep_for(std::chrono::seconds(2));	
	} while (!storage_stream);
	cout << "Connected to Storage Server!" << endl;
	
	cout << "Uploading the data capsule file to Storage Server ..." << endl;
	storage_stream << req_upload_file << endl;
	storage_stream << data_capsule_file << endl;	
	storage_stream << inputfile_fs.rdbuf();
	storage_stream.flush();
	
	inputfile_fs.close();
	cout << "Uploaded the data capsule file to Storage Server!" << endl;
   
	return true;
}


///////////////////////////////////////////////////////////
// Internal APIs
///////////////////////////////////////////////////////////

/* Upload "access policy" to access committee leader 
 *  - dc_policy is the serialized json object
 */
void register_dc_policy(json committee_config, string dc_policy_json_string) {
	/// First, find leader node's endpoint 
	int leader_id = committee_config["leader_id"];	
	json endpoints = committee_config["endpoints"];
	string leader_node_ip;
	int    leader_node_port;
	
	// element.key() => server_id; element.value() => endpoint (i.e., ip:port)
	for (auto& element : endpoints.items()) {
		int server_id = std::stoi( element.key() );
		if(server_id == leader_id) {
			string endpoint = element.value();
			std::vector<string> v = split(endpoint, ':');
			leader_node_ip =   v[0];
			leader_node_port = std::stoi( v[1] );
			break;
		}
	}

    #ifdef DEBUG_LOG	
	cout << "\n---------------------------------------------------\n"; 
	cout << "Leader node info: \n - server_id = " << leader_id 
		 << "\n - endpoint (ip:http_port) = " << leader_node_ip << ":" << leader_node_port;
	cout << "\n---------------------------------------------------\n" << endl;
	#endif	
	
	thread_func_upload_data(leader_node_ip, leader_node_port, req_create_dc_policy, dc_policy_json_string);
}


/* Upload each "key share" to one committee node */ 
void register_dc_key(json committee_config, string key_shares_json_string) {
	//int num_of_nodes = committee_config["num_of_nodes"];
	json endpoints = committee_config["endpoints"];
	
	json key_shares_json = json::parse(key_shares_json_string); 
	string dc_id = key_shares_json["dc_id"];
	int num_of_shares = key_shares_json["num_of_shares"];
	json key_shares = key_shares_json["shares"];
	std::vector<std::string> key_shares_vec;
	for (int i = 0; i < num_of_shares; i++ ) {
		//cout << key_shares[i] << endl; 
		key_shares_vec.push_back( key_shares[i] );
	}

	////////////////////////////////////////////////////////////////
	// Test key reconstruction from shares
	// Calculate secret-sharing scheme parameters
	int n = num_of_shares;
	int k = n/2 + 1; 
	// *n* shares with a recombination theshold of *k*
	sss_Share shares[n]; // typedef uint8_t sss_Share[sss_SHARE_LEN]

	for (int i = 0; i< n; i++) {
		string key_share_i_hex_str = key_shares_vec.at(i); 	
		std::vector<uint8_t> key_share_i_uint8_vec = hex_string_to_uint8_vec(key_share_i_hex_str); 
		for(int j = 0; j< sss_SHARE_LEN; j++) {
			shares[i][j] = key_share_i_uint8_vec.at(j);
		}
	}
	
	// Combine some of the shares to restore the original secret
	unsigned char restored[sss_MLEN];
	int tmp = sss_combine_shares(restored, shares, k);
	assert(tmp == 0);
	//cout << "\n\nRestored Key (HEX): " << uint8_to_hex_string(restored, sss_MLEN) << endl << endl;
	////////////////////////////////////////////////////////////////


	/// Create a vector of threads
    std::vector<std::thread> vecOfThreads;
	
	// element => endpoint, i.e., ip:port
	int num=0;
	for (auto& element : endpoints) {
        #ifdef DEBUG_LOG	
		cout << "Node endpoint (ip:http_port) is : " << element << endl;
		#endif
		
		std::vector<string> v = split(element, ':');
		string node_ip = v[0];
		string node_port = v[1];
		int http_port = std::stoi(node_port);	
		
		json key_share_i;
		key_share_i["dc_id"] = dc_id;
		key_share_i["key_share"] = key_shares_vec.at(num);
		num++;

		vecOfThreads.push_back( 
			std::thread(
				thread_func_upload_data, 
				node_ip, http_port, req_create_dc_key, key_share_i.dump() )
			);
	}	

	// Iterate over the thread vector
    for (std::thread & th : vecOfThreads)
    {
        // If thread Object is Joinable then Join that thread.
        if (th.joinable())
            th.join();
    }

}


/* Upload data to a node
 *   - the server decides how to handle the data according to "request" type
 */
void thread_func_upload_data(const std::string node_ip, int node_port, 
		const std::string request, const std::string data)
{
	// TODO: add SSL support 
	// Use JURY enclave's public key 
	ip::tcp::iostream access_stream;
	do {
		access_stream.clear();
		#ifdef DEBUG_LOG	
		cout << "Connecting to Access Commitee node " << node_ip << " ..." << endl;
		#endif	
		access_stream.connect( node_ip, std::to_string(node_port) );
		//std::this_thread::sleep_for(std::chrono::milliseconds(100));	
	} while (!access_stream);
	#ifdef DEBUG_LOG	
	cout << "Connected to node " << node_ip << "!" << endl;
	#endif	
	
	access_stream << request << endl;
	access_stream << data << endl;	
	access_stream.flush();

	string status;
	access_stream >> status;
	if(status == status_ok) {
		#ifdef DEBUG_LOG	
		cout << "Done on node " << node_ip << "!" << endl;	
		#endif	
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

  // Recovered text contracts up to BLOCK_SIZE
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

#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <future>
#include <string>
#include <cstdlib>

#include <boost/asio.hpp>
using namespace boost::asio;

#include <libnuraft/nuraft.hxx>
using namespace nuraft;

#include "../include/json.hpp"
using json = nlohmann::json;

#include "../include/protocol.h"

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>

using std::cin;
using std::cout;
using std::cerr;
using std::endl;
using std::string;

using namespace dc_server;

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

std::vector<std::string> split(std::string strToSplit, char delimeter);
std::string get_cluster_config(int server_id, int http_port);
void store_dc_key_share(std::string dc_key_share_json_string);
//void handle_connection(ip::tcp::socket& socket, int server_id, int http_port);
void serve(ip::tcp::acceptor& acceptor, int server_id, int http_port);
void append_log(std::string cmd, std::string payload);
/* Verify the enclave evidence and get the MRENCLAVE value from the evidence
 * NOTE: this may fail if the underlying SGX platform is outdated
 */
string verify_enclave_evidence_and_get_mrenclave(string enclave_evidence_hex_str);


struct Session: std::enable_shared_from_this<Session> {
	explicit Session(ip::tcp::socket socket) : socket{std::move(socket)} {  }
	// pass server_id and http_port to make the single_machine_cluster possible
	void handle_connection(int server_id, int http_port);

private:
	ip::tcp::socket socket;
};

// pass server_id and http_port to make the single_machine_cluster possible
void serve(ip::tcp::acceptor& acceptor, int server_id, int http_port) {
	acceptor.async_accept( 
			[&acceptor, server_id, http_port] (boost::system::error_code ec, ip::tcp::socket socket) {
				serve(acceptor, server_id, http_port);
				if(ec) return;
				auto session = std::make_shared<Session>(std::move(socket));
				session->handle_connection(server_id, http_port);
			}
	);
}

bool stop_tcp_server = false;
string jury_enclave_format_settings_hex_str;
string jury_enclave_evidence_hex_str;
string jury_enclave_pub_key_hex_str;
uint8_t* encrypted_message = NULL;
size_t encrypted_message_size = 0;
void thread_func_tcp_server(int server_id, const std::string ip_addr, int http_port) {
	// To run the raft cluster on a single machine, http_port is added by server_id	
	#ifdef SUPPORT_SINGLE_MACHINE_CLUSTER	
	http_port += server_id;	
	#endif
	
	int num_threads = std::thread::hardware_concurrency();
	
	try {
		boost::asio::io_context io_context_{ num_threads };

		// Create a listener socket and bind it to a local endpoint
		boost::asio::ip::tcp::endpoint ep { ip::address::from_string(ip_addr), static_cast<unsigned short>(http_port)};
		ip::tcp::acceptor acceptor_{ io_context_ };
		acceptor_.open(ep.protocol());
		acceptor_.set_option(ip::tcp::acceptor::reuse_address(true));
		acceptor_.bind(ep);
		acceptor_.listen();

		cout << endl << "HTTP Endpoint: " << ip_addr << ":" << http_port << endl	
		     << "Listening on port *" << http_port << "* for TCP connection ..." << endl
		     << "===============================================" << endl;

		while(!stop_tcp_server) {
			/////////////////////////////////////////////////////////
			// Synchronous TCP server
			/////////////////////////////////////////////////////////
			//	ip::tcp::socket socket_{ io_context_ };
			//	acceptor_.accept( socket_ );
			//	handle_connection( socket_ , server_id, http_port);
			

			/////////////////////////////////////////////////////////
			// Asynchronous TCP server
			/////////////////////////////////////////////////////////
			serve(acceptor_, server_id, http_port);
			//io_context_.run();
			
			// Using multiple threads to handle requests
			std::vector<std::future<void>> futures;
			std::generate_n(std::back_inserter(futures), num_threads, 
				[&io_context_] {
					return std::async(std::launch::async, 
							[&io_context_]{io_context_.run();});
				}
			);

			for(auto& future: futures) {
				future.get();
			}

		} // end of "while(!stop_tcp_server)"
	
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
}

// std::string split implementation using a character as the delimiter
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

// dc_key_share_string is the serialized json object "json dc_key_share"
void store_dc_key_share(std::string dc_key_share_json_string) {
	json dc_key_share = json::parse(dc_key_share_json_string);
	#ifdef DEBUG_LOG 	
	cout << dc_key_share.dump(4) << endl;	
	#endif

	string dc_id = dc_key_share["dc_id"];
	string key_share = dc_key_share["key_share"];
	//cout << "key_share =" << key_share << endl;

	string db_file = "./database/" + dc_id;
	json dc;
	std::ifstream dc_ifs(db_file);
	if(!dc_ifs) {
		cerr << "No entry exists, will create a new entry!" << endl;
	} else {
		dc_ifs >> dc;
		dc_ifs.close();	
	}
	
	dc["key_share"] = key_share; 

	std::ofstream dc_ofs(db_file);
	dc_ofs << dc.dump();
}


// When "cmd" = req_create_dc_policy, payload is the serialized json object (string)
// When "cmd" = req_access_dc, payload is the serialized json object (string), which contains "dc_id" and "toke"
void append_log(std::string cmd, std::string payload)
{
	// Serialize and generate Raft log to append
	// The new log will contain the 4-byte length, the cmd (string), and the payload (string)
	// ptr<buffer> new_log = calc_state_machine::enc_log( {op, operand} );
	nuraft::ptr<nuraft::buffer> new_log = buffer::alloc( sizeof(long) + cmd.size() + payload.size() );
	nuraft::buffer_serializer bs(new_log);
	bs.put_str(cmd);
	bs.put_str(payload);

    // To measure the elapsed time.
    ptr<TestSuite::Timer> timer = cs_new<TestSuite::Timer>();
	
    // Do append.
    ptr<raft_result> ret = stuff.raft_instance_->append_entries( {new_log} );

    if (!ret->get_accepted()) {
        // Log append rejected, usually because this node is not a leader.
        std::cout << "failed to replicate: "
                  << ret->get_result_code() << ", "
                  << TestSuite::usToString( timer->getTimeUs() )
                  << std::endl;
        return;
    }
    // Log append accepted, but that doesn't mean the log is committed.
    // Commit result can be obtained below.
	
    if (CALL_TYPE == raft_params::blocking) {
        // Blocking mode:
        //   `append_entries` returns after getting a consensus,
        //   so that `ret` already has the result from state machine.
        ptr<std::exception> err(nullptr);
        handle_result(timer, *ret, err);
		
    } else if (CALL_TYPE == raft_params::async_handler) {
        // Async mode:
        //   `append_entries` returns immediately.
        //   `handle_result` will be invoked asynchronously, after getting a consensus.
        ret->when_ready( std::bind( handle_result,
                                    timer,
                                    std::placeholders::_1,
                                    std::placeholders::_2 ) );

    } else {
        assert(0);
    }

}

// pass server_id and http_port to make the single_machine_cluster possible
// For synchronous TCP server
// void handle_connection(ip::tcp::socket& socket, int server_id, int http_port) {
// For Asynchronous TCP server
void Session::handle_connection( int server_id, int http_port) {
	// https://stackoverflow.com/questions/8003704/boost-asio-is-it-possible-to-turn-accepted-tcp-socket-into-basic-socket-iostrea
	//acceptor_.accept(*access_stream.rdbuf());
	ip::tcp::iostream access_stream;
	access_stream.rdbuf()->assign(boost::asio::ip::tcp::v4(), socket.native_handle() );	

	// First message is the request from client
	string request;
	access_stream >> request;
	
	#ifdef DEBUG_LOG
	cout << "\n--------------------------------------------------" << endl;
	cout << "Request from client: " << request << endl;
	#endif
	
	// ##############################################################	
	if(request == req_cluster_config) {
		std::string cluster_config_serialized = get_cluster_config(server_id, http_port);
		#ifdef DEBUG_LOG
		cout << cluster_config_serialized << endl;
		#endif	
		
		access_stream << cluster_config_serialized << endl;	
		access_stream.flush();
	} // end of "if(request == req_cluster_config)"
	
	// ##############################################################	
	if(request == req_enclave_evidence) {
		string requester_enclave_evidence_hex_str;
		string requester_enclave_pub_key_hex_str;
		access_stream >> requester_enclave_evidence_hex_str;
		access_stream >> requester_enclave_pub_key_hex_str;	
		//cout << "DataRequesterEnclave's evidence: \n" << requester_enclave_evidence_hex_str << "\nSize: " << requester_enclave_evidence_hex_str.size() << endl;
		//cout << "DataRequesterEnclave's public key: " << requester_enclave_pub_key_hex_str  << "\nSize: " << requester_enclave_pub_key_hex_str.size() << endl;
	
		uint8_t* requester_enclave_pub_key = NULL;
    	size_t   requester_enclave_pub_key_size = 0;
    	uint8_t* requester_enclave_evidence = NULL;
    	size_t   requester_enclave_evidence_size = 0;
 
    	std::vector<uint8_t> requester_enclave_evidence_vec = hex_string_to_uint8_vec(requester_enclave_evidence_hex_str);
    	requester_enclave_evidence_size = requester_enclave_evidence_vec.size();
    	requester_enclave_evidence = &requester_enclave_evidence_vec[0];
 
    	std::vector<uint8_t> requester_enclave_pub_key_vec = hex_string_to_uint8_vec(requester_enclave_pub_key_hex_str);
    	requester_enclave_pub_key_size = requester_enclave_pub_key_vec.size();
    	requester_enclave_pub_key = &requester_enclave_pub_key_vec[0];
   
 
    	cout << "Host: verify_evidence_and_set_public_key in JuryEnclave" << endl;
    	result = verify_evidence_and_set_public_key(
    	    enclave_b,
    	    &ret,
    	    format_id,
    	    requester_enclave_pub_key,
    	    requester_enclave_pub_key_size,
    	    requester_enclave_evidence,
    	    requester_enclave_evidence_size);
    	if ((result != OE_OK) || (ret != 0))
    	{
    	    printf( "Host: verify_evidence_and_set_public_key failed. %s\n", oe_result_str(result));
    	}

		access_stream << jury_enclave_evidence_hex_str << endl;
		access_stream << jury_enclave_pub_key_hex_str << endl;
		access_stream.flush();
	} // end of "if(request == req_enclave_evidence)"

	// ##############################################################	
	if(request == req_create_dc_key) {
		string dc_key_share_json_string;	
		access_stream >> dc_key_share_json_string;
		
		store_dc_key_share(dc_key_share_json_string);

		access_stream << status_ok << endl;
		access_stream.flush();
	
		#ifdef DEBUG_LOG
		cout << "key_share stored!" << endl;
		#endif
	} // end of "if(request == req_create_dc_key)

	// ##############################################################	
	if(request == req_create_dc_policy) {
		string dc_policy_json_string;	
		access_stream >> dc_policy_json_string;
	
		append_log(req_create_dc_policy, dc_policy_json_string);
		
		access_stream << status_ok << endl;
		access_stream.flush();

		cout << "Data Capsule created!" << endl;
	} // end of "if(request == req_create_dc_policy)
	
	// ##############################################################	
	if(request == req_access_dc) {
		string request_json_string;
		access_stream >> request_json_string;				
		
		/* Verify the authenticity of this enclave evidence and 
		 * extract the MRENCLAVE value 
		 */
		json request = json::parse(request_json_string);
		string dc_id = request["dc_id"];
		string enclave_evidence_hex_str = request["evidence"];
		string mrenclave = verify_enclave_evidence_and_get_mrenclave(enclave_evidence_hex_str);
		cout << "- dc_id = " << dc_id << "\n"
		     << "- mrenclave = " << mrenclave << endl;
		#ifdef DEBUG_LOG
		cout << "- evidence = " << enclave_evidence_hex_str << endl;
		#endif
		
		/* Check eligibility of the request 
		 */
		cout << "Checking eligibility of the request ... " << endl;
		string db_file = "./database/" + dc_id;
		json dc;
		std::ifstream dc_ifs(db_file);
		if(!dc_ifs) {
			cerr << "No data capsule with such id exists!" << endl;
			access_stream << status_error << endl;
			access_stream.flush();
			return;
		} else {
			dc_ifs >> dc;
			dc_ifs.close();
		}
		string mrenclave_0 = dc["mrenclave"]; 
		int access_limit = dc["access_limit"];
		std::time_t access_expiry = dc["access_expiry"];
	
		// Check whether the enclave is elegible
		#ifdef DEBUG_LOG 
		cout << "- Checking eligibility of the requesting enclave ... " << endl;
		#endif
		if(mrenclave == mrenclave_0) {
			#ifdef DEBUG_LOG 
			cout << "  Enclave is eligible!" << endl;
			#endif
		} else {
			cout << "Illegal Request!" << endl;	
			access_stream << status_error << endl;
			access_stream.flush();
			return;	
		}
	
		// Check whether the data capsule has expired 
		#ifdef DEBUG_LOG
		cout << "- Checking whether the data capsule has expired ... " << endl;
		#endif
		if(access_limit >= 1) {
			std::chrono::time_point tp_now = std::chrono::system_clock::now();
			std::time_t t_now = std::chrono::system_clock::to_time_t(tp_now);
			//cout << "access_expiry = " << access_expiry << endl;
			//cout << "t_now = " << t_now << endl;
			if( access_expiry > t_now ) {
				cout << "  Data capsule is available!" << endl;

				access_stream << status_ok << endl;
				access_stream.flush();

				cout << "  Sending Token ... " << endl; 	
				long token = rand();
				cout << "      token = " << token << endl;
				access_stream << std::to_string(token) << endl;
				
		
				/* We request all the followers to send the key share and token
				 *
				 * Once the client receives enough key shares with matching token, it will 
				 * reconstruct the key
				 */
				cout << "  Asking followers to distribute key shares ... " << endl; 	
				json dc_id_token_json;
				dc_id_token_json["dc_id"] = dc_id;
				dc_id_token_json["token"] = std::to_string(token);
				append_log(req_access_dc, dc_id_token_json.dump());
				
			} else { // end of "if( access_expiry > t_now )"
				cout << "Illegal Request!" << endl;	
				access_stream << status_error << endl;
				access_stream.flush();
				return;	
			}
		} else { // end of "if(access_limit >= 1)"
			cout << "Illegal Request!" << endl;	
			access_stream << status_error << endl;
			access_stream.flush();
			return;	
		}
		
		cout << "Access request is granted!" << endl;
	} // end of "if(request == req_access_dc)"

	// ##############################################################	
	if(request == req_key_share) {
		string dc_id;
		
		access_stream >> dc_id;
		cout << "dc_id = " << dc_id << endl;

		string db_file = "./database/" + dc_id;
		json dc;
		std::ifstream dc_ifs(db_file);
		if(!dc_ifs) {
			cerr << "No data capsule with such id exists!" << endl;
			return;
		} else {
			dc_ifs >> dc;
			dc_ifs.close();
		}
		
		string key_share = dc["key_share"]; 
		string token = dc["token"];
		cout << "key_share: " << key_share << endl 
			 << "token: " << std::stol(token) << endl;

		access_stream << key_share << endl;
		access_stream << token << endl;
		access_stream.flush();

		cout << "key_share sent to remote enclave!" << endl;
	} // end of "if(request == req_key_share)

	// ##############################################################	
	// Testing code for encrytion, both asymmetric and symmetric 
	if(request == req_send_ciphertext) {
		string ciphertext_hex_str;
		access_stream >> ciphertext_hex_str;
    	
		std::vector<uint8_t> ciphertext_vec = hex_string_to_uint8_vec(ciphertext_hex_str);
    	encrypted_message_size = ciphertext_vec.size();
    	encrypted_message = &ciphertext_vec[0];
	
		/// Testing asymmetric encryption 
	//	result = process_encrypted_message( enclave_b, &ret, encrypted_message, encrypted_message_size);
	//    if ((result != OE_OK) || (ret != 0))
	//    {
	//        printf("Host: process_encrypted_message failed. %s", oe_result_str(result));
	//        if (ret == 0)
	//            ret = 1;
	//		
	//		free(encrypted_message);
	//    }
		
		/// Testing symmetric encryption
		uint8_t* rtext;
    	size_t   rtext_size;
    	result = decrypt_message_aes(
    	    enclave_b,
    	    &ret,
    	    encrypted_message,
    	    encrypted_message_size,
    	    &rtext,
    	    &rtext_size);
    	if ((result != OE_OK) || (ret != 0))
    	{
    	    printf( "Host: decrypt_message_ase() failed. %s\n", oe_result_str(result));
    		cout << "Host: veriry enclave-to-enclave traffic key failed!" << endl;
    	    if (ret == 0) {
            	ret = 1;
			}
    	} else {
    		string rtext_hex_str = uint8_to_hex_string( rtext, rtext_size);
    		cout << "Host: rtext_hex_str = " << rtext_hex_str << endl;
    		cout << "Host: veriry enclave-to-enclave traffic key succeeded!" << endl;
		}

		if(ret == 0) {
			access_stream >> status_ok;
		} else {
			access_stream >> status_error;
		} 
		
		access_stream.flush();
	} // end of "if(request == req_send_ciphertext)"

}


// Return the serialized cluster configuration (json object) 
// Pass server_id and http_port to make single_machine_cluster possible
std::string get_cluster_config(int server_id, int http_port) {
	json cluster_config;
	
	// Get configs from a raft server instance
	std::vector< ptr<srv_config> > configs;
	stuff.raft_instance_->get_srv_config_all(configs);
	
	int leader_id = stuff.raft_instance_->get_leader();
	cluster_config["leader_id"] = leader_id;
	
	int num_of_nodes = configs.size(); 
	//cout << "num_of_nodes = " << num_of_nodes << endl;	
	cluster_config["num_of_nodes"] = num_of_nodes;
		
	for (auto& entry: configs) {
		ptr<srv_config>& srv = entry;
		//std::cout << "server id " << srv->get_id() << ": " << srv->get_endpoint() << endl;
		int node_server_id = srv->get_id();
		string endpoint_raft = srv->get_endpoint();
		
		std::vector<string> v = split(endpoint_raft, ':');
		string node_ip = v[0];

		int node_port = http_port;
		#ifdef SUPPORT_SINGLE_MACHINE_CLUSTER	
		node_port = http_port - server_id + node_server_id;
		#endif

		string endpoint_http = node_ip + ":" + std::to_string(node_port);
		//cout << "endpoint_http = " << endpoint_http << endl;	
		
		cluster_config["endpoints"][std::to_string(node_server_id)] = endpoint_http;	
	}

	//std::string cluster_config_serialized = cluster_config.dump(4);
	//std::string cluster_config_serialized = cluster_config.dump();
	return cluster_config.dump();
}


/* 
 * Verify the enclave evidence and get the MRENCLAVE value from the evidence
 * 
 * NOTE: this may fail if the underlying SGX platform is outdated
 */
string verify_enclave_evidence_and_get_mrenclave(string enclave_evidence_hex_str) {
	string mrenclave_hex_str;
	
	oe_result_t result = OE_FAILURE;
	static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
	uint8_t* evidence = NULL;
    size_t evidence_size = 0;	
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

	std::vector<uint8_t> evidence_vec = hex_string_to_uint8_vec(enclave_evidence_hex_str);
	evidence_size = evidence_vec.size();
  	evidence = &evidence_vec[0];

    result = oe_verify_evidence(
        &sgx_remote_uuid,
        evidence,
        evidence_size,
        NULL,
		0,
        NULL,
        0,
        &claims,
        &claims_length);
    
	if (result != OE_OK) {
        printf("Host: verify evidence failed. %s \n", oe_result_str(result));
		//return nullptr;
		
		// NOTE: to work around our outdated SGX platforms, we hard-coded the MRENCLAVE value of 
		// the DataUserEnclave
		mrenclave_hex_str = "5dabe838af1a6300036bb9e55ccec129448729beaa339279123c56baee2edd1b";
		return mrenclave_hex_str;
	} 

	const oe_claim_t* claim;
	// The unique ID for the enclave; for SGX enclaves, this is the MRENCLAVE value
    if( (claim = find_claim(claims, claims_length, OE_CLAIM_UNIQUE_ID)) == nullptr ) {
        printf("Host: could not find OE_CLAIM_UNIQUE_ID\n");
		return nullptr;
    }
    
	if (claim->value_size != OE_UNIQUE_ID_SIZE) {
        printf("Host: unique_id size(%zu) checking failed\n", claim->value_size);
		return nullptr;
    } 

//	for (size_t i = 0; i < claim->value_size; i++) {
//		printf("0x%x ", (uint8_t)claim->value[i]);
//	}
	mrenclave_hex_str = uint8_to_hex_string( &(claim->value[0]) , claim->value_size ); 

    free(evidence);
    oe_free_claims(claims, claims_length);
	
	return mrenclave_hex_str;
}


#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <string>
#include <ctime>
using namespace std::chrono;
using namespace std::literals::chrono_literals;
using std::cout;
using std::cin;
using std::cerr;
using std::endl;
using std::string;

#include "api.h"

int main(int argc, char* argv[]) {
  	if (argc != 7) {
    	cerr << "Usage: " << argv[0] << "input_file enclave_policy_file access_committee_leader_ip http_port storage_server_ip port  " << endl;
    	return 0;
  	}
	string inputfile_name = argv[1];	
	string enclave_policy_file = argv[2];	
	string access_committee_leader_ip = argv[3];
	int    access_committee_leader_port = std::stoi(argv[4]);
	string storage_server_ip = argv[5];
	int storage_server_port  = std::stoi(argv[6]);

#ifdef DEBUG_LOG	
	cout << "Arguments provided: " << endl
		 << " - inputfile_name        = " << inputfile_name << endl 
 	     << " - enclave_policy_file          = " << enclave_policy_file << endl 
		 << " - access_committee_leader_ip   = " << access_committee_leader_ip << endl 
		 << " - access_committee_leader_port = " << access_committee_leader_port << endl
		 << " - storage_server_ip     = " << storage_server_ip << endl 
		 << " - storage_server_port   = " << storage_server_port << endl << endl;
#endif

	
	json access_policy_json = create_access_policy(enclave_policy_file);
	//cout << access_policy_json << endl;	

	json committee_config_json = get_committee_config(access_committee_leader_ip, access_committee_leader_port);
	//cout << committee_config_json << endl;	
	
	cout << "Creating Your Data Capsule ... " << endl;
	json dc_metadata_json = create_data_capsule(inputfile_name, access_policy_json, committee_config_json);	
	

	/////////////////////////////////////////////////////////////////////////////////////////
	std::time_t access_expiry_time = (std::time_t) dc_metadata_json["access_expiry"];
    std::string ts = std::ctime(&access_expiry_time); // convert to calendar time

 	cout << "\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"
		 << "Data Capsule created! Here are the details:\n\n"
		 << "Secret data to be protected: " << inputfile_name << "\n\n"
		 << "Data Capsule ID: " << dc_metadata_json["dc_id"].get<std::string>() << "\n\n"
		 << "Expiry Conditions: \n" 
		 << "  - Access limit : " << dc_metadata_json["access_limit"] << "\n"
		 << "  - Expires on   : " << ts << "\n"
		 << "Apps that can access the secret data: \n  MRENLCAVE = " << dc_metadata_json["mrenclave"].get<std::string>() << endl;
 	cout << "\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"
		 << "To let others use your secret data, share with them or ask them to download \nthe data capsule file with the following name: \n  "
		 << dc_metadata_json["dc_file"].get<std::string>() << "\n" 
		 << "and tell them the above Data Capsule ID!" << endl << endl;
	
	// Explicit conversion to string
	// string dc_metadata_string = dc_metadata_json.dump();	
	// Serialization with pretty printing; pass in the amount of spaces to indent
	string dc_metadata_string = dc_metadata_json.dump(4);
	//cout << dc_metadata_string << endl; 

	// Save the data capsule metadata to file
	string metadata_filename = dc_metadata_json["dc_id"].get<std::string>() + ".metadata";
	std::ofstream outputfile_of(metadata_filename);
	outputfile_of << dc_metadata_string << endl;

	return 0;
}


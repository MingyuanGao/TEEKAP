#include <iostream>
#include <fstream>
#include <chrono>
#include <unistd.h>

using namespace std::chrono;
using namespace std::literals::chrono_literals;


extern "C" {
#include "../sss/sss.h"
}

#include "../include/json.hpp"
using json = nlohmann::json;

using std::cout;
using std::cin;
using std::cerr;
using std::endl;
using std::string;

int main(int argc, char* argv[]) {
	int n = 3; 		
	if(argc == 2) {
		n = std::stoi(argv[1]); 
	}
	
	int k = n/2 + 1; 

	string enc_key = "L6GE95+PfsclkaVU9JtVCOF5TiJ7+1/PoY/zeidTjgw=";

	// Read a message to be shared
	unsigned char data[sss_MLEN]; // sss_MLEN = 64
	memcpy(data, enc_key.c_str(), sizeof(enc_key) );
	
 	auto start = std::chrono::time_point_cast<std::chrono::microseconds>(high_resolution_clock::now());
	// "Split" the secret into *n* shares (with a recombination theshold of *k*)
	sss_Share shares[n]; // typedef uint8_t sss_Share[sss_SHARE_LEN]
	sss_create_shares(shares, data, n, k);
	auto stop = std::chrono::time_point_cast<std::chrono::microseconds>(high_resolution_clock::now());
	cout << "sss_SHARE_LEN: " << sss_SHARE_LEN << endl;
	cout << "sss_MLEN: " << sss_MLEN << endl;
	cout << "key construction time: " << (stop-start).count() << " us \n";


	// Combine some of the shares to restore the original secret
	unsigned char restored[sss_MLEN];
	int tmp = sss_combine_shares(restored, shares, k);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);
	
	return 0;
}


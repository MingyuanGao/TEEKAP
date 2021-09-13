#pragma once

#include "../include/json.hpp"
using json = nlohmann::json;


/* APIs for data users */
json get_committee_config(std::string leader_node_ip, int port);
string get_leader_enclave_evidence_with_public_key (string leader_node_ip, int port, string our_evidence, string our_pub_key);
bool send_ciphertext(string leader_node_ip, int port, string ciphertext_hex_str);
bool download_dc_file_from_storage_server(std::string data_capsule_id, std::string server_ip, int port);


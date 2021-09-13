#pragma once

#include "../include/json.hpp"
using json = nlohmann::json;

/* APIs for data owners */

json create_access_policy(std::string enclave_policy_file);
json get_committee_config(std::string leader_node_ip, int port);
json create_data_capsule(std::string input_file, json access_policy, json committee_config);
bool upload_dc_file_to_storage_server(std::string data_capsule_id, std::string data_capsule_file, std::string server_endpoint);

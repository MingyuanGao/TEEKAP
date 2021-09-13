#/bin/bash

# Usage: 
# dc_client inputfile enclave_policy_file access_committee_leader_ip http_port storage_server_ip port  

./data_owner_client secret_data.txt enclave_policy.json 172.27.126.170 9001 127.0.0.1 10001 

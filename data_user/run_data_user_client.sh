#/bin/bash

# Usage: data_user_client enclave_path access_committee_leader_ip http_port data_capsule_id data_capsule_file
./data_user_client ./DataUserEnclave.signed 172.27.126.170 9001 $1 $2 

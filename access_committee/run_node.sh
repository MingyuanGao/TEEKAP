#/bin/bash

# Usage: access_committee_node enclave_path server_id ip_addr raft_port http_port

rm -rf database
rm -f *.log

mkdir database
./access_committee_node ./JuryEnclave.signed $1 `hostname -I` 8000 9000 


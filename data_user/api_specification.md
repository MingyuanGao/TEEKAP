After compiling the source code in the "data_user" direcory, a library named "libDataUser.a" is created. This library contain all the APIs that the data owner can use.

**NOTE Since much code for data user is too specific to enclave, we are in the progress of designing some generic APIs for enclave code.**


### API 1: 
`json get_committee_config(string leader_node_ip, int port)`

> Get the config of the access committee (i.e., the Raft cluster config)
> 
> Arguments: leader node's `ip` and `port`
> 
> Return: a json object containing number of nodes, each node's `server_id` and `endpoint (ip:http_port)`, and leader node's `server_id`


### API 2: 
`json get_leader_enclave_evidence_with_public_key(string leader_node_ip, int port)`
> Get the enclave report of JURY leader node, and the public key generated inside the enclave
> 
> Arguments: leader node's ip and port
> 
> Return: a json object containing leader node's enclave evidence and the public key (in hex string format)


### API 3: 
`bool download_data_capsule_file_from_storage_server(std::string data_capsule_id, std::string server_ip, int port);`
> Download the data capsule file from the storage server
> 
> Arguments: path of data capsule file, endpoint of the storage server (ip:port)
> 
> Return: ture/false


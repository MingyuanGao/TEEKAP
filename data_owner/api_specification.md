After compiling the source code in the "data_owner" direcory, a library named "libDataOwner.a" is created. This library contain all the APIs that the data owner can use.

### API 1: 
`json create_access_policy(string enclave_policy_file)`
> Create the access policy which specifies eligible enclaves, and the threshold values of expiry conditions
> 
> Arguments: the enclave policy file, and the interactive inputs
> 
> Return: a json object containing measurements of eligible enclaves, and threshold values of expiry conditions

### API 2: 
`json get_committee_config(string leader_node_ip, int port)`

> Get the config of the access committee (i.e., the Raft cluster config)
> 
> Arguments: leader node's `ip` and `port`
> 
> Return: a json object containing number of nodes, each node's `server_id` and `endpoint (ip:http_port)`, and leader node's `server_id`


### API 3: 
`json  create_data_capsule(string input_file, json access_policy, json committee_config)`
> Create the data capsule per the requirements specified by the data owner
> 
> Arguments: enclave policy file (negociated between data owner and data user), access_policy_file (from API 2), committee_config (from API 1)
> 
> Return: a json object containing metadata of the crated data capsule

### API 4: 
`bool upload_to_storage_server(string data_capsule, string server_ip, int port)`
> Upload the created data capsule to the storage server
> 
> Arguments: path of data capsule file, endpoint of the storage server (ip:port)
> 
> Return: ture/false



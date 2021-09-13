Thank you for evaluating the artifact for TEEKAP. This document will get you started with our prototype implementation. If you encounter any technial difficulties, we will do our best to resolve them as soon as possible. Please contact us at mingyuan.gao@u.nus.edu (Mingyuan Gao), hungdang@comp.nus.edu.sg (Hung Dang) or changec@comp.nus.edu.sg (Ee-Chien Chang).


**Since deploying TEEKAP requires that 1) most machines feature Intel SGX with Flexible Launch Control (FLC) support, and 2) a DCAP (Data Center Attestation Primitive)-based attestation service for Intel SGX has been setup, we have deployed TEEKAP in the SGX cluster at our school. We have sent the login credentials to the Artifact Evaluation Chairs for the reviewers to access our TEEKAP deployment. We also uploaded recordings of terminal sessions to [asciinema.org](https://asciinema.org/~mingyuan) for your reference!**


## 1. Overview of the TEEKAP Platform

Our platform mainly consists of three parts, namely, API library for Data Owners (`libDataOwner`), Access Committee JURY (a cluster of nodes), and API library for Data Users (`libDataUser`). The storage server is optional, and its source code is also provided. Specifically, the specification for all APIs in `libDataOwner` is described in [`data_ower/api_specification.md`](data_owner/api_specification.md). The specification for all APIs in `libDataUser` is described in [`data_user/api_specification.md`](data_user/api_specification.md).

The platform has been prototyped on Ubuntu Linux, and the remote attestation for SGX enclaves uses the DCAP-based scheme, rather than the EPID-based Intel Attestation Service.

<img src=images/overview.png width=80%>


## 2. Setting up TEEKAP

### 2.0 Setting up DCAP Attestation Service for Intel SGX
Please refer to the following links on how to setup the *DCAP Attestation Service* in your own data center, and how to provision your SGX platforms to this service.

* [Intel SGX DCAP Quick Install Guide](https://software.intel.com/content/www/us/en/develop/articles/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html)

* [Setting up Open Enclave to use DCAP](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/NonAccMachineSGXLinuxGettingStarted.md)

### 2.1 Setting up JURY machines

Each JURY node is required to feature Intel SGX with FLC support. In addition, the Open Enclave runtime and some dependent libraries like Boost are required to be installed. In the scripts folder, there are three bash scripts for installing these dependencies, that is, `setup_openenclave_with_dcap_support.sh`, `setup_boost.sh`, and `setup_raft.sh`.

### 2.2 Setting up Data Owner's machine

Data Owner's machine is not required to feature Intel SGX. In addition to the `libDataOwner` library, we also need to install some dependent libraries like Boost, OpenSSL, and the secret-sharing lib. In the scripts folder, there are two bash scripts for installing these libraries, that is, `setup_boost.sh` and `setup_openssl.sh`.

### 2.3 Setting up Data User's machine

Data User's machine is required to feature Intel SGX. In addition to the `libDataUser` library, we also need to install the Open Enclave runtime and some dependent libraries like Boost, OpenSSL, and the secret-sharing lib. In the scripts folder, there are three bash scripts for installing these libraries, that is, `setup_openenclave_with_dcap_support.sh`, `setup_boost.sh` and `setup_openssl.sh`.


## 3. Workflow in TEEKAP

### 3.1 Negociation between Data Owner and Data User 

To use **Data Owner**'s `Data`, **Data User** needs to pass his code (in the form of enclave code) to **Data Owner** for inspection. After inspecting the code without any issues like explicitly leaking raw data, **Data Owner** creates a data capsule for **Data User**. 

When creating a data capsule, the **Data Owner** needs to obtain the "MRENCLAVE" value of the **Data User**'s enclave. Many tools are availale for this, and we will use the built-in tool (i.e., `oesign`) from Open Enclave.

`$ oesign dump --enclave-image DataUserEnclave.signed `

> The above command will dump many metadata about the enclave, one of them is the "MRENCLAVE" value.

### 3.2 Data Owner Creates the Data Capsule

To create a data capsule, the **DataOwner** first creates a file named "enclave_policy.json" with the "MRENCLAVE" value obtained above.

`$ cat enclave_policy.json`

> `{ "mrenclave":"5dabe838af1a6300036bb9e55ccec129448729beaa339279123c56baee2edd1b"}`

Second, the **DataOwner** runs the program `data_owner_client` in the directory `data_owner` to create the data capsule. The program will promote for inputting the **expiry conditions**.

`$ ./data_owner_client input_file access_committee_leader_ip http_port enclave_policy_file storage_server_ip port `

> When the data capsule is successfully created, a metadata file will be created.

`$ cat 06acfb1adc43473a5860f1c124d7568f621bab627f6e9b7a499e63c3c28dfa6f.metadata`

>     "access_expiry": 1633718666,
>     "access_limit": 100,
>     "dc_file": "06acfb1adc43473a5860f1c124d7568f621bab627f6e9b7a499e63c3c28dfa6f.enc",
>     "dc_id": "06acfb1adc43473a5860f1c124d7568f621bab627f6e9b7a499e63c3c28dfa6f",
>     "mrenclave": "bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd",
>     "mrsigner": "bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd"

Here, `dc_file` contains the ciphertext of **DataOwner**'s `Data`, and `dc_id` is the data capsule's permanent `ID`.

### 3.3 Data User Uses the Data Capsule

To use the data capsule, the **DataUser** needs to get the `dc_id` and `dc_file` for the data capsule. The `dc_file` can be shared from the **DataOwner** or downloaded from the `Storage Server`.

To access the `Data` stored inside the data capsule, the **DataUser** runs the program at the directory `data_user_client`.

`$ ./data_user_client enclave_path access_committee_leader_ip http_port data_capsule_id data_capsule_file`


## 4. TEEKAP Deployment at our SGX Cluster

Deploying TEEKAP is non-trivial, since it requires that 1) most machines feature Intel SGX with Flexible Launch Control (FLC) support, and 2) a DCAP (Data Center Attestation Primitive)-based attestation service for Intel SGX has been setup. 

To facilitate the evaluation process, we have deployed TEEKAP in the SGX cluster at our school. We have sent the login credentials to the Artifact Evaluation Chairs for the reviewers to access our TEEKAP deployment.

<img src=images/deployment.png width=80%>

As shown in the above figure, the JURY cluster consists of three machines, i.e., `node1`, `node2`, and `node3`. We provide step-by-step guides on 1) how to deploy JURY, and 2) how to use TEEKAP for **Data Owners** and **Data Users**, as well as recordings of the terminal sessions for your reference.

### 4.0 How to Access our TEEKAP Deployment

We have prepared a machine `acsac-gateway` for the reviewers to access our SGX cluster. 

We have sent the login credentials to this machine.

**Here, we assume you have logged into the machine `acsac-gateway` and opened a Terminal.**


### 4.1 Deploying JURY at a three-node Cluster

**NOTE: We have created a script called `start_jury_nodes.sh` to deploy JURY at a three-node cluster.**

**`$ cd ~/data_capsule/scripts`**
 
**`$ ./start_jury_nodes.sh`**
 
**Type `add_followers` in `node1`'s prompt, and the cluster is brought up.**

**Below is more detailed explanation.**


At the directory `access_committee`, run the make command to compile the source code.

`$ make`

> After the building process is finished, a program called `access_committee_node` will be generated. A signed enclave image called `JuryEnclave.signed` is also generated.


Copy `access_committee_node`, `JuryEnclave.signed` and `run_node.sh` to each node.

Log in to each node, and start the `access_committee_node` program as follows. Record each node's `ip_address` and `server_id`.

`$ ./run_node.sh server_id`

> Please refer to the following terminal recording at https://asciinema.org/a/435586 on how to start a node, and how to add other nodes as followers.

We will make node `node1` the leader, and nodes `node2` and `node3` followers. To do this, first, create a file named `cluster.config` and copy this file to the same directory as `run_node.sh` on machine `node1`.

`$ cat cluster.config`

>`1 172.27.126.170`

>`2 172.27.73.56`

>`3 172.27.87.233`


Then, at `node1`'s "access_committee_node" prompt, issue the `add_followers` command, as shown in the following figure.

<img src=images/add_followers.png width=80%>


### 4.2 DataOwner Creates a Data Capsule

**NOTE: We use the machine `acsac-gateway` as the `DataOwner`'s machine** 

**`$ cd ~/data_capsule/data_owner`**


At the directory `data_owner`, run the make command to compile the source code.

`$ make`

> After the building process is finished, a program called `data_owner_client` will be generated. An API library file called `libDataOwner.a` is also generated.


Run the script `./run_data_owner_client.sh` to create a data capsule for the secrete data `secret_data.txt`

`$ ./run_data_owner_client.sh`

> Please refer to the following terminal recording at https://asciinema.org/a/435677 on how to create a data capsule.


### 4.3 DataUser Uses the Data Capsule

**NOTE: We also use the machine `acsac-gateway` as the `DataUser`'s machine**

**`$ cd ~/data_capsule/data_user`**


At the directory `data_user`, run the `make` command to compile the source code.

`$ make`

> After the building process is finished, a program called `data_user_client` will be generated. A signed enclave image called `DataUserEnclave.signed` is also generated.


Run the script `./run_data_user_client.sh data_capsule_id data_capsule_file` to use a data capsule

`$ ./run_data_user_client.sh data_capsule_id data_capsule_file`

> Please refer to the following terminal recording at https://asciinema.org/a/435678 on how to use a data capsule.

#!/bin/bash

# Set up Open Enclave with DCAP support on Ubuntu 20.04 
#  - https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/NonAccMachineSGXLinuxGettingStarted.md
#  - https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_20.04.md


# 1. Configure the Intel and Microsoft APT repositories
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-focal-10.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt update -y 


# 2. Install Intel SGX DCAP Driver
sudo apt install linux-image-5.13.0-1010-oem
# Optional: If you intend to run an SGX application that loads an enclave requiring 
# the Provision Key Access, the user needs to be added to the group "sgx_prv". 
# Applications that obtain a quote from the DCAP Quote Generation library for the 
# purposes of remote attestation may require Provision Key Access.
sudo usermod -aG sgx_prv $(whoami)


# 3. Install Open Enclave
sudo apt install -y clang-10 libssl-dev gdb libprotobuf17 
sudo apt install -y open-enclave  


# 4. Install Intel DCAP Quote Provider Library
sudo apt purge -y az-dcap-client 
sudo apt install -y libsgx-dcap-default-qpl 
# Create a soft link (named libdcap_quoteprov.so) to libdcap_quoteprov.so.x.yy.zzz.v 
# TODO: get the version number automatically
pushd /usr/lib/x86_64-linux-gnu
sudo rm -f libdcap_quoteprov.so
sudo ln -s libdcap_quoteprov.so.1.11.100.2 libdcap_quoteprov.so
popd 
# Configure the qpl 
echo -e "\n=========================================================================================="
echo -e "1. Please double-check libdcap_quoteprov.so.1.11.100.2 matches \n   the version in /usr/lib/x86_64-linux-gnu"
echo -e "2. Please configure the qpl: /etc/sgx_default_qcnl.conf"
echo -e "     PCCS_URL=https://10.0.0.80:8081/sgx/certification/v3/"
echo -e "     USE_SECURE_CERT=FALSE"
echo -e "   Then, use the attestation sample in Open Enclave to verify OE remote attestation works."
echo -e "=========================================================================================="

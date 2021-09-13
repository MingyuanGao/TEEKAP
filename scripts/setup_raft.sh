#!/bin/bash

sudo apt update
sudo apt install -y cmake openssl libssl-dev zlib1g-dev git g++
rm -rf nuraft
git clone https://github.com/eBay/NuRaft.git nuraft
pushd nuraft
./prepare.sh
mkdir build
pushd build
cmake ../
make -j8
sudo make install
popd
popd
sudo ldconfig /usr/local/lib
rm -rf nuraft

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk
OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB
	

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

enclave_name = data_user_enclave

all:
	$(MAKE) genkey
	$(MAKE) -C ../../access_committee/enclave/ genkey
	$(MAKE) build
	$(MAKE) sign

#private.pem:
#	openssl genrsa -out $@ -3 3072
#
#public.pem: private.pem
#	openssl rsa -in $< -out $@ -pubout

# The enclaves in the sample will check if the other enclave is signed
# with the expected key. Since this sample builds both enclaves, we can
# inject the expected public keys at build time.
#
# If the other public key isn't known, then we would have to load the
# public key from the host. We can't simply load the raw public key since
# a malicious host might change it. So, we would need to load a certicate
# that contains the expected public key that is signed by a trusted CA.
genkey: public.pem
	../gen_pubkey_header.sh ../../access_committee/enclave/enclave_a_pubkey.h $<

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../datauser.edl --trusted --trusted-dir ../common \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I../../../include -I. -I.. -std=c++11 -DOE_API_VERSION=2 ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/datauser_t.c
	$(CXX) -o $(enclave_name) attestation.o crypto.o ecalls.o dispatcher.o datauser_t.o $(LDFLAGS) $(CRYPTO_LDFLAGS) ../../sss/libsss.a 



sign:
	oesign sign -e $(enclave_name) -c enc.conf -k private.pem

clean:
	rm -f *.o $(enclave_name) $(enclave_name).signed ../common/datauser_t.* ../common/datauser_args.h enclave_b_pubkey.h

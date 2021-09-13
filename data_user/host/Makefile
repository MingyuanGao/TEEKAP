# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../datauser.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) datauser_u.c
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++17 main.cpp
	$(CXX) -o data_user_client main.o datauser_u.o ../libDataUser.a ../../sss/libsss.a $(LDFLAGS)  

clean:
	rm -f data_user_client *.o datauser_u.*  datauser_args.h

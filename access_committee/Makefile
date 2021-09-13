# Makefile for the Data Capsule project

app_name = access_committee_node
app_objs = main.o logger.o in_memory_log_store.o host/juryenclave_u.o 
app_libs = -L/usr/lib/ -lboost_system -lboost_serialization -lnuraft -lssl -pthread

enclave_name = JuryEnclave.signed


include config.mk
OE_CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
OE_CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
OE_LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
OE_INCDIR=$(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)


#CFLAGS = -std=c11 -DSUPPORT_SINGLE_MACHINE_CLUSTER  
#CXXFLAGS = -std=c++17 -DSUPPORT_SINGLE_MACHINE_CLUSTER  
CFLAGS = -std=c11 -DSUPPORT_SINGLE_MACHINE_CLUSTER -DDEBUG_LOG  
CXXFLAGS = -std=c++17 -DSUPPORT_SINGLE_MACHINE_CLUSTER -DDEBUG_LOG  


###############################
OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

.PHONY: prerequisite

all: prerequisite $(app_name) $(enclave_name)
	@echo "=============="
	@echo "Building done!"
	@echo "=============="

prerequisite: 
	make -C host

$(app_name): $(app_objs)
	g++ -o $@ $^ $(app_libs) $(OE_LDFLAGS)

main.o: main.cpp tcp_server.hpp raft_server.hpp
	$(CXX) -c -fPIE  $(CXXFLAGS) $(OE_CXXFLAGS) $(INCLUDES) -std=c++17 $<

$(enclave_name):
	make -C enclave	
	cp enclave/jury_enclave.signed $(enclave_name) 


###############################
# Rules
%.o : %.c
	gcc $(CFLAGS) -c $< -o $@

%.o : %.cpp
	g++ $(CXXFLAGS)  -c $< -o $@

%.o : %.cxx
	g++ $(CXXFLAGS)  -c $< -o $@

%.o : %.cc
	g++ $(CXXFLAGS) -c $< -o $@


###############################
.PHONY: clean
clean:
	rm -f $(app_name) $(app_objs) $(enclave_name) 
	make clean -C host
	make clean -C enclave 


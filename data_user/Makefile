# Makefile for the Data Capsule project

api_lib = libDataUser.a
api_lib_objs = api.o 

app_name = data_user_client

enclave_name = DataUserEnclave.signed

#CFLAGS = -std=c11 
#CXXFLAGS = -std=c++17 -fpermissive 
CFLAGS = -std=c11 -DDEBUG_LOG 
CXXFLAGS = -std=c++17 -fpermissive -DDEBUG_LOG

OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

###############################

all: $(api_lib) $(app_name) $(enclave_name) 
	@echo "=============="
	@echo "Building done!"
	@echo "=============="

$(api_lib): $(api_lib_objs)  
	ar rvs $(api_lib) $(api_lib_objs)

$(app_name):
	make -C host
	cp host/data_user_client $(app_name)

$(enclave_name): 
	make -C enclave
	cp enclave/data_user_enclave.signed $(enclave_name)


###############################
# Rules
%.o : %.c
	gcc $(CFLAGS) -c $< -o $@

%.o : %.cpp
	g++ $(CXXFLAGS) -c $< -o $@


###############################
.PHONY: clean
clean:
	rm -f $(api_lib) $(api_lib_objs) $(app_name) $(enclave_name) 
	make clean -C host
	make clean -C enclave

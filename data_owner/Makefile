# Makefile for the Data Capsule project

api_lib = libDataOwner.a
api_lib_objs = api.o 

app_name = data_owner_client
app_objs = main.o
app_libs = -L/usr/lib/x86_64-linux-gnu/ -lboost_system -pthread -lcrypto -lssl ../sss/libsss.a

app2_name = sss_test
app2_objs = sss_test.o
app2_libs = ../sss/libsss.a

#CFLAGS = -std=c11
#CXXFLAGS = -std=c++17 -fpermissive
CFLAGS = -std=c11                  -DDEBUG_LOG  
CXXFLAGS = -std=c++17 -fpermissive -DDEBUG_LOG 


###############################
all: $(api_lib) $(app_name) $(app2_name)
	@echo "=============="
	@echo "Building done!"
	@echo "=============="

$(api_lib): $(api_lib_objs)  
	ar rvs $(api_lib) $(api_lib_objs)

$(app_name): $(app_objs) $(api_lib)  
	g++ -o $@ $^ $(api_lib) $(app_libs)  

$(app2_name): $(app2_objs)
	g++ $(CXX_FLAGS) -o $@ $< $(app2_libs)

###############################
# Rules
%.o : %.c
	gcc $(CFLAGS) -c $< -o $@

%.o : %.cpp
	g++ $(CXXFLAGS) -c $< -o $@

###############################
.PHONY: clean
clean:
	rm -f $(api_lib) $(api_lib_objs) 
	rm -f $(app_name) $(app_objs) 
	rm -f $(app2_name) $(app2_objs) 


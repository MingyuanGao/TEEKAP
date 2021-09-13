#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <stdio.h>

#include "../include/json.hpp"
using json = nlohmann::json;

#include <libnuraft/nuraft.hxx>
using namespace nuraft;

#include "dc_state_machine.hxx"
#include "in_memory_state_mgr.hxx"
#include "logger_wrapper.hxx"
#include "test_common.h"

namespace dc_server {

static const raft_params::return_method_type CALL_TYPE
    = raft_params::blocking;
//  = raft_params::async_handler;

using raft_result = cmd_result< ptr<buffer> >;

struct server_stuff {
    server_stuff()
        : server_id_(1)
        , addr_("localhost")
        , port_(25000)
        , raft_logger_(nullptr)
        , sm_(nullptr)
        , smgr_(nullptr)
        , raft_instance_(nullptr)
        {}

    void reset() {
        raft_logger_.reset();
        sm_.reset();
        smgr_.reset();
        raft_instance_.reset();
    }

    // Server ID.
    int server_id_;

    // Server address.
    std::string addr_;

    // Server port.
    int port_;

    // Endpoint: `<addr>:<port>`.
    std::string endpoint_;

    // Logger.
    ptr<logger> raft_logger_;

    // State machine.
    ptr<state_machine> sm_;

    // State manager.
    ptr<state_mgr> smgr_;

    // Raft launcher.
    raft_launcher launcher_;

    // Raft server instance.
    ptr<raft_server> raft_instance_;
};

static server_stuff stuff;

void add_server(const std::string& cmd,
                const std::vector<std::string>& tokens)
{
    if (tokens.size() < 3) {
        std::cout << "too few arguments" << std::endl;
        return;
    }

    int server_id_to_add = atoi(tokens[1].c_str());
    if ( !server_id_to_add || server_id_to_add == stuff.server_id_ ) {
        std::cout << "wrong server id: " << server_id_to_add << std::endl;
        return;
    }

    std::string endpoint_to_add = tokens[2];
    srv_config srv_conf_to_add( server_id_to_add, endpoint_to_add );
    ptr<raft_result> ret = stuff.raft_instance_->add_srv(srv_conf_to_add);
    if (!ret->get_accepted()) {
        std::cout << "failed to add server: "
                  << ret->get_result_code() << std::endl;
        return;
    }
    std::cout << "async request is in progress (check with `list` command)"
              << std::endl;
}

void server_list(const std::string& cmd,
                 const std::vector<std::string>& tokens)
{
    std::vector< ptr<srv_config> > configs;
    stuff.raft_instance_->get_srv_config_all(configs);

    int leader_id = stuff.raft_instance_->get_leader();

    for (auto& entry: configs) {
        ptr<srv_config>& srv = entry;
        std::cout
            << "server id " << srv->get_id()
            << ": " << srv->get_endpoint();
        if (srv->get_id() == leader_id) {
            std::cout << " (LEADER)";
        }
        std::cout << std::endl;
    }
}

bool do_cmd(const std::vector<std::string>& tokens);

std::vector<std::string> tokenize(const char* str, char c = ' ') {
    std::vector<std::string> tokens;
    do {
        const char *begin = str;
        while(*str != c && *str) str++;
        if (begin != str) tokens.push_back( std::string(begin, str) );
    } while (0 != *str++);

    return tokens;
}

void init_raft(ptr<state_machine> sm_instance) {
    // Logger.
    std::string log_file_name = "./access_committee_node" +
                                std::to_string( stuff.server_id_ ) +
                                ".log";
    ptr<logger_wrapper> log_wrap = cs_new<logger_wrapper>( log_file_name, 4 );
    stuff.raft_logger_ = log_wrap;

    // State machine.
    stuff.smgr_ = cs_new<inmem_state_mgr>( stuff.server_id_,
                                           stuff.endpoint_ );
    // State manager.
    stuff.sm_ = sm_instance;

    // ASIO options.
    asio_service::options asio_opt;
    asio_opt.thread_pool_size_ = 4;

    // Raft parameters.
    raft_params params;
#if defined(WIN32) || defined(_WIN32)
    // heartbeat: 1 sec, election timeout: 2 - 4 sec.
    params.heart_beat_interval_ = 1000;
    params.election_timeout_lower_bound_ = 2000;
    params.election_timeout_upper_bound_ = 4000;
#else
    // heartbeat: 100 ms, election timeout: 200 - 400 ms.
    params.heart_beat_interval_ = 100;
    params.election_timeout_lower_bound_ = 200;
    params.election_timeout_upper_bound_ = 400;
#endif
    // Upto 5 logs will be preserved ahead the last snapshot.
    params.reserved_log_items_ = 5;
    // Snapshot will be created for every 5 log appends.
    params.snapshot_distance_ = 5;
    // Client timeout: 3000 ms.
    params.client_req_timeout_ = 3000;
    // According to this method, `append_log` function
    // should be handled differently.
    params.return_method_ = CALL_TYPE;

    // Initialize Raft server.
    stuff.raft_instance_ = stuff.launcher_.init(stuff.sm_,
                                                stuff.smgr_,
                                                stuff.raft_logger_,
                                                stuff.port_,
                                                asio_opt,
                                                params);
    if (!stuff.raft_instance_) {
        std::cerr << "Failed to initialize launcher (see the message "
                     "in the log file)." << std::endl;
        log_wrap.reset();
        exit(-1);
    }

    // Wait until Raft server is ready (upto 5 seconds).
    const size_t MAX_TRY = 20;
    std::cout << "Initialize Raft instance ";
    for (size_t ii=0; ii<MAX_TRY; ++ii) {
        if (stuff.raft_instance_->is_initialized()) {
            std::cout << " done" << std::endl;
            return;
        }
        std::cout << ".";
        fflush(stdout);
        TestSuite::sleep_ms(250);
    }
    std::cout << " FAILED" << std::endl;
    log_wrap.reset();
    exit(-1);
}

calc_state_machine* get_sm() {
    return static_cast<calc_state_machine*>( stuff.sm_.get() );
}

void handle_result(ptr<TestSuite::Timer> timer,
                   raft_result& result,
                   ptr<std::exception>& err)
{
    if (result.get_result_code() != cmd_result_code::OK) {
        // Something went wrong.
        // This means committing this log failed,
        // but the log itself is still in the log store.
        std::cout << "failed: " << result.get_result_code() << ", "
                  << TestSuite::usToString( timer->getTimeUs() )
                  << std::endl;
        return;
    }
   	
	
	ptr<buffer> buf = result.get();
    uint64_t ret_value = buf->get_ulong();
	std::cout << "succeeded, "
              << TestSuite::usToString( timer->getTimeUs() )
              << ", return value: "
              << ret_value
              << ", state machine value: "
              << get_sm()->get_current_value()
              << std::endl;

	#ifdef TEST_CONSENSUS_TIME
	std::string time_string = TestSuite::usToString( timer->getTimeUs() );
	//std::cout << "append_entries() took " << time_string << "\n";
	std::ofstream ofs("consensus.log", std::iostream::app);
	ofs << time_string << "\n" ;
	#endif
}

void print_status(const std::string& cmd,
                  const std::vector<std::string>& tokens)
{
    ptr<log_store> ls = stuff.smgr_->load_log_store();
    std::cout
        << "my server id: " << stuff.server_id_ << std::endl
        << "leader id: " << stuff.raft_instance_->get_leader() << std::endl
        << "Raft log range: "
            << ls->start_index()
            << " - " << (ls->next_slot() - 1) << std::endl
        << "last committed index: "
            << stuff.raft_instance_->get_committed_log_idx() << std::endl
        << "state machine value: "
            << get_sm()->get_current_value() << std::endl;
}

void help(const std::string& cmd,
          const std::vector<std::string>& tokens)
{
    std::cout
    << "modify value: <+|-|*|/><operand>\n"
    << "    +: add <operand> to state machine's value.\n"
    << "    -: subtract <operand> from state machine's value.\n"
    << "    *: multiple state machine'value by <operand>.\n"
    << "    /: divide state machine's value by <operand>.\n"
    << "    e.g.) +123\n"
    << "\n"
    << "add server: add <server id> <address>:<port>\n"
    << "    e.g.) add 2 127.0.0.1:20000\n"
    << "\n"
    << "get current server status: st (or stat)\n"
    << "\n"
    << "get the list of members: ls (or list)\n"
    << "\n";
}

bool do_cmd(const std::vector<std::string>& tokens) {
    if (!tokens.size()) return true;

    const std::string& cmd = tokens[0];

    if (cmd == "q" || cmd == "exit") {
        stuff.launcher_.shutdown(5);
        stuff.reset();
        return false;
	
	} else if ( cmd == "add" ) {
        // e.g.) add 2 localhost:12345
        add_server(cmd, tokens);

    } else if ( cmd == "st" || cmd == "stat" ) {
        print_status(cmd, tokens);

    } else if ( cmd == "ls" || cmd == "list" ) {
        server_list(cmd, tokens);

    } else if ( cmd == "h" || cmd == "help" ) {
        help(cmd, tokens);
    
	} else if ( cmd == "add_followers" ) {
		// this command is added just for doing experiments in a paper submission
		std::ifstream ifs("cluster.config");
		std::string line;
		
		while (std::getline(ifs, line)) {
    		// std::cout << line << std::endl;
			std::stringstream ss;
			ss << line;

			int server_id_to_add;
			std::string ip;
			ss >> server_id_to_add >> ip;
			// Skip itself
			if(ip == stuff.addr_ || server_id_to_add == stuff.server_id_ ) {
				continue;
			}

			//std::cout << "server_id = " << server_id_to_add << std::endl;
			//std::cout << "ip = " << ip << std::endl;
    		if ( !server_id_to_add ) {
        		std::cout << "wrong server id: " << server_id_to_add << std::endl;
    		}

			int port = 8000 + server_id_to_add;
			std::string endpoint_to_add = ip + ":" + std::to_string(port); 
			
    		srv_config srv_conf_to_add( server_id_to_add, endpoint_to_add );
    		ptr<raft_result> ret = stuff.raft_instance_->add_srv(srv_conf_to_add);
    		if (!ret->get_accepted()) {
        		std::cout << "failed to add server: "
                  << ret->get_result_code() << std::endl;
    		}
    		std::cout << "async request is in progress (check with `list` command)"
              << std::endl;

			sleep(1);
		}
	}
    
	return true;
}

}; // namespace dc_server 


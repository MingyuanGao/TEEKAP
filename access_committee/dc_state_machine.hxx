#pragma once

#include <iostream>
#include <fstream>
#include <atomic>
#include <cassert>
#include <mutex>
#include <string.h>
#include <chrono>

using namespace std::chrono;
using namespace std::literals::chrono_literals;

#include <libnuraft/nuraft.hxx>
using namespace nuraft;

#include "../include/json.hpp"
using json = nlohmann::json;

#include "../include/protocol.h"


namespace dc_server {

class calc_state_machine : public state_machine {
public:
    calc_state_machine(): cur_value_(0), last_committed_idx_(0) {  }

    ~calc_state_machine() {  }

   // enum op : int {
   //     INIT  = 0x0,
   //     USE   = 0x1,
   //     RESET = 0x2
   // };

   // struct op_payload {
   //     op_type type_;
   //     int operand_;
   // };

   // static ptr<buffer> enc_log(const op_payload& payload) {
   //     // Encode from {operator, operand} to Raft log.
   //     ptr<buffer> ret = buffer::alloc(sizeof(op_payload));
   //     buffer_serializer bs(ret);

   //     // WARNING: We don't consider endian-safety in this example.
   //     bs.put_raw(&payload, sizeof(op_payload));

   //     return ret;
   // }

   // static void dec_log(buffer& log, op_payload& payload_out) {
   //     // Decode from Raft log to {operator, operand} pair.
   //     assert(log.size() == sizeof(op_payload));

   //     buffer_serializer bs(log);
   //     memcpy(&payload_out, bs.get_raw(log.size()), sizeof(op_payload));
   // }

    ptr<buffer> pre_commit(const ulong log_idx, buffer& data) {
		std::cout << "pre-commit: log_idx = " << log_idx << std::endl;

		return nullptr;
    }

    ptr<buffer> commit(const ulong log_idx, buffer& data) {
       /* 
		op_payload payload;
        dec_log(data, payload);
        //int64_t prev_value = cur_value_;
		switch (payload.type_) {
			case INIT: 
			       	std::cerr << "payload.type_ = " << payload.type_ << std::endl 
						<< "payload.operand_ = " << payload.operand_ << std::endl;
					break;
			case USE:  
				    std::cerr << "payload.type_ = " << payload.type_ << std::endl 
						<< "payload.operand_ = " << payload.operand_ << std::endl;
					break;
			
			case RESET: 
				    std::cerr << "payload.type_ = " << payload.type_ << std::endl 
						<< "payload.operand_ = " << payload.operand_ << std::endl;
					break;
        }
        //cur_value_ = prev_value;
		*/ 

		std::cout << "commit: log_idx = " << log_idx << std::endl;
		
		// Extract fields from 'data'
		buffer_serializer bs_data(data);
		std::string cmd = bs_data.get_str();	
		
		if(cmd == req_create_dc_policy) {
			std::string dc_config_json_string = bs_data.get_str();
			
			json dc = json::parse(dc_config_json_string);
		
			std::string dc_id = dc["dc_id"];
			std::string mrsigner = dc["mrsigner"];
			std::string mrenclave = dc["mrenclave"];
			int access_limit = dc["access_limit"];
			std::time_t access_expiry = dc["access_expiry"];

			#ifdef DEBUG_LOG
			std::cout << "  cmd = " << req_create_dc_policy << std::endl
			          << "  dc_id = " << dc_id << std::endl
				      << "  mrsigner = " << mrsigner << std::endl
				      << "  mrenclave = " << mrenclave << std::endl
				      << "  access_limit  = " << access_limit << std::endl
				      << "  access_expiry = " << access_expiry << std::endl;
			#endif

			/////////////////////////////////
			json dc_existing;	
			std::string db_file = "./database/" + dc_id;
			
			std::ifstream dc_ifs(db_file);
			if(!dc_ifs) {
				std::cerr << "No entry exists, will create a new entry!" << std::endl;
			} else {
				dc_ifs >> dc_existing;
			}
			dc_existing["dc_id"] = dc_id;	
			dc_existing["mrsigner"] = mrsigner;	
			dc_existing["mrenclave"] = mrenclave;	
			dc_existing["access_limit"] = access_limit;	
			dc_existing["access_expiry"] = access_expiry;	

			std::ofstream dc_ofs(db_file);
			dc_ofs << dc_existing.dump(4);
		} // end of if(cmd == req_create_dc_policy) 
		
		if( cmd == req_access_dc ) {
			// decrement the access_limit
			std::string dc_id_token_jstr = bs_data.get_str();
			json dc_id_token = json::parse(dc_id_token_jstr);
			std::string dc_id = dc_id_token["dc_id"];
			std::string token = dc_id_token["token"];
			
			#ifdef DEBUG_LOG
			std::cout << "  cmd = " << req_access_dc << std::endl
			          << "  dc_id = " << dc_id << std::endl
			          << "  token = " << std::stol(token) << std::endl;
			#endif


			/////////////////////////////////
			json dc_existing;	
			std::string db_file = "./database/" + dc_id;
			
			std::ifstream dc_ifs(db_file);
			if(!dc_ifs) {
				std::cerr << "No data capsule with such id exists!" << std::endl;
			} else {
				dc_ifs >> dc_existing ;
			}
			int access_limit = dc_existing["access_limit"];
			access_limit--;
			dc_existing["access_limit"] = access_limit;
			
			// We simplify a little bit by saving the "token" to a file
			dc_existing["token"] = token;
			std::ofstream dc_ofs(db_file);
			dc_ofs << dc_existing.dump(4);
		} // end of if(cmd == req_access_dc) 
		

		//////////////////////////////////////////////

		last_committed_idx_ = log_idx;

        // Return Raft log number as a return result.
        ptr<buffer> ret = buffer::alloc( sizeof(log_idx) );
        buffer_serializer bs(ret);
        bs.put_u64(log_idx);
		
		return ret;
    }

    void rollback(const ulong log_idx, buffer& data) {
        // Nothing to do with rollback,
        // as this example doesn't do anything on pre-commit.
    }

    int read_logical_snp_obj(snapshot& s,
                             void*& user_snp_ctx,
                             ulong obj_id,
                             ptr<buffer>& data_out,
                             bool& is_last_obj)
    {
        ptr<snapshot_ctx> ctx = nullptr;
        {   std::lock_guard<std::mutex> ll(snapshots_lock_);
            auto entry = snapshots_.find(s.get_last_log_idx());
            if (entry == snapshots_.end()) {
                // Snapshot doesn't exist.
                data_out = nullptr;
                is_last_obj = true;
                return 0;
            }
            ctx = entry->second;
        }

        if (obj_id == 0) {
            // Object ID == 0: first object, put dummy data.
            data_out = buffer::alloc( sizeof(int32) );
            buffer_serializer bs(data_out);
            bs.put_i32(0);
            is_last_obj = false;

        } else {
            // Object ID > 0: second object, put actual value.
            data_out = buffer::alloc( sizeof(ulong) );
            buffer_serializer bs(data_out);
            bs.put_u64( ctx->value_ );
            is_last_obj = true;
        }
        return 0;
    }

    void save_logical_snp_obj(snapshot& s,
                              ulong& obj_id,
                              buffer& data,
                              bool is_first_obj,
                              bool is_last_obj)
    {
        if (obj_id == 0) {
            // Object ID == 0: it contains dummy value, create snapshot context.
            create_snapshot_internal(s);

        } else {
            // Object ID > 0: actual snapshot value.
            buffer_serializer bs(data);
            int64_t local_value = (int64_t)bs.get_u64();

            std::lock_guard<std::mutex> ll(snapshots_lock_);
            auto entry = snapshots_.find(s.get_last_log_idx());
            assert(entry != snapshots_.end());
            entry->second->value_ = local_value;
        }
        // Request next object.
        obj_id++;
    }

    bool apply_snapshot(snapshot& s) {
        std::lock_guard<std::mutex> ll(snapshots_lock_);
        auto entry = snapshots_.find(s.get_last_log_idx());
        if (entry == snapshots_.end()) return false;

        ptr<snapshot_ctx> ctx = entry->second;
        cur_value_ = ctx->value_;
        return true;
    }

    void free_user_snp_ctx(void*& user_snp_ctx) {
        // In this example, `read_logical_snp_obj` doesn't create
        // `user_snp_ctx`. Nothing to do in this function.
    }

    ptr<snapshot> last_snapshot() {
        // Just return the latest snapshot.
        std::lock_guard<std::mutex> ll(snapshots_lock_);
        auto entry = snapshots_.rbegin();
        if (entry == snapshots_.rend()) return nullptr;

        ptr<snapshot_ctx> ctx = entry->second;
        return ctx->snapshot_;
    }

    ulong last_commit_index() {
        return last_committed_idx_;
    }

    void create_snapshot(snapshot& s,
                         async_result<bool>::handler_type& when_done)
    {
        {   std::lock_guard<std::mutex> ll(snapshots_lock_);
            create_snapshot_internal(s);
        }
        ptr<std::exception> except(nullptr);
        bool ret = true;
        when_done(ret, except);
    }

    int64_t get_current_value() const { return cur_value_; }

private:
    struct snapshot_ctx {
        snapshot_ctx( ptr<snapshot>& s, int64_t v )
            : snapshot_(s), value_(v) {}
        ptr<snapshot> snapshot_;
        int64_t value_;
    };

    void create_snapshot_internal(snapshot& s) {
        // Clone snapshot from `s`.
        ptr<buffer> snp_buf = s.serialize();
        ptr<snapshot> ss = snapshot::deserialize(*snp_buf);

        // Put into snapshot map.
        ptr<snapshot_ctx> ctx = cs_new<snapshot_ctx>(ss, cur_value_);
        snapshots_[s.get_last_log_idx()] = ctx;

        // Maintain last 3 snapshots only.
        const int MAX_SNAPSHOTS = 3;
        int num = snapshots_.size();
        auto entry = snapshots_.begin();
        for (int ii = 0; ii < num - MAX_SNAPSHOTS; ++ii) {
            if (entry == snapshots_.end()) break;
            entry = snapshots_.erase(entry);
        }
    }

    // State machine's current value.
    std::atomic<int64_t> cur_value_;
	
	#ifdef TEST_THROUGHPUT	
	std::atomic<int64_t> num_req;	
	time_point<high_resolution_clock, microseconds> start;
	time_point<high_resolution_clock, microseconds> stop;
	#endif

	// Last committed Raft log number.
    std::atomic<uint64_t> last_committed_idx_;

    // Keeps the last 3 snapshots, by their Raft log numbers.
    std::map< uint64_t, ptr<snapshot_ctx> > snapshots_;

    // Mutex for `snapshots_`.
    std::mutex snapshots_lock_;
};

}; // namespace dc_server

// Data Capsule Protocol

#pragma once

// Common
std::string status_error   =  "dc_status_error";
std::string status_ok      =  "dc_status_ok";

// Storage Server
std::string req_upload_file   = "request_upload_file";
std::string req_download_file = "request_download_file";

// Access Committee
std::string req_cluster_config    = "request_cluster_config";
std::string req_create_dc_key     = "request_upload_key_shares";
std::string req_create_dc_policy  = "request_upload_access_policy";
std::string req_access_dc  =  "request_access_data_capsule";
std::string req_key_share  =  "request_key_share";
std::string req_enclave_evidence = "request_enclave_evidence_with_public_key";
std::string req_send_ciphertext = "request_send_ciphertext";

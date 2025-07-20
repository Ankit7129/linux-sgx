#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <sstream>
#include <functional>
#include <sgx_urts.h>
#include "Enclave_u.h"
#include <ctime>
#include <unistd.h>
#include <sys/utsname.h>
#include <iomanip>
#include <cstdlib>

#define ENCLAVE_FILE "enclave.signed.so"

sgx_enclave_id_t global_eid = 0;
const std::string vec_path = "/home/ankit/data/vector1.enc";
std::vector<uint8_t> global_data;

// Note time 


void ocall_get_time_micro(long* time_in_us) {
    auto now = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    *time_in_us = us;
}

void ocall_log_json(const char* json_str) {
    // Step 1: Save JSON string to summary_ms.json
    const char* path = "/home/ankit/data/summary_ms.json";
    std::ofstream out(path);
    if (out.is_open()) {
        out << json_str;
        out.close();
        printf("📄 JSON Summary (ms) saved to %s ✅\n", path);
    } else {
        printf("❌ Failed to open %s for writing.\n", path);
        return;
    }

    // Step 2: Optionally call Python for summary processing (optional)
    std::string json_arg = std::string(json_str);
    size_t pos = 0;
    while ((pos = json_arg.find('\'', pos)) != std::string::npos) {
        json_arg.replace(pos, 1, "'\"'\"'");
        pos += 5;
    }

    std::string cmd = "python3 /home/ankit/utils/log_combined_report.py '" + json_arg + "'";
    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        printf("⚠️ Python summary script failed with code %d.\n", ret);
    } else {
        printf("✅ Python summary script executed successfully.\n");
    }
}

// ✨ Reads key file into byte vector
std::vector<uint8_t> read_file(const char* path) {
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), {});
}

// ✅ Preload AES key into enclave
bool preload_key(const std::string& key_path) {
    auto key_data = read_file(key_path.c_str());
    if (key_data.size() != 16) {
        std::cerr << "❌ AES key must be 16 bytes\n";
        return false;
    }

    sgx_status_t status;
    sgx_status_t ret = ecall_preload_key_into_enclave(global_eid, &status, key_data.data(), 16);
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        std::cerr << "❌ Failed to preload key into enclave\n";
        return false;
    }

    std::cout << "✅ AES-GCM key preloaded into enclave successfully\n";
    return true;
}

void ocall_print_string(const char* str) {
    std::printf("%s", str);
}

void print_error_message(sgx_status_t ret) {
    std::cerr << "SGX error: 0x" << std::hex << ret << std::endl;
}

int initialize_enclave() {
    sgx_status_t ret = sgx_create_enclave(
        ENCLAVE_FILE, SGX_DEBUG_FLAG, nullptr, nullptr, &global_eid, nullptr);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

void ocall_get_file_info(size_t* file_size) {
    std::ifstream file(vec_path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "❌ Could not open file\n";
        *file_size = 0;
        return;
    }
    *file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    global_data.resize(*file_size);
    file.read(reinterpret_cast<char*>(global_data.data()), *file_size);
    std::cout << "📁 File to preloaded: " << *file_size << " bytes\n";
}

void ocall_read_chunk(uint8_t* buffer, size_t buf_size, size_t offset) {
    if (offset + buf_size > global_data.size()) {
        std::cerr << "❌ Invalid read: offset=" << offset << " size=" << buf_size << "\n";
        return;
    }
    memcpy(buffer, global_data.data() + offset, buf_size);
}



void run_enclave_memory_tests() {
    sgx_status_t status;
    printf("🔍 Testing heap allocation in enclave...\n");
    status = ecall_test_heap_allocation(global_eid);
    if (status != SGX_SUCCESS) {
        printf("❌ ecall_test_heap_allocation failed (0x%x)\n", status);
    }

   /* printf("🔍 Testing max chunk allocation in enclave...\n");
    status = ecall_test_max_chunk_buffer(global_eid);
    if (status != SGX_SUCCESS) {
        printf("❌ ecall_test_max_chunk_buffer failed (0x%x)\n", status);
    }*/
}


FILE* plain_file = nullptr;

void ocall_write_plain_chunk(uint8_t* plaintext, size_t len, size_t offset) {
    if (!plain_file) {
        // Open decrypted output file once
        plain_file = fopen("/home/ankit/data/vector1.dec.txt", "wb");
        if (!plain_file) {
            printf("❌ Failed to open decrypted output file\n");
            return;
        }
    }

    // Write at end (append)
    size_t written = fwrite(plaintext, 1, len, plain_file);
    if (written != len) {
        printf("❌ Write error in ocall_write_plain_chunk\n");
    }

    fflush(plain_file); // optional, to flush immediately
}

// e.g., in App.cpp or OCALL file
void ocall_get_epc_free_kb(size_t* epc_kb) {
    *epc_kb = 0;
    FILE* f = fopen("/sys/devices/system/node/node0/epc/epc0/free_kb", "r");
    if (f) {
        fscanf(f, "%zu", epc_kb);
        fclose(f);
    }
}

int main(int argc, char* argv[]) {
    if (initialize_enclave() < 0) return -1;

    if (argc >= 3 && std::string(argv[1]) == "preload_key") {
        const std::string key_path = argv[2];
        if (!preload_key(key_path)) {
          //  sgx_destroy_enclave(global_eid);
            return 1;
        }
        // Do NOT destroy enclave here so key remains loaded
    }

    // Load vector (or run other functions) inside the same enclave instance
   ecall_start_vector_load(global_eid);
   //ecall_SGX_Memory_Analysis(global_eid);
    //ecall_start_vector_load_size_test(global_eid);
     // Optionally: run_enclave_memory_tests();
   //
   //run_enclave_memory_tests();
    // Destroy enclave only once all processing is done
    sgx_destroy_enclave(global_eid);
    return 0;
}

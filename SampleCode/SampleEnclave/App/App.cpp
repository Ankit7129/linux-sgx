#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* SGX error handling */
void print_sgx_error(sgx_status_t ret) {
    switch (ret) {
        case SGX_ERROR_ENCLAVE_LOST:       std::cerr << "SGX_ERROR_ENCLAVE_LOST"; break;
        case SGX_ERROR_INVALID_PARAMETER:  std::cerr << "SGX_ERROR_INVALID_PARAMETER"; break;
        case SGX_ERROR_OUT_OF_MEMORY:      std::cerr << "SGX_ERROR_OUT_OF_MEMORY"; break;
        case SGX_ERROR_UNEXPECTED:        std::cerr << "SGX_ERROR_UNEXPECTED"; break;
        case SGX_ERROR_INVALID_ENCLAVE:    std::cerr << "SGX_ERROR_INVALID_ENCLAVE"; break;
        case SGX_ERROR_INVALID_ENCLAVE_ID: std::cerr << "SGX_ERROR_INVALID_ENCLAVE_ID"; break;
        case SGX_ERROR_INVALID_VERSION:   std::cerr << "SGX_ERROR_INVALID_VERSION"; break;
        case SGX_ERROR_MEMORY_MAP_FAILURE: std::cerr << "SGX_ERROR_MEMORY_MAP_FAILURE"; break;
        default: std::cerr << "Unknown SGX error: 0x" << std::hex << ret; break;
    }
}

/* Initialize the enclave */
int initialize_enclave(void) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        std::cerr << "❌ Enclave creation failed: ";
        print_sgx_error(ret);
        std::cerr << std::endl;
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str) {
    printf("%s", str);
}
void read_hello_file_and_send_to_sgx() {
    const char* filepath = "/home/ankit/data/vector2.txt";
    std::ifstream infile(filepath, std::ios::binary);
    if (!infile) {
        std::cerr << "Error: Cannot open file " << filepath << std::endl;
        return;
    }

    std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(infile)),
                                   std::istreambuf_iterator<char>());
    infile.close();

    sgx_status_t ret = ecall_process_file(global_eid, file_data.data(), file_data.size());
    if (ret != SGX_SUCCESS) {
        std::cerr << "ECALL failed with error: " << std::hex << ret << std::endl;
    }
}


void load_vectors_and_add_in_sgx() {
    const char* path1 = "/home/ankit/data/vector1.txt";
    const char* path2 = "/home/ankit/data/vector2.txt";

    std::ifstream file1(path1), file2(path2);
    if (!file1 || !file2) {
        std::cerr << "❌ Failed to open one or both vector files.\n";
        return;
    }

    std::vector<uint8_t> vec1, vec2;
    int val;

    while (file1 >> val) vec1.push_back(static_cast<uint8_t>(val));
    while (file2 >> val) vec2.push_back(static_cast<uint8_t>(val));

    file1.close(); file2.close();

    if (vec1.size() != vec2.size()) {
        std::cerr << "❌ Vectors must be of same size!\n";
        return;
    }

    sgx_status_t ret = ecall_add_vectors(global_eid, vec1.data(), vec2.data(), vec1.size());
    if (ret != SGX_SUCCESS) {
        std::cerr << "❌ ECALL failed: " << std::hex << ret << std::endl;
    }
}

int main(int argc, char *argv[]) {
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if (initialize_enclave() < 0) {
        std::cerr << "❌ Enclave initialization failed" << std::endl;
        return -1;
    }

    /* Test enclave functionality */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();

    /* Run our custom functions */
   // read_hello_file_and_send_to_sgx();
    load_vectors_and_add_in_sgx();
   // load_vectors_and_send_to_sgx();
    /* Cleanup */
    sgx_destroy_enclave(global_eid);
    std::cout << "✅ Enclave operations completed successfully" << std::endl;
    return 0;
}
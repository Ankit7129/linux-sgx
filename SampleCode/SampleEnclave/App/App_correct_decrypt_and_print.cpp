#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <sgx_urts.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"
#define CHUNK_SIZE (1 << 20)  // 1MB chunks (~65,536 blocks)

sgx_enclave_id_t global_eid = 0;

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

std::vector<uint8_t> read_file(const char* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error(std::string("Cannot open: ") + path);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file");
    }
    return buffer;
}

void decrypt_and_print() {
    try {
        const char* key_path = "/home/ankit/data/aes_key.bin";
        const char* nonce_path = "/home/ankit/data/aes_nonce1.bin";
        const char* vec_path = "/home/ankit/data/vector1.enc";

        auto key = read_file(key_path);
        auto nonce = read_file(nonce_path);
        auto enc_data = read_file(vec_path);

        const size_t block_size = 16;
        const size_t total_blocks = (enc_data.size() + block_size - 1) / block_size;
        const size_t blocks_per_chunk = CHUNK_SIZE / block_size;

        std::cout << "Starting decryption of " << total_blocks << " blocks...\n";

        for (size_t start_block = 0; start_block < total_blocks; start_block += blocks_per_chunk) {
            size_t end_block = std::min(start_block + blocks_per_chunk, total_blocks);
            size_t byte_offset = start_block * block_size;
            size_t byte_count = (end_block - start_block) * block_size;
            byte_count = std::min(byte_count, enc_data.size() - byte_offset);

            int retval = 0;
            sgx_status_t ret = ecall_decrypt_and_print_range(
                global_eid, &retval,
                enc_data.data() + byte_offset, byte_count,
                key.data(), key.size(),
                nonce.data(), nonce.size(),
                start_block, end_block);

            if (ret != SGX_SUCCESS || retval != 0) {
                std::cerr << "Error processing blocks " << start_block 
                          << " to " << end_block << std::endl;
                break;
            }

            // Progress reporting
            if (start_block % (100 * blocks_per_chunk) == 0) {
                std::cout << "Progress: " << (100 * start_block / total_blocks) 
                          << "% (" << start_block << "/" << total_blocks << " blocks)\n";
            }
        }
        std::cout << "Decryption complete!\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}


int main() {
    if (initialize_enclave() < 0) return -1;
    decrypt_and_print();
    sgx_destroy_enclave(global_eid);
    return 0;
}
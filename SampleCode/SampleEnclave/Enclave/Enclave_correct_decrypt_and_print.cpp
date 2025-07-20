#include "sgx_tcrypto.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <stdint.h>

#define PRINT_EVERY_N_BLOCKS 256  // Print every 256 blocks to reduce OCALLs

int printf(const char* fmt, ...) {
    char buf[BUFSIZ] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int ecall_decrypt_and_print_range(
    uint8_t* enc_buf, size_t buf_size,
    uint8_t* key, size_t key_size,
    uint8_t* nonce, size_t nonce_size,
    uint64_t start_block, uint64_t end_block)
{
    if (!enc_buf || !key || !nonce || key_size != 16 || nonce_size != 8)
        return -1;

    const size_t block_size = 16;
    sgx_aes_ctr_128bit_key_t aes_key;
    memcpy(&aes_key, key, 16);

    // Use dynamic buffer to handle partial blocks
    uint8_t* print_buf = new uint8_t[buf_size];
    size_t print_buf_count = 0;
    size_t total_bytes_processed = 0;

    for (uint64_t block_num = start_block; block_num < end_block; block_num++) {
        size_t offset = (block_num - start_block) * block_size;
        size_t bytes_remaining = buf_size - offset;
        size_t current_block_size = (bytes_remaining >= block_size) ? block_size : bytes_remaining;

        if (current_block_size == 0) break;

        // Prepare counter (nonce + block_num in big-endian)
        uint8_t counter[16] = {0};
        memcpy(counter, nonce, 8);
        for (int i = 0; i < 8; i++) {
            counter[15 - i] = (block_num >> (i * 8)) & 0xFF;
        }

        // Decrypt directly into print buffer
        uint32_t ctr_inc_bits = 128;
        sgx_status_t status = sgx_aes_ctr_encrypt(
            &aes_key, enc_buf + offset, current_block_size,
            counter, ctr_inc_bits, print_buf + print_buf_count);

        if (status != SGX_SUCCESS) {
            printf("❌ Block #%lu decryption failed: 0x%X\n", block_num, status);
            continue;
        }

        print_buf_count += current_block_size;
        total_bytes_processed += current_block_size;

        // Print conditions
        bool should_print = (print_buf_count >= 512) || // ~32 blocks
                          (block_num % PRINT_EVERY_N_BLOCKS == 0) ||
                          (block_num == end_block - 1) ||
                          (current_block_size < block_size); // Partial block

        if (should_print && print_buf_count > 0) {
            printf("🔓 Decrypted Data #%lu-#%lu (%zu bytes):\n", 
                  start_block, block_num, print_buf_count);
            
            for (size_t i = 0; i < print_buf_count; i++) {
                printf("%02X ", print_buf[i]);
                if ((i + 1) % 32 == 0) printf("\n");
            }
            printf("\n");
            print_buf_count = 0;
        }
    }

    delete[] print_buf;
    return 0;
}
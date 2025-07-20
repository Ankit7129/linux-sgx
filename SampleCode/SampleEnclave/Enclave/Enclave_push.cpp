#include "sgx_tcrypto.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <stdint.h>


#define PRINT_EVERY_N_BYTES 512
#define MAX_CHUNK_SIZE (1 << 20) // 1MB maximum chunk size

// Global buffer to store loaded chunks (if needed)
static std::vector<uint8_t> loaded_vector_data;
static size_t total_loaded_bytes = 0;

int printf(const char* fmt, ...) {
    char buf[BUFSIZ] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void ecall_load_vector_chunk(const uint8_t* chunk_data, size_t chunk_size) {
    if (!chunk_data || chunk_size == 0) {
        printf("❌ Invalid chunk data or size\n");
        return;
    }

    if (chunk_size > MAX_CHUNK_SIZE) {
        printf("❌ Chunk size too large (%zu > %d)\n", chunk_size, MAX_CHUNK_SIZE);
        return;
    }

    // Just verify the chunk was received, but don't store it
    printf("✅ Received chunk of %zu bytes\n", chunk_size);
    
    // Debug: Print first 8 bytes of the chunk
    printf("🔍 First 8 bytes: ");
    for (size_t i = 0; i < 8 && i < chunk_size; i++) {
        printf("%02x ", chunk_data[i]);
    }
    printf("\n");
}


int ecall_decrypt_aesgcm_chunk(    uint8_t* ciphertext, size_t ciphertext_size,    uint8_t* key, size_t key_size, uint8_t* nonce, size_t nonce_size, uint8_t* tag, size_t tag_size)
{

    static int total_found_count = 0; 
/*
    printf("=== Enclave Debug Info ===\n");
    printf("🔍 Received chunk of size: %zu\n", ciphertext_size);
    printf("🔍 Nonce size: %zu, Tag size: %zu\n", nonce_size, tag_size);
    */
    if (!ciphertext || !key || !nonce || !tag) {
       // printf("❌ Null pointer detected!\n");
        return -1;
    }
    
    if (key_size != 16 || nonce_size != 12 || tag_size != 16) {
        /*
        printf("❌ Invalid sizes - Key:%zu (16), Nonce:%zu (12), Tag:%zu (16)\n", 
               key_size, nonce_size, tag_size);
               */
        return -1;
    }

    // Print first bytes of each component for verification
   /* printf("🔍 Key (first 8): ");
    for (int i = 0; i < 8; i++) printf("%02x ", key[i]);
    printf("\n🔍 Nonce (first 8): ");
    for (int i = 0; i < 8; i++) printf("%02x ", nonce[i]);
    printf("\n🔍 Tag (first 8): ");
    for (int i = 0; i < 8; i++) printf("%02x ", tag[i]);
    printf("\n");
*/
    sgx_aes_gcm_128bit_key_t aes_key;
    memcpy(&aes_key, key, 16);

    uint8_t plaintext[ciphertext_size];
    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        &aes_key,
        ciphertext,
        ciphertext_size,
        plaintext,
        nonce, nonce_size,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t*)tag);
    
    if (status != SGX_SUCCESS) {
        /*
        printf("❌ Decryption failed with status: 0x%X\n", status);
        printf("❌ Possible causes:\n");
        printf("   - Incorrect key\n");
        printf("   - Corrupted ciphertext\n");
        printf("   - Invalid nonce/tag\n");
        printf("   - SGX internal error\n");
        */
        return -2;
    }

    printf("✅ Decryption successful\n");
    printf("🔍 First 16 plaintext bytes: ");
    for (size_t i = 0; i < 16 && i < ciphertext_size; i++) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");

   
    return 0;
}


int ecall_decrypt_aesgcm_search_chunk(    uint8_t* ciphertext, size_t ciphertext_size,    uint8_t* key, size_t key_size, uint8_t* nonce, size_t nonce_size, uint8_t* tag, size_t tag_size)
{

    static int total_found_count = 0; 

    printf("=== Enclave Debug Info ===\n");
    printf("🔍 Received chunk of size: %zu\n", ciphertext_size);
    printf("🔍 Nonce size: %zu, Tag size: %zu\n", nonce_size, tag_size);
    
    if (!ciphertext || !key || !nonce || !tag) {
        printf("❌ Null pointer detected!\n");
        return -1;
    }
    
    if (key_size != 16 || nonce_size != 12 || tag_size != 16) {
        printf("❌ Invalid sizes - Key:%zu (16), Nonce:%zu (12), Tag:%zu (16)\n", 
               key_size, nonce_size, tag_size);
        return -1;
    }

    // Print first bytes of each component for verification
    printf("🔍 Key (first 8): ");
    for (int i = 0; i < 8; i++) printf("%02x ", key[i]);
    printf("\n🔍 Nonce (first 8): ");
    for (int i = 0; i < 8; i++) printf("%02x ", nonce[i]);
    printf("\n🔍 Tag (first 8): ");
    for (int i = 0; i < 8; i++) printf("%02x ", tag[i]);
    printf("\n");

    sgx_aes_gcm_128bit_key_t aes_key;
    memcpy(&aes_key, key, 16);

    uint8_t plaintext[ciphertext_size];
    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        &aes_key,
        ciphertext,
        ciphertext_size,
        plaintext,
        nonce, nonce_size,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t*)tag);
    
    if (status != SGX_SUCCESS) {
        printf("❌ Decryption failed with status: 0x%X\n", status);
        printf("❌ Possible causes:\n");
        printf("   - Incorrect key\n");
        printf("   - Corrupted ciphertext\n");
        printf("   - Invalid nonce/tag\n");
        printf("   - SGX internal error\n");
        return -2;
    }

    printf("✅ Decryption successful\n");
    printf("🔍 First 16 plaintext bytes: ");
    for (size_t i = 0; i < 16 && i < ciphertext_size; i++) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");

    // Search for specific value (e.g., 0x05) in the first 16 bytes
    uint8_t search_value = 0x04;
    int found_count = 0;
    for (size_t i = 0; i < ciphertext_size; i++) {
        if (plaintext[i] == search_value) {
            found_count++;
        }
    }
     total_found_count += found_count;

    // Print the count of found occurrences of the value
    printf("🔍 Found value 0x%02x: %d times in the plaintext bytes\n", search_value, found_count);
    printf("🔍 Total found so far: %d times across all chunks\n", total_found_count);
    return 0;
}


void ecall_test_heap_allocation() {
    size_t max_success_mb = 0;

    for (size_t i = 1; i <= 128; i++) {
        size_t alloc_size = i * 1024 * 1024; // i MB
        uint8_t* ptr = (uint8_t*)malloc(alloc_size);

        if (!ptr) {
            printf("❌ Failed to allocate %zu MB\n", i);
            break;
        }

        memset(ptr, 0xAA, alloc_size); // Touch memory to ensure it's valid
        printf("✅ Allocated and initialized %zu MB\n", i);
        free(ptr);
        max_success_mb = i;
    }

    printf("✅ Max successful malloc inside enclave: %zu MB\n", max_success_mb);
}

void ecall_test_max_chunk_buffer() {
    size_t max_size = 0;

    for (size_t mb = 1; mb <= 128; mb++) {
        size_t size = mb * 1024 * 1024;
        uint8_t* buf = (uint8_t*)malloc(size);
        if (!buf) {
            printf("❌ Max single chunk malloc size: %zu MB\n", mb - 1);
            break;
        }
        memset(buf, 0x00, size);
        free(buf);
        max_size = mb;
    }

    printf("✅ Max safe single chunk allocation: %zu MB\n", max_size);
}


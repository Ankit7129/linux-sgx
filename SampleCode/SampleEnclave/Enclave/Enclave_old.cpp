#include "sgx_tcrypto.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <algorithm> // for std::min
#include <cstdint>
#include <ctime> // Included but timing code removed due to SGX limitation

int printf(const char* fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

// Globals for audit profiling
static size_t chunk_counter = 0;
static size_t total_added = 0;

// Audit struct for per-chunk profiling (timing removed)
struct ChunkProfile {
    size_t chunk;
    size_t size;
   
};
static std::vector<ChunkProfile> chunk_profiles;

// Cumulative times removed

// AES-CTR Decrypt with safe cast
sgx_status_t aes_ctr_decrypt(const uint8_t* ciphertext, size_t len,
                             const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
                             std::vector<uint8_t>& plaintext) {
    if (len > UINT32_MAX) return SGX_ERROR_INVALID_PARAMETER;

    plaintext.resize(len);
    sgx_aes_ctr_128bit_key_t aes_key;
    memcpy(&aes_key, key, 16);

    uint8_t counter[16] = {0};
    if (nonce_len != 8) return SGX_ERROR_INVALID_PARAMETER;
    memcpy(counter, nonce, 8);
    uint32_t ctr_inc_bits = 128;

    return sgx_aes_ctr_encrypt(&aes_key, ciphertext, (uint32_t)len, counter, ctr_inc_bits, plaintext.data());
}

// Main ECALL (per-chunk, without timing)
sgx_status_t ecall_decrypt_and_add(uint8_t* enc_vec1, uint8_t* enc_vec2, size_t len,
                                   uint8_t* key, size_t key_len,
                                   uint8_t* nonce1, size_t nonce1_len,
                                   uint8_t* nonce2, size_t nonce2_len) {
    if (key_len != 16 || nonce1_len != 8 || nonce2_len != 8) {
        printf("❌ Invalid key/nonce size.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    printf("🔐 Encrypted Vectors Received (len = %zu)\n", len);
    
    // Use block scope to ensure these vectors are destroyed after use
    {
        std::vector<uint8_t> vec1, vec2, sum_vec(len);

        // Decrypt both vectors
        sgx_status_t status1 = aes_ctr_decrypt(enc_vec1, len, key, nonce1, nonce1_len, vec1);
        sgx_status_t status2 = aes_ctr_decrypt(enc_vec2, len, key, nonce2, nonce2_len, vec2);
        if (status1 != SGX_SUCCESS || status2 != SGX_SUCCESS) {
            printf("❌ Decryption failed.\n");
            return SGX_ERROR_UNEXPECTED;
        }

        // Preview decrypted vectors
        printf("🔎 Vector1 Preview: ");
        for (size_t i = 0; i < std::min(len, size_t(10)); ++i) printf("%d ", vec1[i]);
        printf("...\n");

        printf("🔎 Vector2 Preview: ");
        for (size_t i = 0; i < std::min(len, size_t(10)); ++i) printf("%d ", vec2[i]);
        printf("...\n");

        // Add element-wise with saturation
        for (size_t i = 0; i < len; ++i) {
            uint16_t sum = static_cast<uint16_t>(vec1[i]) + static_cast<uint16_t>(vec2[i]);
            sum_vec[i] = (sum > 255) ? 255 : static_cast<uint8_t>(sum);
        }

        printf("✅ Chunk #%zu added. 🧮 Result Preview: ", chunk_counter);
        for (size_t i = 0; i < std::min(len, size_t(10)); ++i)
            printf("%d ", sum_vec[i]);
        printf("...\n");
    } // 🔁 Vectors destroyed here immediately

    // Store only minimal audit info (not whole vectors!)
    chunk_profiles.push_back({chunk_counter, len});
    chunk_counter++;
    total_added += len;

    return SGX_SUCCESS;
}

void ecall_addition_summary() {
    printf("\n📊 Addition Summary:\n");
    printf("   • Chunks Processed: %zu\n", chunk_counter);
    printf("   • Total Elements:   %zu\n", total_added);
    printf("   • Avg Chunk Size:   %.2f\n", chunk_counter ? ((float)total_added / chunk_counter) : 0.0f);
    printf("\n");
}


// Other ECALLs unchanged

sgx_status_t ecall_process_file(uint8_t* chunk, size_t len) {
    printf("📥 Received file chunk of %zu bytes.\n", len);

    // Preview first 10 bytes
    for (size_t i = 0; i < std::min(len, size_t(10)); ++i)
        printf("%d ", chunk[i]);
    printf("...\n");

    // 🔐 Zero out chunk content (in-place)
    if (chunk && len > 0) {
        memset(chunk, 0, len);  // Optional since caller owns memory
    }

    return SGX_SUCCESS;
}

sgx_status_t ecall_decrypt_vector_chunk(uint8_t* enc_data, size_t enc_len,
                                        uint8_t* key, size_t key_len,
                                        uint8_t* nonce, size_t nonce_len) {
    if (key_len != 16 || nonce_len != 8) {
        printf("❌ Invalid key or nonce length.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_aes_ctr_128bit_key_t aes_key;
    memcpy(&aes_key, key, 16);

    uint8_t counter[16] = {0};
    memcpy(counter, nonce, 8);

    std::vector<uint8_t> decrypted(enc_len);
    uint32_t ctr_inc_bits = 128;

    sgx_status_t status = sgx_aes_ctr_encrypt(
        &aes_key,
        enc_data,
        static_cast<uint32_t>(enc_len),
        counter,
        ctr_inc_bits,
        decrypted.data()
    );

    if (status != SGX_SUCCESS) {
        printf("❌ Decryption failed.\n");
        return status;
    }

    // 📊 Preview only for debug
    printf("🔓 Decrypted Chunk Preview: ");
    for (size_t i = 0; i < std::min(enc_len, size_t(10)); ++i)
        printf("%d ", decrypted[i]);
    printf("...\n");

    // 🔐 SECURELY ERASE decrypted content before exit
    if (!decrypted.empty()) {
        memset(decrypted.data(), 0, decrypted.size());
    }

    return SGX_SUCCESS;
}

int ecall_search_value(uint8_t* enc_chunk, size_t chunk_size,
                       uint8_t* key, size_t key_size,
                       uint8_t* nonce, size_t nonce_size,
                       int search_value) {
    if (!enc_chunk || !key || !nonce || key_size != 16 || nonce_size != 8)
        return -1;

    if (search_value < 0 || search_value > 255)
        return -2;  // out of uint8_t range

    std::vector<uint8_t> decrypted;
    sgx_status_t status = aes_ctr_decrypt(enc_chunk, chunk_size, key, nonce, nonce_size, decrypted);
    if (status != SGX_SUCCESS) {
        printf("❌ Decryption failed inside search.\n");
        return -3;
    }

    size_t found = 0;
    for (size_t i = 0; i < decrypted.size(); ++i) {
        if (decrypted[i] == static_cast<uint8_t>(search_value)) found++;
    }

    printf("🔎 Searched chunk #%zu → found value %d = %zu times.\n", chunk_counter, search_value, found);
    chunk_profiles.push_back({chunk_counter, chunk_size});
    chunk_counter++;

    return static_cast<int>(found);
}

void ecall_add_vectors(uint8_t* vec1, uint8_t* vec2, size_t len) {
    printf("🔹 Vector 1: ");
    for (size_t i = 0; i < len; ++i) printf("%d ", vec1[i]);
    printf("\n🔹 Vector 2: ");
    for (size_t i = 0; i < len; ++i) printf("%d ", vec2[i]);
    printf("\n➕ Sum: ");
    for (size_t i = 0; i < len; ++i) printf("%d ", static_cast<uint8_t>(vec1[i] + vec2[i]));
    printf("\n");
}

void ecall_add_vectors_chunk(uint8_t* vec1, uint8_t* vec2, size_t len) {
    chunk_counter++;
    total_added += len;

    printf("📦 Chunk #%zu (size = %zu): ", chunk_counter, len);
    for (size_t i = 0; i < len; ++i) {
        uint8_t sum = static_cast<uint8_t>((vec1[i] + vec2[i]) % 10);
        printf("%d ", sum);
    }
    printf("\n✅ Chunk processed.\n");
}

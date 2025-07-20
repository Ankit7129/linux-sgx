#include "sgx_tcrypto.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <stdint.h>
#include <string>



uint8_t enclave_key[16];
bool key_loaded = false;

extern "C" sgx_status_t ecall_preload_key_into_enclave(uint8_t* key, size_t len) {
    if (len != 16) return SGX_ERROR_INVALID_PARAMETER;
    memcpy(enclave_key, key, 16);
    key_loaded = true;
    printf("✅ Key loaded/replaced inside enclave.\n");
    return SGX_SUCCESS;
}



// Global buffer to store loaded chunks (if needed)
//static std::vector<uint8_t> loaded_vector_data;
//static size_t total_loaded_bytes = 0;

int printf(const char* fmt, ...) {
    char buf[BUFSIZ] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


/* 
 * This function determines the maximum safe memory allocation size 
 * for the enclave using binary search, then tests how many such chunks 
 * can be allocated simultaneously. It then reads the input file into 
 * enclave memory using the largest safe and simultaneously allocatable 
 * chunk size, measuring and reporting the load times.
 */



// Helper function to convert bytes to human-readable format
std::string human_readable_size(size_t bytes) {
    const char* suffixes[] = {"B", "KB", "MB", "GB", "TB"};
    size_t i = 0;
    double dblBytes = bytes;

    if (bytes > 1024) {
        for (i = 0; (bytes / 1024) > 0 && i < sizeof(suffixes)/sizeof(suffixes[0])-1; i++, bytes /= 1024) {
            dblBytes = bytes / 1024.0;
        }
    }

    char output[32];
    snprintf(output, sizeof(output), "%.2f %s", dblBytes, suffixes[i]);
    return output;
}

void ecall_start_vector_load_size_test() {
    long t_start_total = 0, t_end_total = 0;
    if (ocall_get_time_micro(&t_start_total) != 0) {
        printf("❌ Failed to get start time\n");
        return;
    }

    size_t file_size = 0;
    if (ocall_get_file_info(&file_size) != 0) {
        printf("❌ Failed to get file info\n");
        return;
    }

    printf("📁 File to preload: %zu bytes (%s)\n", file_size, human_readable_size(file_size).c_str());

    if (file_size == 0) {
        printf("❌ File size reported as 0\n");
        return;
    }

    // Constants
    const size_t NONCE_SIZE = 12;
    const size_t TAG_SIZE = 16;
    const size_t MIN_CHUNK_SIZE = NONCE_SIZE + TAG_SIZE + 1;
    const size_t MAX_TEST_MB = 128;
    const size_t STEP_SIZE = 1 * 1024 * 1024;

    printf("\nℹ️ Starting max single chunk size detection (up to %zu MB)...\n", MAX_TEST_MB);

    // 1) Find max safe single chunk size using binary search
    size_t low = MIN_CHUNK_SIZE;
    size_t high = MAX_TEST_MB * 1024 * 1024;
    size_t last_success = 0;
    size_t allocation_attempts = 0;

    while (low <= high) {
        size_t mid = low + (high - low) / 2;
        allocation_attempts++;
        
        uint8_t* test_buf = (uint8_t*) malloc(mid);
        if (test_buf) {
            // Verify we can actually use the memory
            memset(test_buf, 0xAA, mid);
            if (test_buf[0] != 0xAA || test_buf[mid-1] != 0xAA) {
                printf("⚠️ Memory verification failed for allocation of %s\n", human_readable_size(mid).c_str());
                free(test_buf);
                high = mid - 1;
                continue;
            }
            
            free(test_buf);
            last_success = mid;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    size_t max_chunk_size = last_success;

    if (max_chunk_size < MIN_CHUNK_SIZE) {
        printf("❌ Critical Error: Unable to allocate minimum chunk size (%zu bytes), max allocatable: %zu bytes\n", 
               MIN_CHUNK_SIZE, max_chunk_size);
        return;
    }

    printf("✅ Max safe single chunk size: %s (after %zu allocation attempts)\n", 
           human_readable_size(max_chunk_size).c_str(), allocation_attempts);
    printf("✅ Phase 1 Completed: Max single chunk size detection done\n\n");

    // 2) Find max number of simultaneous allocations for chunk sizes
    const size_t MAX_CHUNKS_TO_TEST = 16;
    size_t max_chunks_found = 0;
    size_t best_chunk_size = 0;
    size_t best_total_size = 0;

    printf("ℹ️ Testing simultaneous allocations with different chunk sizes...\n");
    
    // Test from max size downward
    for (size_t test_chunk_size = max_chunk_size; 
         test_chunk_size >= MIN_CHUNK_SIZE; 
         test_chunk_size = (test_chunk_size > STEP_SIZE) ? test_chunk_size - STEP_SIZE : MIN_CHUNK_SIZE) {
        
        printf("\nℹ️ Testing chunk size: %s\n", human_readable_size(test_chunk_size).c_str());

        uint8_t** chunks = (uint8_t**) malloc(sizeof(uint8_t*) * MAX_CHUNKS_TO_TEST);
        if (!chunks) {
            printf("❌ Failed to allocate chunks array\n");
            continue;
        }

        size_t allocated_chunks = 0;
        bool allocation_failed = false;
        
        // Try to allocate all chunks
        for (size_t i = 0; i < MAX_CHUNKS_TO_TEST; i++) {
            chunks[i] = (uint8_t*) malloc(test_chunk_size);
            if (!chunks[i]) {
                printf("❌ Failed to allocate chunk %zu of size %s\n", 
                       i + 1, human_readable_size(test_chunk_size).c_str());
                allocation_failed = true;
                break;
            }
            
            // Verify memory
            memset(chunks[i], 0xAA, test_chunk_size);
            if (chunks[i][0] != 0xAA || chunks[i][test_chunk_size-1] != 0xAA) {
                printf("⚠️ Memory verification failed for chunk %zu\n", i + 1);
                free(chunks[i]);
                chunks[i] = nullptr;
                allocation_failed = true;
                break;
            }
            
            allocated_chunks++;
        }

        // Clean up
        for (size_t i = 0; i < allocated_chunks; i++) {
            if (chunks[i]) {
                free(chunks[i]);
            }
        }
        free(chunks);

        size_t total_size = allocated_chunks * test_chunk_size;
        printf("ℹ️ Allocated %zu chunks (%s total) simultaneously at chunk size %s\n",
               allocated_chunks, human_readable_size(total_size).c_str(), 
               human_readable_size(test_chunk_size).c_str());

        // Track the best configuration (prioritize more chunks, then larger total size)
        if (allocated_chunks > max_chunks_found || 
            (allocated_chunks == max_chunks_found && total_size > best_total_size)) {
            max_chunks_found = allocated_chunks;
            best_chunk_size = test_chunk_size;
            best_total_size = total_size;
            
            if (max_chunks_found == MAX_CHUNKS_TO_TEST) {
                break; // We've hit the maximum we wanted to test
            }
        }
        
        if (test_chunk_size == MIN_CHUNK_SIZE) break; // Prevent underflow
    }

    if (max_chunks_found == 0) {
        printf("⚠️ Warning: Could not allocate any chunks simultaneously, falling back to single chunk mode\n");
        max_chunks_found = 1;
        best_chunk_size = max_chunk_size;
    }

    max_chunk_size = best_chunk_size;

    printf("\n✅ Optimal configuration found:\n");
    printf("  - Chunk size: %s\n", human_readable_size(max_chunk_size).c_str());
    printf("  - Max simultaneous chunks: %zu\n", max_chunks_found);
    printf("  - Total batch size: %s\n", human_readable_size(max_chunk_size * max_chunks_found).c_str());
    printf("✅ Phase 2 Completed: Batch allocation tuning done\n\n");

    // Adjust chunk size if larger than file
    if (max_chunk_size > file_size) {
        printf("⚠️ Adjusting chunk size from %s to file size %s\n",
               human_readable_size(max_chunk_size).c_str(), human_readable_size(file_size).c_str());
        max_chunk_size = file_size;
        max_chunks_found = 1; // Can't do batching with single chunk
    }

    printf("ℹ️ Starting file load with configuration:\n");
    printf("  - Chunk size: %s\n", human_readable_size(max_chunk_size).c_str());
    printf("  - Max chunks per batch: %zu\n", max_chunks_found);
    printf("  - Expected batches: %zu\n", (file_size + max_chunk_size * max_chunks_found - 1) / (max_chunk_size * max_chunks_found));

    // 3) Load file in chunks batch-wise
    size_t offset = 0;
    size_t chunk_count = 0;
    size_t batch_count = 0;
    size_t current_batch_size = max_chunks_found;

    std::vector<long> load_times_us;
    std::vector<size_t> chunk_sizes;
    std::vector<size_t> batch_sizes;

    while (offset < file_size) {
        batch_count++;
        size_t remaining_file = file_size - offset;
        size_t chunks_to_load = current_batch_size;

        // Adjust chunks for last batch
        if (remaining_file < max_chunk_size * current_batch_size) {
            chunks_to_load = (remaining_file + max_chunk_size - 1) / max_chunk_size;
        }

        printf("\n🔁 Batch %zu: Loading %zu chunks (chunk size: %s)\n",
               batch_count, chunks_to_load, human_readable_size(max_chunk_size).c_str());

        uint8_t** enc_chunks = (uint8_t**) malloc(sizeof(uint8_t*) * chunks_to_load);
        if (!enc_chunks) {
            printf("❌ Failed to allocate chunks array for loading %zu chunks\n", chunks_to_load);

            if (current_batch_size > 1) {
                current_batch_size = current_batch_size / 2;
                printf("⚠️ Reducing batch size to %zu and retrying...\n", current_batch_size);
                continue;
            } else {
                printf("❌ Critical Error: Failed to allocate even a single chunk, aborting load\n");
                break;
            }
        }

        // Initialize pointers to NULL for safe cleanup
        memset(enc_chunks, 0, sizeof(uint8_t*) * chunks_to_load);

        bool alloc_failed = false;
        size_t temp_remaining = remaining_file;

        // Allocate all chunks in this batch
        for (size_t i = 0; i < chunks_to_load; i++) {
            size_t chunk_size = (temp_remaining >= max_chunk_size) ? max_chunk_size : temp_remaining;
            enc_chunks[i] = (uint8_t*) malloc(chunk_size);
            if (!enc_chunks[i]) {
                printf("❌ Failed to allocate chunk buffer (%zu bytes) at batch chunk %zu\n", 
                       chunk_size, i + 1);
                alloc_failed = true;
                break;
            }
            temp_remaining -= chunk_size;
        }

        if (alloc_failed) {
            // Cleanup any allocated chunks
            for (size_t i = 0; i < chunks_to_load; i++) {
                if (enc_chunks[i]) {
                    free(enc_chunks[i]);
                }
            }
            free(enc_chunks);

            if (current_batch_size > 1) {
                current_batch_size = current_batch_size / 2;
                printf("⚠️ Reducing batch size to %zu and retrying...\n", current_batch_size);
                continue;
            } else {
                printf("❌ Critical Error: Failed to allocate chunk buffers, aborting load\n");
                break;
            }
        }

        // Load and time each chunk in this batch
        size_t batch_bytes = 0;
        for (size_t i = 0; i < chunks_to_load; i++) {
            long t_load_start = 0, t_load_end = 0;
            size_t chunk_size = (file_size - offset >= max_chunk_size) ? max_chunk_size : (file_size - offset);

            if (ocall_get_time_micro(&t_load_start) != 0) {
                printf("❌ Failed to get load start time for chunk %zu\n", chunk_count + 1);
                continue;
            }

            if (ocall_read_chunk(enc_chunks[i], chunk_size, offset) != 0) {
                printf("❌ Failed to read chunk %zu at offset %zu\n", chunk_count + 1, offset);
                continue;
            }

            if (ocall_get_time_micro(&t_load_end) != 0) {
                printf("❌ Failed to get load end time for chunk %zu\n", chunk_count + 1);
                continue;
            }

            long load_time = t_load_end - t_load_start;
            batch_bytes += chunk_size;

            printf("\n📦 Chunk %zu loaded\n", chunk_count + 1);
            printf("  ├─ Size: %s\n", human_readable_size(chunk_size).c_str());
            printf("  ├─ Offset: %zu (%.2f%% of file)\n", offset, (offset * 100.0) / file_size);
            printf("  └─ Load Time: %ld µs (%s/s)\n", 
                   load_time, human_readable_size((chunk_size * 1000000) / (load_time ? load_time : 1)).c_str());

            load_times_us.push_back(load_time);
            chunk_sizes.push_back(chunk_size);
            offset += chunk_size;
            chunk_count++;
        }

        batch_sizes.push_back(batch_bytes);

        // Clean up this batch
        for (size_t i = 0; i < chunks_to_load; i++) {
            if (enc_chunks[i]) {
                free(enc_chunks[i]);
            }
        }
        free(enc_chunks);
    }

    if (ocall_get_time_micro(&t_end_total) != 0) {
        printf("❌ Failed to get end time\n");
    }
    long total_time_us = t_end_total - t_start_total;

    // Calculate statistics
    long total_load_time_us = 0;
    size_t total_bytes_loaded = 0;
    for (size_t i = 0; i < load_times_us.size(); i++) {
        total_load_time_us += load_times_us[i];
        total_bytes_loaded += chunk_sizes[i];
    }

    double avg_load_time_ms = (load_times_us.empty() ? 0 : total_load_time_us / (1000.0 * load_times_us.size()));
    double avg_throughput = (total_load_time_us > 0 ? (total_bytes_loaded * 1000000.0) / (1024.0 * 1024.0 * total_load_time_us) : 0);

    printf("\n✅ Load process completed\n");
    printf("======================= SUMMARY =======================\n");
    printf("  - Total chunks loaded: %zu\n", chunk_count);
    printf("  - Total batches: %zu\n", batch_count);
    printf("  - Final batch size: %zu chunks\n", current_batch_size);
    printf("  - Total size loaded: %s\n", human_readable_size(total_bytes_loaded).c_str());
    printf("\n⏱️ Performance Metrics:\n");
    printf("  - Total elapsed time: %.2f ms (%.2f s)\n", total_time_us / 1000.0, total_time_us / 1000000.0);
    printf("  - Total load time: %.2f ms (%.2f s)\n", total_load_time_us / 1000.0, total_load_time_us / 1000000.0);
    printf("  - Average chunk load time: %.2f ms\n", avg_load_time_ms);
    printf("  - Average throughput: %.2f MB/s\n", avg_throughput);
    printf("=======================================================\n");
    printf("✅ Phase 3 Completed: File loading finished\n");

    // Additional debug info if needed
    #ifdef DEBUG
    printf("\nDebug Info:\n");
    for (size_t i = 0; i < load_times_us.size(); i++) {
        printf("Chunk %4zu: %6zu bytes in %6ld µs\n", i+1, chunk_sizes[i], load_times_us[i]);
    }
    #endif
}




#define MAX_CHUNK_SIZE 5000000  // 1MB
#define PRINT_BYTES 20          // Number of bytes to print for testing

void ecall_start_vector_load() {
    const size_t NONCE_SIZE = 12;
    const size_t TAG_SIZE = 16;
    const size_t ENCRYPTED_CHUNK_SIZE = NONCE_SIZE + MAX_CHUNK_SIZE + TAG_SIZE;

    long t_start_total = 0, t_end_total = 0;
    ocall_get_time_micro(&t_start_total);

    size_t file_size = 0;
    ocall_get_file_info(&file_size);
    if (file_size == 0) {
        printf("❌ File size reported as 0\n");
        return;
    }

    std::vector<long> load_times_us, decrypt_times_us, search_times_us;
    std::vector<size_t> chunk_sizes, ciphertext_sizes;
    std::vector<size_t> chunk_hits;
    const uint8_t TARGET = 5;

    size_t offset = 0;
    size_t chunk_count = 0;
    size_t total_hits = 0;
    size_t batch_number = 0;
    size_t dynamic_n_fragments = 0;
    size_t total_chunks_expected = (file_size + ENCRYPTED_CHUNK_SIZE - 1) / ENCRYPTED_CHUNK_SIZE;

    while (offset < file_size) {
        batch_number++;
        printf("\n================ 🧱 Batch %zu ================\n", batch_number);

        size_t remaining = file_size - offset;
        size_t chunks_this_batch = (batch_number == 1)
            ? (remaining + ENCRYPTED_CHUNK_SIZE - 1) / ENCRYPTED_CHUNK_SIZE
            : dynamic_n_fragments;

        if (batch_number == 1)
            printf("⚡ Determining EPC capacity with initial batch size: %zu\n", chunks_this_batch);

        uint8_t** enc_chunks = (uint8_t**) malloc(chunks_this_batch * sizeof(uint8_t*));
        size_t* actual_sizes = (size_t*) malloc(chunks_this_batch * sizeof(size_t));
        long* load_start = (long*) malloc(chunks_this_batch * sizeof(long));
        long* load_end = (long*) malloc(chunks_this_batch * sizeof(long));
        bool* chunk_success = (bool*) calloc(chunks_this_batch, sizeof(bool));

        if (!enc_chunks || !actual_sizes || !load_start || !load_end || !chunk_success) {
            printf("❌ Memory allocation failed for batch buffers.\n");
            break;
        }

        size_t successful_loads = 0;

        for (size_t i = 0; i < chunks_this_batch; i++) {
            size_t rem = file_size - offset;
            if (rem == 0) {
                chunks_this_batch = i;
                break;
            }

            size_t read_size = (rem >= ENCRYPTED_CHUNK_SIZE) ? ENCRYPTED_CHUNK_SIZE : rem;

            enc_chunks[i] = (uint8_t*) malloc(read_size);
            if (!enc_chunks[i]) {
                printf("❌ malloc failed for chunk %zu\n", chunk_count + 1);
                continue;
            }

            ocall_get_time_micro(&load_start[i]);
            ocall_read_chunk(enc_chunks[i], read_size, offset);
            ocall_get_time_micro(&load_end[i]);

            actual_sizes[i] = read_size;
            offset += read_size;
            chunk_success[i] = true;
            successful_loads++;
        }

        if (batch_number == 1 && successful_loads > 0) {
            dynamic_n_fragments = successful_loads;
            printf("🔍 Determined EPC capacity: %zu chunks per batch\n", dynamic_n_fragments);
        }

        for (size_t i = 0; i < chunks_this_batch; i++) {
            if (!chunk_success[i]) continue;

            size_t enc_size = actual_sizes[i];
            if (enc_size < NONCE_SIZE + TAG_SIZE + 1) {
                printf("⚠️ Encrypted chunk too small to process, skipping chunk %zu\n", chunk_count + 1);
                free(enc_chunks[i]);
                continue;
            }

            uint8_t* nonce = enc_chunks[i];
            size_t ciphertext_len = enc_size - NONCE_SIZE - TAG_SIZE;
            uint8_t* ciphertext = enc_chunks[i] + NONCE_SIZE;
            uint8_t* tag = enc_chunks[i] + NONCE_SIZE + ciphertext_len;

            uint8_t* plaintext = (uint8_t*) malloc(ciphertext_len);
            if (!plaintext) {
                printf("❌ malloc failed for plaintext chunk %zu\n", chunk_count + 1);
                free(enc_chunks[i]);
                continue;
            }

            if (!key_loaded) {
                free(enc_chunks[i]);
                free(plaintext);
                continue;
            }

            long t_dec_start, t_dec_end, t_search_start, t_search_end;
            ocall_get_time_micro(&t_dec_start);
            sgx_status_t ret = sgx_rijndael128GCM_decrypt(
                (const sgx_aes_gcm_128bit_key_t*) enclave_key,
                ciphertext, ciphertext_len,
                plaintext,
                nonce, NONCE_SIZE,
                nullptr, 0,
                (const sgx_aes_gcm_128bit_tag_t*) tag
            );
            ocall_get_time_micro(&t_dec_end);

            if (ret != SGX_SUCCESS) {
                printf("❌ Decryption failed for chunk %zu with SGX error: 0x%x\n", chunk_count + 1, ret);
                free(enc_chunks[i]);
                free(plaintext);
                continue;
            }

            printf("First %d bytes of chunk %zu (Global #%zu): ", PRINT_BYTES, i + 1, chunk_count + 1);
            for (int j = 0; j < PRINT_BYTES && j < ciphertext_len; j++) {
                printf("%02x ", plaintext[j]);
            }
            printf("\n");

            ocall_get_time_micro(&t_search_start);
            size_t hits = 0;
            for (size_t j = 0; j < ciphertext_len; ++j)
                if (plaintext[j] == TARGET) hits++;
            ocall_get_time_micro(&t_search_end);

            printf("🔹 Chunk %zu (Global #%zu): %zu hits | Load: %ld µs | Decrypt: %ld µs | Search: %ld µs\n\n",
                i + 1, chunk_count + 1, hits,
                load_end[i] - load_start[i],
                t_dec_end - t_dec_start,
                t_search_end - t_search_start);

            load_times_us.push_back(load_end[i] - load_start[i]);
            decrypt_times_us.push_back(t_dec_end - t_dec_start);
            search_times_us.push_back(t_search_end - t_search_start);
            chunk_sizes.push_back(enc_size);
            ciphertext_sizes.push_back(ciphertext_len);
            chunk_hits.push_back(hits);

            total_hits += hits;
            chunk_count++;

            free(enc_chunks[i]);
            free(plaintext);
        }

        free(enc_chunks);
        free(actual_sizes);
        free(load_start);
        free(load_end);
        free(chunk_success);

        printf("Batch %zu processed: %zu/%zu chunks\n", batch_number, successful_loads, chunks_this_batch);
    }

    ocall_get_time_micro(&t_end_total);
    long total_time_us = t_end_total - t_start_total;

    long total_load = 0, total_decrypt = 0, total_search = 0;
    for (size_t i = 0; i < chunk_count; i++) {
        total_load += load_times_us[i];
        total_decrypt += decrypt_times_us[i];
        total_search += search_times_us[i];
    }

    // Final check
    if (offset != file_size) {
        printf("⚠️ Incomplete file processed! Final offset = %zu, expected = %zu\n", offset, file_size);
    }
    if (chunk_count != total_chunks_expected) {
        printf("⚠️ Chunk count mismatch: expected = %zu, actual = %zu\n", total_chunks_expected, chunk_count);
    } else {
        printf("✅ All chunks processed successfully.\n");
    }

    printf("\n=================== 📊 Final Summary ===================\n");
    printf("📁 File Size: %s\n", human_readable_size(file_size));
    printf("🧩 Total Chunks Processed: %zu\n", chunk_count);
    printf("🧩 Each Chunk Size: %zu\n", MAX_CHUNK_SIZE);
    printf("🧩 Determined EPC Capacity: %zu chunks per batch\n", dynamic_n_fragments);
    size_t total_used = dynamic_n_fragments * MAX_CHUNK_SIZE;
    printf("🧩 Total SGX potential used (Approx): %s\n", human_readable_size(total_used));
    printf("🧱 Batches Processed: %zu\n", batch_number);
    printf("🔐 AES-GCM Key: %s\n", key_loaded ? "LOADED ✅" : "NOT LOADED ❌");
    printf("🔍 Total Matches for [%u]: %zu\n", TARGET, total_hits);
    printf("⏱️ Total Time: %.2f ms\n", total_time_us / 1000.0);
    printf("📥 Total Load Time:     %ld µs (%.2f ms)\n", total_load, total_load / 1000.0);
    printf("🔐 Total Decrypt Time:  %ld µs (%.2f ms)\n", total_decrypt, total_decrypt / 1000.0);
    printf("🔍 Total Search Time:   %ld µs (%.2f ms)\n", total_search, total_search / 1000.0);

    // Optional JSON logging (unchanged logic)
    char clean_file_size_str[64];
    double file_size_mb = static_cast<double>(file_size) / (1024.0 * 1024.0);
    snprintf(clean_file_size_str, sizeof(clean_file_size_str), "%.2f MB", file_size_mb);
    for (size_t i = 0; i < strlen(clean_file_size_str); ++i)
        if (!isprint(clean_file_size_str[i])) clean_file_size_str[i] = '?';

    std::string chunk_size_str = human_readable_size(MAX_CHUNK_SIZE);
    std::string sgx_potential_size_str = human_readable_size(total_used);

    char summary_json_buf[4096];
    snprintf(summary_json_buf, sizeof(summary_json_buf),
        "{"
        "\"file_size\": \"%s\", "
        "\"total_chunks\": %zu, "
        "\"each_chunk_size\": \"%s\", "
        "\"batches\": %zu, "
        "\"chunks_per_batch\": %.1f, "
        "\"target_value\": %u, "
        "\"total_matches\": %zu, "
        "\"total_elapsed_time_ms\": %.2f, "
        "\"total_load_time_ms\": %.2f, "
        "\"total_decrypt_time_ms\": %.2f, "
        "\"total_search_time_ms\": %.2f, "
        "\"total_sgx_config\": \"%s\", "
        "\"total_sgx_potential_used\": \"%s\", "
        "\"status\": \"%s\""
        "}",
        clean_file_size_str,
        chunk_count,
        chunk_size_str.c_str(),
        batch_number,
        (float)dynamic_n_fragments,
        TARGET,
        total_hits,
        total_time_us / 1000.0,
        total_load / 1000.0,
        total_decrypt / 1000.0,
        total_search / 1000.0,
        "CONFIGURED",  // update if dynamic
        sgx_potential_size_str.c_str(),
        "Process completed successfully"
    );

    ocall_log_json(summary_json_buf);
}

void ecall_SGX_Memory_Analysis() {
    // 1. Find maximum contiguous block
    size_t max_contiguous = 0;
    for (size_t size = (1 << 20); size <= (128 << 20); size *= 2) {
        void* ptr = malloc(size);
        if (ptr) {
            max_contiguous = size;
            free(ptr);
        } else {
            break;
        }
    }

    // 2. Determine optimal chunk size (1/8th of max contiguous, page aligned)
    const size_t page_size = 4096;
    size_t optimal_chunk = (max_contiguous / 8) & ~(page_size - 1);
    optimal_chunk = std::max(optimal_chunk, page_size);  // At least one page

    // 3. Count how many chunks we can actually allocate
    std::vector<void*> chunks;
    while (true) {
        void* chunk = malloc(optimal_chunk);
        if (!chunk) break;
        chunks.push_back(chunk);
    }
    size_t total_chunks = chunks.size();
    
    // 4. Calculate fragmentation
    double utilized_memory = chunks.size() * optimal_chunk;
    double fragmentation = 100.0 - ((utilized_memory * 100.0) / (128 << 20));

    // 5. Find largest batch that fits in contiguous memory
    size_t chunks_per_batch = max_contiguous / optimal_chunk;

    // Clean up
    for (void* ptr : chunks) free(ptr);

    printf("\n=== SGX Memory Analysis ===\n");
    printf("Max Contiguous Block: %.2f MB\n", max_contiguous/(1024.0*1024.0));
    printf("Optimal Chunk Size: %.2f MB\n", optimal_chunk/(1024.0*1024.0));
    printf("Total Allocatable Chunks: %zu (%.2f MB total)\n", 
           total_chunks, (total_chunks * optimal_chunk)/(1024.0*1024.0));
    printf("Fragmentation: %.2f%%\n", fragmentation);
    printf("Recommendation:\n");
    printf("- Chunk Size: %zu bytes (%.2f MB)\n", optimal_chunk, optimal_chunk/(1024.0*1024.0));
    printf("- Batch Size: %zu chunks (%.2f MB per batch)\n", 
           chunks_per_batch, (chunks_per_batch * optimal_chunk)/(1024.0*1024.0));
    printf("================================\n\n");
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


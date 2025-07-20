
#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sstream>
#include <chrono>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <iomanip>


#define ENCLAVE_FILE "enclave.signed.so"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
  printf("%s", str);
}



struct TimingMetrics {
    size_t total_bytes = 0;
    size_t total_chunks = 0;
    size_t chunk_size = 0;
    double total_load_time = 0.0;
    double total_load_decrypt_time = 0.0;
    double chunk_prepare_time = 0.0;
    double exec_time_insidesgx = 0.0;
    double avg_load_time_per_chunk = 0.0;
    double avg_load_decrypt_time_per_chunk = 0.0;
    double avg_decrypt_add_time_per_chunk = 0.0;
};



TimingMetrics read_file_in_chunks_and_send_to_sgx() {
    TimingMetrics metrics;
    const char* filepath = "/home/ankit/data/vector1.enc";
    const size_t chunk_size = 100000;
    metrics.chunk_size = chunk_size;

    std::ifstream infile(filepath, std::ios::binary);
    if (!infile) {
        std::cerr << "❌ Error: Cannot open file " << filepath << std::endl;
        return metrics;
    }

    std::vector<uint8_t> buffer(chunk_size);
    while (!infile.eof()) {
        infile.read(reinterpret_cast<char*>(buffer.data()), chunk_size);
        std::streamsize bytes_read = infile.gcount();
        if (bytes_read <= 0) break;

        metrics.total_bytes += bytes_read;
        metrics.total_chunks++;

        auto start = std::chrono::high_resolution_clock::now();
        sgx_status_t retval;
        sgx_status_t ret = ecall_process_file(global_eid, &retval, buffer.data(), bytes_read);

        auto end = std::chrono::high_resolution_clock::now();
        double chunk_time = std::chrono::duration<double>(end - start).count();
        metrics.total_load_time += chunk_time;

        if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
            std::cerr << "❌ ECALL failed on chunk #" << metrics.total_chunks << "\n";
            return metrics;
        }

        std::cout << "✅ Processed chunk #" << metrics.total_chunks << " (" << bytes_read << " bytes) in "
                  << chunk_time << " sec\n";
    }
    infile.close();

    if (metrics.total_chunks > 0)
        metrics.avg_load_time_per_chunk = metrics.total_load_time / metrics.total_chunks;

    return metrics;
}

TimingMetrics decrypt_single_vector_chunk_with_timing() {
    TimingMetrics metrics;
    const char* key_path    = "/home/ankit/data/aes_key.bin";
    const char* nonce1_path = "/home/ankit/data/aes_nonce1.bin";
    const char* vec1_path   = "/home/ankit/data/vector1.enc";

    const size_t chunk_size = 100000;
    metrics.chunk_size = chunk_size;

    // Load key
    std::ifstream kf(key_path, std::ios::binary);
    std::vector<uint8_t> key((std::istreambuf_iterator<char>(kf)), {});
    kf.close();

    // Load nonce
    std::ifstream nf(nonce1_path, std::ios::binary);
    std::vector<uint8_t> nonce((std::istreambuf_iterator<char>(nf)), {});
    nf.close();

    std::ifstream vf(vec1_path, std::ios::binary);
    if (!vf) {
        std::cerr << "❌ Failed to open vector file\n";
        return metrics;
    }

    std::vector<uint8_t> enc_chunk(chunk_size);
    while (!vf.eof()) {
        vf.read(reinterpret_cast<char*>(enc_chunk.data()), chunk_size);
        size_t bytes_read = vf.gcount();
        if (bytes_read == 0) break;

        metrics.total_chunks++;
        metrics.total_bytes += bytes_read;

        auto start = std::chrono::high_resolution_clock::now();

        sgx_status_t retval;
        sgx_status_t ret = ecall_decrypt_vector_chunk(global_eid, &retval,
                                                      enc_chunk.data(), bytes_read,
                                                      key.data(), key.size(),
                                                      nonce.data(), nonce.size());

        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double>(end - start).count();
        metrics.total_load_decrypt_time += duration;

        if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
            std::cerr << "❌ Decryption ECALL failed on chunk #" << metrics.total_chunks << "\n";
            return metrics;
        }

        std::cout << "✅ Decrypted chunk #" << metrics.total_chunks << " (" << bytes_read << " bytes) in "
                  << duration << " sec\n";
    }
    vf.close();

    if (metrics.total_chunks > 0)
        metrics.avg_load_decrypt_time_per_chunk = metrics.total_load_decrypt_time / metrics.total_chunks;

    return metrics;
}

void log_all_metrics_to_python(const std::string& exp_id,
                               const TimingMetrics& load_metrics,
                               const TimingMetrics& decrypt_metrics,
                               const TimingMetrics& add_metrics,
                               double full_app_time) {
    // Derive useful refined metrics
    double load_only_time       = load_metrics.total_load_time;
    double decrypt_total_time   = decrypt_metrics.total_load_decrypt_time;
    double decrypt_only_time    = decrypt_total_time - load_only_time;
    double approx_add_only_time = full_app_time - decrypt_total_time;

    double avg_decrypt_time_per_chunk = (decrypt_metrics.total_chunks > 0)
        ? decrypt_only_time / decrypt_metrics.total_chunks : 0.0;

    double avg_add_time_per_chunk = (add_metrics.total_chunks > 0)
        ? approx_add_only_time / add_metrics.total_chunks : 0.0;

    // Prepare command to call Python logger
    std::ostringstream cmd;
    cmd << "python3 /home/ankit/utils/log_untrusted_app_metrics.py "
        << exp_id << " "
        << std::fixed << std::setprecision(6)
        << full_app_time << " "                     // total end-to-end time
        << add_metrics.exec_time_insidesgx << " "   // enclave-only time
        << add_metrics.chunk_prepare_time << " "    // chunk processing time
        << load_only_time << " "                    // raw vector1 load time
        << decrypt_total_time << " "                // load + decrypt total
        << decrypt_only_time << " "                 // decrypt only time
        << approx_add_only_time << " "              // add time only
        << avg_decrypt_time_per_chunk << " "        // avg decrypt per chunk
        << avg_add_time_per_chunk << " "            // avg add per chunk
        << add_metrics.chunk_size << " "
        << add_metrics.total_chunks << " "
        << add_metrics.total_bytes << " "
        << add_metrics.avg_decrypt_add_time_per_chunk << " "
        << "\"Untrusted App Metrics\"";

    std::cout << "\n📝 Logging SGX metrics...\n";
    int code = system(cmd.str().c_str());
    if (code == 0)
        std::cout << "✅ SGX metrics logged successfully.\n";
    else
        std::cerr << "❌ Failed to log SGX metrics. Exit code: " << code << "\n";
}


void decrypt_vectors_and_add_in_chunks() {
    const char* key_path    = "/home/ankit/data/aes_key.bin";
    const char* nonce1_path = "/home/ankit/data/aes_nonce1.bin";
    const char* nonce2_path = "/home/ankit/data/aes_nonce2.bin";
    const char* vec1_path   = "/home/ankit/data/vector1.enc";
    const char* vec2_path   = "/home/ankit/data/vector2.enc";
    const char* id_path     = "/home/ankit/data/exp_id.txt";

    std::ifstream idf(id_path);
    std::string exp_id;
    if (!idf || !std::getline(idf, exp_id)) {
        std::cerr << "❌ Failed to read exp_id\n";
        return;
    }

    TimingMetrics load_metrics = read_file_in_chunks_and_send_to_sgx();
    TimingMetrics decrypt_metrics = decrypt_single_vector_chunk_with_timing();

    // Full timer
    auto total_start = std::chrono::high_resolution_clock::now();

    std::ifstream kf(key_path, std::ios::binary);
    std::vector<uint8_t> key((std::istreambuf_iterator<char>(kf)), {});
    kf.close();
    std::ifstream nf1(nonce1_path, std::ios::binary);
    std::vector<uint8_t> nonce1((std::istreambuf_iterator<char>(nf1)), {});
    nf1.close();
    std::ifstream nf2(nonce2_path, std::ios::binary);
    std::vector<uint8_t> nonce2((std::istreambuf_iterator<char>(nf2)), {});
    nf2.close();
    std::ifstream vf1(vec1_path, std::ios::binary);
    std::vector<uint8_t> enc_vec1((std::istreambuf_iterator<char>(vf1)), {});
    vf1.close();
    std::ifstream vf2(vec2_path, std::ios::binary);
    std::vector<uint8_t> enc_vec2((std::istreambuf_iterator<char>(vf2)), {});
    vf2.close();

    if (enc_vec1.size() != enc_vec2.size()) {
        std::cerr << "❌ Vector size mismatch.\n";
        return;
    }

    const size_t total_size = enc_vec1.size();
    const size_t chunk_size = 100000;

    TimingMetrics add_metrics;
    add_metrics.chunk_size = chunk_size;
    size_t offset = 0;

    auto exec_start = std::chrono::high_resolution_clock::now();

    while (offset < total_size) {
        size_t current_chunk = std::min(chunk_size, total_size - offset);

        auto prep_start = std::chrono::high_resolution_clock::now();
        sgx_status_t retval;
        sgx_status_t ret = ecall_decrypt_and_add(global_eid, &retval,
                                                 enc_vec1.data() + offset,
                                                 enc_vec2.data() + offset,
                                                 current_chunk,
                                                 key.data(), key.size(),
                                                 nonce1.data(), nonce1.size(),
                                                 nonce2.data(), nonce2.size());
        auto prep_end = std::chrono::high_resolution_clock::now();
        double chunk_time = std::chrono::duration<double>(prep_end - prep_start).count();
        add_metrics.chunk_prepare_time += chunk_time;

        if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
            std::cerr << "❌ SGX ECALL failed.\n";
            return;
        }

        add_metrics.total_chunks++;
        add_metrics.total_bytes += current_chunk;
        offset += current_chunk;
    }

    auto exec_end = std::chrono::high_resolution_clock::now();
    add_metrics.exec_time_insidesgx = std::chrono::duration<double>(exec_end - exec_start).count();

    auto total_end = std::chrono::high_resolution_clock::now();
    double full_app_time = std::chrono::duration<double>(total_end - total_start).count();

    if (add_metrics.total_chunks > 0)
        add_metrics.avg_decrypt_add_time_per_chunk = add_metrics.chunk_prepare_time / add_metrics.total_chunks;

    sgx_status_t ret2 = ecall_addition_summary(global_eid);
    if (ret2 != SGX_SUCCESS) {
        std::cerr << "❌ Failed to finalize addition.\n";
    }

    // Logging (now a separate function!)
    log_all_metrics_to_python(exp_id, load_metrics, decrypt_metrics, add_metrics, full_app_time);
}

void decrypt_vectors_and_search_in_chunks(int search_value) {
    if (search_value < 0 || search_value > 255) {
        std::cerr << "❌ Invalid search value (must be 0–255 for uint8_t matching): " << search_value << "\n";
        return;
    }

    const char* id_path     = "/home/ankit/data/exp_id.txt";
    const char* key_path    = "/home/ankit/data/aes_key.bin";
    const char* nonce_path  = "/home/ankit/data/aes_nonce1.bin";
    const char* vec_path    = "/home/ankit/data/vector1.enc";
    const size_t chunk_size = 100000;

    std::ifstream idf(id_path);
    std::string exp_id;
    if (!idf || !std::getline(idf, exp_id)) {
        std::cerr << "❌ Failed to read exp_id\n";
        return;
    }

    std::ifstream kf(key_path, std::ios::binary);
    std::vector<uint8_t> key((std::istreambuf_iterator<char>(kf)), {});
    kf.close();

    std::ifstream nf(nonce_path, std::ios::binary);
    std::vector<uint8_t> nonce((std::istreambuf_iterator<char>(nf)), {});
    nf.close();

    std::ifstream vf(vec_path, std::ios::binary);
    if (!vf) {
        std::cerr << "❌ Failed to open encrypted vector file.\n";
        return;
    }

    std::vector<uint8_t> enc_vec((std::istreambuf_iterator<char>(vf)), {});
    vf.close();

    const size_t total_size = enc_vec.size();
    size_t offset = 0;

    TimingMetrics search_metrics;
    search_metrics.chunk_size = chunk_size;

    int total_found = 0;
    auto total_start = std::chrono::high_resolution_clock::now();

    while (offset < total_size) {
        size_t current_chunk = std::min(chunk_size, total_size - offset);
        auto start = std::chrono::high_resolution_clock::now();

        int retval = 0;
        sgx_status_t ret = ecall_search_value(global_eid, &retval,
                                              enc_vec.data() + offset, current_chunk,
                                              key.data(), key.size(),
                                              nonce.data(), nonce.size(),
                                              search_value);

        auto end = std::chrono::high_resolution_clock::now();
        double time = std::chrono::duration<double>(end - start).count();
        search_metrics.chunk_prepare_time += time;

        if (ret != SGX_SUCCESS) {
            std::cerr << "❌ Search ECALL failed at offset " << offset << "\n";
            return;
        }

        std::cout << "✅ Chunk " << search_metrics.total_chunks + 1
                  << " searched in " << time << " sec (found = " << retval << ").\n";

        total_found += retval;
        search_metrics.total_chunks++;
        search_metrics.total_bytes += current_chunk;
        offset += current_chunk;
    }

    auto total_end = std::chrono::high_resolution_clock::now();
    double total_time = std::chrono::duration<double>(total_end - total_start).count();

    if (search_metrics.total_chunks > 0)
        search_metrics.avg_decrypt_add_time_per_chunk = search_metrics.chunk_prepare_time / search_metrics.total_chunks;

    std::cout << "\n🔍 Search Summary:\n";
    std::cout << "   • Value searched: " << search_value << "\n";
    std::cout << "   • Total found: " << total_found << "\n";
    std::cout << "   • Chunks processed: " << search_metrics.total_chunks << "\n";
    std::cout << "   • Total search time: " << total_time << " sec\n";
    std::cout << "   • Avg time per chunk: " << search_metrics.avg_decrypt_add_time_per_chunk << " sec\n";

    // ✅ Call search metrics logger
    std::ostringstream cmd;
    cmd << "python3 /home/ankit/utils/log_search_metrics.py "
        << exp_id << " "
        << search_value << " "
        << total_found << " "
        << search_metrics.total_chunks << " "
        << total_size << " "
        << chunk_size << " "
        << std::fixed << std::setprecision(6)
        << total_time << " "
        << search_metrics.avg_decrypt_add_time_per_chunk << " "
        << "\"Standalone SGX Search Audit\"";

    int res = std::system(cmd.str().c_str());
    if (res != 0) {
        std::cerr << "❌ Python logger failed to execute.\n";
    }
}

/* Application entry */


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

    // Your main function calls - comment/uncomment as needed
    // read_file_in_chunks_and_send_to_sgx();
    // decrypt_single_vector_chunk_with_timing();
    // read_hello_file_and_send_to_sgx();
    // load_vectors_and_add_in_sgx();
    // load_vectors_and_send_to_sgx();
    // load_vectors_and_add_in_chunks();
    //decrypt_vectors_and_add_in_chunks();
    decrypt_vectors_and_search_in_chunks(16);

    /*
    // Optionally call summary if implemented
    sgx_status_t summary_ret = ecall_addition_summary(global_eid);
    if (summary_ret != SGX_SUCCESS) {
        std::cerr << "❌ ECALL summary failed: " << std::hex << summary_ret << std::endl;
    }
    */

    /* Cleanup */
    sgx_destroy_enclave(global_eid);
    std::cout << "✅ Enclave operations completed successfully" << std::endl;
/*
    // Launch python plot script automatically after enclave ops
    std::cout << "📊 Launching Python plot script..." << std::endl;
    int plot_code = system("python3 /home/ankit/utils/plot_sgx_metrics.py");
    if (plot_code != 0) {
        std::cerr << "❌ Python plotting script failed with exit code: " << plot_code << std::endl;
    }
*/
    return 0;
}
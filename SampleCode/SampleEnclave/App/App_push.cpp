#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <sstream>
#include <functional>  // For std::function
#include <sgx_urts.h>
#include "Enclave_u.h"

#include <ctime>               // for timestamp
#include <unistd.h>            // for uname
#include <sys/utsname.h>       // for system info
#include <iomanip> 


#define ENCLAVE_FILE "enclave.signed.so"

sgx_enclave_id_t global_eid = 0;

std::vector<std::string> final_reports;




std::string get_cpu_model() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("model name") != std::string::npos) {
            return line.substr(line.find(":") + 2);  // Skip "model name : "
        }
    }
    return "Unknown CPU";
}

std::string get_sgx_mode() {
    std::ifstream mode_file("/sys/module/isgx/parameters/sgx_mode");  // Intel DCAP (kernel driver)
    if (!mode_file) {
        return "Unknown";  // Not available or using different SGX driver
    }

    std::string mode;
    mode_file >> mode;
    if (mode == "HW") return "HW";
    if (mode == "SW") return "SIM";
    return mode;
}

void print_system_info() {
    struct utsname uname_data;
    uname(&uname_data);

    std::string cpu_model = get_cpu_model();
    int epc_size_mb = 32;       
    int heap_max_size_mb = 32;  
    int stack_max_size_kb = 1024;
    int tcs_num = 10;



    std::cout << "\nSystem Info:\n";
    std::cout << "  " << std::setw(22) << std::left << "CPU" << ": " << cpu_model << "\n";
    std::cout << "  " << std::setw(22) << "OS" << ": " << uname_data.sysname << "\n";
    std::cout << "  " << std::setw(22) << "Kernel" << ": " << uname_data.release << "\n";

    // These might be fixed unless read dynamically from config
     std::cout << "  " << std::setw(22) << "SGX Mode" << ": HW\n";
    std::cout << "  " << std::setw(22) << "EPC Size (MB)" << ": " << epc_size_mb << "\n";
    std::cout << "  " << std::setw(22) << "Heap Max Size (MB)" << ": " << heap_max_size_mb << "\n";
    std::cout << "  " << std::setw(22) << "Stack Max Size (KB)" << ": " << stack_max_size_kb << "\n";
    std::cout << "  " << std::setw(22) << "TCS Num" << ": " << tcs_num << "\n";

    // Static test configuration (update if dynamic)
  //  std::cout << "  " << std::setw(22) << "Chunk Size (MB)" << ": 1\n";
    //std::cout << "  " << std::setw(22) << "Vector Size (GB)" << ": 1\n";
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




void load_vector_in_chunks() {
    try {
        const char* vec_path = "/home/ankit/data/vector1.enc";
        auto enc_data = read_file(vec_path);
        
        const size_t chunk_size = 120000000; // ~1MB chunks
        size_t total_bytes = enc_data.size();
        size_t loaded_bytes = 0;
        size_t chunk_count = 0;
        size_t total_chunks = (total_bytes + chunk_size - 1) / chunk_size;
        double total_load_time = 0.0;
        auto global_start = std::chrono::high_resolution_clock::now();

        /*
        std::cout << "=== VECTOR LOADING IN CHUNKS ===\n";
        std::cout << "🔍 Total file size: " << total_bytes << " bytes\n";
        std::cout << "🔍 Chunk size: " << chunk_size << " bytes\n";
        std::cout << "🔍 Total chunks expected: " << total_chunks << "\n";
        */

        while (loaded_bytes < total_bytes) {
            chunk_count++;
            size_t current_chunk_size = std::min(chunk_size, total_bytes - loaded_bytes);
            
            auto chunk_start = std::chrono::high_resolution_clock::now();
            
            // Call enclave to load the chunk
            sgx_status_t ret = ecall_load_vector_chunk(
                global_eid,
                enc_data.data() + loaded_bytes,
                current_chunk_size);
                
            auto chunk_end = std::chrono::high_resolution_clock::now();
            
            if (ret != SGX_SUCCESS) {
                std::cerr << "❌ Enclave call failed for chunk " << chunk_count 
                          << " (sgx_status=" << ret << ")\n";
                break;
            }
            
            double chunk_time = std::chrono::duration<double, std::milli>(chunk_end - chunk_start).count();
            total_load_time += chunk_time;
            
            /*
            std::cout << "✅ Chunk " << chunk_count << " loaded (" 
                      << current_chunk_size << " bytes) in " 
                      << chunk_time << " ms\n";
            
            loaded_bytes += current_chunk_size;
            std::cout << "🔍 Total loaded: " << loaded_bytes << "/" << total_bytes 
                      << " (" << (100 * loaded_bytes / total_bytes) << "%)\n";
            */
            loaded_bytes += current_chunk_size;
        }

        auto global_end = std::chrono::high_resolution_clock::now();
        double total_wall_time = std::chrono::duration<double, std::milli>(global_end - global_start).count();

        std::cout << "\n=== FINAL LOADING REPORT ===\n";
        std::cout << " Total bytes loaded: " << loaded_bytes << "\n";
        std::cout << " Total chunks processed: " << chunk_count << "\n";
        std::cout << "  Pure loading time (sum): " << total_load_time << " ms\n";
        std::cout << "  Wall clock time: " << total_wall_time << " ms\n";
        std::cout << " Average load time: " << (total_load_time/chunk_count) << " ms/chunk\n";
        std::cout << " Throughput: " 
                 << (loaded_bytes / (total_load_time / 1000.0) / (1024*1024) )
                 << " MB/s\n";

        if (loaded_bytes != total_bytes) {
            std::cerr << "⚠️  Warning: Only loaded " << loaded_bytes 
                      << " out of " << total_bytes << " bytes\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ Fatal Error: " << e.what() << "\n";
    }
}


void decrypt_and_log() {
    try {
        const char* key_path = "/home/ankit/data/aesgcm_key.bin";
        const char* vec_path = "/home/ankit/data/vector1.enc";

        // Read files
        auto key = read_file(key_path);
        auto enc_data = read_file(vec_path);

        // Validate key size
        if (key.size() != 16) {
            std::cerr << "❌ Invalid key size: " << key.size() << " bytes (expected 16)\n";
            return;
        }

        // AES-GCM parameters
        const size_t nonce_size = 12;
        const size_t tag_size = 16;
        const size_t header_size = nonce_size + tag_size;
        const size_t chunk_size = 120000000; // ~1MB chunks

        size_t total_bytes = enc_data.size();
        size_t processed_bytes = 0;
        size_t chunk_count = 0;
        size_t total_chunks = (total_bytes + chunk_size - 1) / chunk_size;
        double total_decrypt_time = 0.0;

        /*
        std::cout << "=== DEBUG INFORMATION ===\n";
        std::cout << "🔍 Total file size: " << total_bytes << " bytes\n";
        std::cout << "🔍 Chunk size: " << chunk_size << " bytes\n";
        std::cout << "🔍 Total chunks expected: " << total_chunks << "\n";
        std::cout << "🔍 Key: ";
        for (auto b : key) printf("%02x", b);
        std::cout << "\n";
        std::cout << "Starting decryption...\n\n";
        */

        auto start_time = std::chrono::high_resolution_clock::now();

        while (processed_bytes + header_size < total_bytes) {
            chunk_count++;
            /*
            std::cout << "\n=== Processing chunk " << chunk_count << " ===\n";
            std::cout << "🔍 Current offset: " << processed_bytes << "\n";
            */

            // Extract nonce
            if (processed_bytes + nonce_size > total_bytes) {
                std::cerr << "❌ Not enough bytes left for nonce (needed " << nonce_size 
                          << ", have " << (total_bytes - processed_bytes) << ")\n";
                break;
            }
            
            std::vector<uint8_t> nonce(
                enc_data.begin() + processed_bytes,
                enc_data.begin() + processed_bytes + nonce_size
            );
            processed_bytes += nonce_size;

            /*
            std::cout << "🔍 Nonce: ";
            for (auto b : nonce) printf("%02x", b);
            std::cout << "\n";
            */

            // Calculate ciphertext size
            size_t remaining_bytes = total_bytes - processed_bytes;
            if (remaining_bytes < tag_size) {
                std::cerr << "❌ Not enough bytes left for tag (needed " << tag_size 
                          << ", have " << remaining_bytes << ")\n";
                break;
            }
            
            size_t ciphertext_size = std::min(remaining_bytes - tag_size, chunk_size);
            // std::cout << "🔍 Ciphertext size: " << ciphertext_size << "\n";

            // Extract ciphertext and tag
            std::vector<uint8_t> ciphertext(
                enc_data.begin() + processed_bytes,
                enc_data.begin() + processed_bytes + ciphertext_size
            );
            
            std::vector<uint8_t> tag(
                enc_data.begin() + processed_bytes + ciphertext_size,
                enc_data.begin() + processed_bytes + ciphertext_size + tag_size
            );

            /*
            std::cout << "🔍 Tag: ";
            for (auto b : tag) printf("%02x", b);
            std::cout << "\n";

            // Debug print first 16 bytes of ciphertext
            std::cout << "🔍 First 16 ciphertext bytes: ";
            for (size_t i = 0; i < 16 && i < ciphertext.size(); i++) {
                printf("%02x ", ciphertext[i]);
            }
            std::cout << "\n";

            std::cout << "🔄 Calling enclave...\n";
            */

            auto chunk_start = std::chrono::high_resolution_clock::now();
            int retval = 0;
            sgx_status_t ret = ecall_decrypt_aesgcm_chunk(
                global_eid, &retval,
                ciphertext.data(), ciphertext.size(),
                key.data(), key.size(),
                nonce.data(), nonce.size(),
                tag.data(), tag.size());

                
            auto chunk_end = std::chrono::high_resolution_clock::now();

            double chunk_time = std::chrono::duration<double, std::milli>(chunk_end - chunk_start).count();
            total_decrypt_time += chunk_time;

            if (ret != SGX_SUCCESS) {
                std::cerr << "❌ Enclave call failed (sgx_status=" << ret << ")\n";
                break;
            }
            if (retval != 0) {
                std::cerr << "❌ Decryption failed (retval=" << retval << ")\n";
                break;
            }

            processed_bytes += ciphertext_size + tag_size;
            /*
            std::cout << "✅ Chunk processed successfully\n";
            std::cout << "🔍 Total processed: " << processed_bytes << "/" << total_bytes 
                      << " (" << (100 * processed_bytes / total_bytes) << "%)\n";
            std::cout << "\n";
            */
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

        std::cout << "\n=== FINAL DECRYPT REPORT ===\n";
        std::cout << " Finished processing " << processed_bytes << " bytes\n";
        std::cout << " Total chunks processed: " << chunk_count << "\n";
        std::cout << "  Total time: " << elapsed << " ms\n";
        std::cout << "  Pure decrypt time: " << total_decrypt_time << " ms\n";
        std::cout << "  Average time per chunk: " << (total_decrypt_time/chunk_count) << " ms\n";
        std::cout << " Throughput: " << (processed_bytes/(total_decrypt_time/1000.0))/(1024*1024) << " MB/s\n";
        
        if (processed_bytes != total_bytes) {
            std::cerr << "❌ WARNING: Only processed " << processed_bytes 
                      << " out of " << total_bytes << " bytes\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ Exception: " << e.what() << "\n";
    }
}

void decrypt_and_search_log() {
    try {
        const char* key_path = "/home/ankit/data/aesgcm_key.bin";
        const char* vec_path = "/home/ankit/data/vector1.enc";

        // Read files
        auto key = read_file(key_path);
        auto enc_data = read_file(vec_path);

        // Validate key size
        if (key.size() != 16) {
            std::cerr << "❌ Invalid key size: " << key.size() << " bytes (expected 16)\n";
            return;
        }

        // AES-GCM parameters
        const size_t nonce_size = 12;
        const size_t tag_size = 16;
        const size_t header_size = nonce_size + tag_size;
        const size_t chunk_size = 120000000; // ~1MB chunks

        size_t total_bytes = enc_data.size();
        size_t processed_bytes = 0;
        size_t chunk_count = 0;
        size_t total_chunks = (total_bytes + chunk_size - 1) / chunk_size;
        double total_decrypt_time = 0.0;
        double total_search_time = 0.0;

        /*
        std::cout << "=== DEBUG INFORMATION ===\n";
        std::cout << "🔍 Total file size: " << total_bytes << " bytes\n";
        std::cout << "🔍 Chunk size: " << chunk_size << " bytes\n";
        std::cout << "🔍 Total chunks expected: " << total_chunks << "\n";
        std::cout << "🔍 Key: ";
        for (auto b : key) printf("%02x", b);
        std::cout << "\n";
        std::cout << "Starting decryption...\n\n";
        */

        auto start_time = std::chrono::high_resolution_clock::now();

        while (processed_bytes + header_size < total_bytes) {
            chunk_count++;
            /*
            std::cout << "\n=== Processing chunk " << chunk_count << " ===\n";
            std::cout << "🔍 Current offset: " << processed_bytes << "\n";
            */

            // Extract nonce
            if (processed_bytes + nonce_size > total_bytes) {
                std::cerr << "❌ Not enough bytes left for nonce (needed " << nonce_size 
                          << ", have " << (total_bytes - processed_bytes) << ")\n";
                break;
            }
            
            std::vector<uint8_t> nonce(
                enc_data.begin() + processed_bytes,
                enc_data.begin() + processed_bytes + nonce_size
            );
            processed_bytes += nonce_size;

            /*
            std::cout << "🔍 Nonce: ";
            for (auto b : nonce) printf("%02x", b);
            std::cout << "\n";
            */

            // Calculate ciphertext size
            size_t remaining_bytes = total_bytes - processed_bytes;
            if (remaining_bytes < tag_size) {
                std::cerr << "❌ Not enough bytes left for tag (needed " << tag_size 
                          << ", have " << remaining_bytes << ")\n";
                break;
            }
            
            size_t ciphertext_size = std::min(remaining_bytes - tag_size, chunk_size);
            // std::cout << "🔍 Ciphertext size: " << ciphertext_size << "\n";

            // Extract ciphertext and tag
            std::vector<uint8_t> ciphertext(
                enc_data.begin() + processed_bytes,
                enc_data.begin() + processed_bytes + ciphertext_size
            );
            
            std::vector<uint8_t> tag(
                enc_data.begin() + processed_bytes + ciphertext_size,
                enc_data.begin() + processed_bytes + ciphertext_size + tag_size
            );

            /*
            std::cout << "🔍 Tag: ";
            for (auto b : tag) printf("%02x", b);
            std::cout << "\n";

            std::cout << "🔍 First 16 ciphertext bytes: ";
            for (size_t i = 0; i < 16 && i < ciphertext.size(); i++) {
                printf("%02x ", ciphertext[i]);
            }
            std::cout << "\n";

            std::cout << "🔄 Calling enclave...\n";
            */

            auto chunk_start = std::chrono::high_resolution_clock::now();
            int retval = 0;
            sgx_status_t ret = ecall_decrypt_aesgcm_search_chunk(
                global_eid, &retval,
                ciphertext.data(), ciphertext.size(),
                key.data(), key.size(),
                nonce.data(), nonce.size(),
                tag.data(), tag.size());
            auto chunk_end = std::chrono::high_resolution_clock::now();

            double chunk_time = std::chrono::duration<double, std::milli>(chunk_end - chunk_start).count();
            total_decrypt_time += chunk_time;

            if (ret != SGX_SUCCESS) {
                std::cerr << "❌ Enclave call failed (sgx_status=" << ret << ")\n";
                break;
            }
            if (retval != 0) {
                std::cerr << "❌ Decryption failed (retval=" << retval << ")\n";
                break;
            }

            processed_bytes += ciphertext_size + tag_size;
            /*
            std::cout << "✅ Chunk processed successfully\n";
            std::cout << "🔍 Total processed: " << processed_bytes << "/" << total_bytes 
                      << " (" << (100 * processed_bytes / total_bytes) << "%)\n";
            std::cout << "\n";
            */
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

        std::cout << "\n=== FINAL SEARCH REPORT ===\n";
        std::cout << " Finished processing " << processed_bytes << " bytes\n";
        std::cout << " Total chunks processed: " << chunk_count << "\n";
        std::cout << "  Total wall time: " << elapsed << " ms\n";
        std::cout << "  Pure decrypt+search time: " << total_decrypt_time << " ms\n";
        std::cout << "  Average time per chunk: " << (total_decrypt_time/chunk_count) << " ms\n";
        std::cout << " Throughput: " << (processed_bytes/(total_decrypt_time/1000.0))/(1024*1024) << " MB/s\n";
        
        if (processed_bytes != total_bytes) {
            std::cerr << "❌ WARNING: Only processed " << processed_bytes 
                      << " out of " << total_bytes << " bytes\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ Exception: " << e.what() << "\n";
    }
}


void time_function_execution(const std::string& function_name, std::function<void()> func) {
    auto start_time = std::chrono::high_resolution_clock::now();

    // Redirect std::cout to stringstream
    std::stringstream buffer;
    std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

    func();  // Run the actual function

    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    // Restore std::cout
    std::cout.rdbuf(old);

    // Append additional report info
   // buffer << "\n=== FINAL REPORT ===\n";
    buffer << "✅ " << function_name << " completed in " << elapsed << " ms\n";

    final_reports.push_back(buffer.str());
}


void run_all_tests() {
    std::cout << "=== Starting All Tests ===\n";

    time_function_execution("Load Vector in Chunks", load_vector_in_chunks);
    time_function_execution("Decrypt and Log", decrypt_and_log);
    time_function_execution("Decrypt and Search Log", decrypt_and_search_log);

    // Collect combined report into a stringstream
    std::ostringstream combined_report;

    combined_report << "\n\n=== COMBINED FINAL REPORT ===\n\n";
       std::cout << "\n\n=== COMBINED FINAL REPORT ===\n";

         print_system_info();


    for (const auto& report : final_reports) {
        std::cout << report << "\n";
    }
    // Redirect cout temporarily to combined_report for system info
    {
        std::streambuf* old_cout = std::cout.rdbuf();
        std::cout.rdbuf(combined_report.rdbuf());

        print_system_info();

        // Restore cout
        std::cout.rdbuf(old_cout);
    }

    // Append all final reports
    for (const auto& report : final_reports) {
        combined_report << report << "\n";
    }

    // Write combined report to file
    std::string report_path = "/home/ankit/data/combined_report.txt";
    std::ofstream out(report_path);
    if (out.is_open()) {
        out << combined_report.str();
        out.close();
        std::cout << "✅ Combined report saved to " << report_path << "\n";
    } else {
        std::cerr << "❌ Failed to open file " << report_path << " for writing\n";
        return;
    }

    // Call Python logger script to process combined report file
    std::string cmd = "python3 /home/ankit/utils/log_combined_report.py " + report_path;
    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "⚠️ Python logger script exited with code " << ret << "\n";
    }
}

void run_enclave_memory_tests() {
    sgx_status_t status;

    printf("🔍 Testing heap allocation in enclave...\n");
    status = ecall_test_heap_allocation(global_eid);
    if (status != SGX_SUCCESS) {
        printf("❌ ecall_test_heap_allocation failed (0x%x)\n", status);
    }

    printf("🔍 Testing max chunk allocation in enclave...\n");
    status = ecall_test_max_chunk_buffer(global_eid);
    if (status != SGX_SUCCESS) {
        printf("❌ ecall_test_max_chunk_buffer failed (0x%x)\n", status);
    }
}

int main() {
    if (initialize_enclave() < 0) return -1;
    //un_all_tests();
    // Comment out decrypt_and_log() and call the new function instead
   //  load_vector_in_chunks();
    
   // decrypt_and_log();
   // decrypt_and_search_log();
   run_enclave_memory_tests();
    sgx_destroy_enclave(global_eid);
    return 0;
}
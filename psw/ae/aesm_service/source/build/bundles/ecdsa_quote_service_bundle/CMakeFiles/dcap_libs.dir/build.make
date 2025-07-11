# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build

# Utility rule file for dcap_libs.

# Include the progress variables for this target.
include bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/progress.make

bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs: /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_qe3_logic.so
bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs: /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libdcap_quoteprov.so
bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs: /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_default_qcnl_wrapper.so


/home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_qe3_logic.so:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_qe3_logic.so"
	cd /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/quote_wrapper/quote/linux && make all

/home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libdcap_quoteprov.so: /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_default_qcnl_wrapper.so
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Generating /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libdcap_quoteprov.so"
	cd /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/qpl/linux && make all

/home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_default_qcnl_wrapper.so:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Generating /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_default_qcnl_wrapper.so"
	cd /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/qcnl/linux && make all

dcap_libs: bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs
dcap_libs: /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_qe3_logic.so
dcap_libs: /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libdcap_quoteprov.so
dcap_libs: /home/ankit71297129/linux-sgx/external/dcap_source/QuoteGeneration/build/linux/libsgx_default_qcnl_wrapper.so
dcap_libs: bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/build.make

.PHONY : dcap_libs

# Rule to build all files generated by this target.
bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/build: dcap_libs

.PHONY : bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/build

bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/clean:
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/ecdsa_quote_service_bundle && $(CMAKE_COMMAND) -P CMakeFiles/dcap_libs.dir/cmake_clean.cmake
.PHONY : bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/clean

bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/depend:
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/bundles/ecdsa_quote_service_bundle /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/ecdsa_quote_service_bundle /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : bundles/ecdsa_quote_service_bundle/CMakeFiles/dcap_libs.dir/depend


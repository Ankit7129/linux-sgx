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

# Include any dependencies generated for this target.
include bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/depend.make

# Include the progress variables for this target.
include bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/progress.make

# Include the compile flags for this target's objects.
include bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/flags.make

bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_resources.cpp: bundles/quote_ex_service_bundle/quote_ex_service_bundle/res_0.zip
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Checking resource dependencies for quote_ex_service_bundle"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/cmake -E copy /home/ankit71297129/linux-sgx/external/CppMicroServices/local-install/share/cppmicroservices4/cmake/CMakeResourceDependencies.cpp /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_resources.cpp

bundles/quote_ex_service_bundle/quote_ex_service_bundle/res_0.zip: ../bundles/quote_ex_service_bundle/manifest.json
bundles/quote_ex_service_bundle/quote_ex_service_bundle/res_0.zip: /home/ankit71297129/linux-sgx/external/CppMicroServices/local-install/bin/usResourceCompiler4
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Checking resource dependencies for quote_ex_service_bundle"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/bundles/quote_ex_service_bundle && /usr/bin/cmake -E make_directory /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/bundles/quote_ex_service_bundle && /home/ankit71297129/linux-sgx/external/CppMicroServices/local-install/bin/usResourceCompiler4 -o /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/res_0.zip -n quote_ex_service_bundle_name -r manifest.json

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.o: bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/flags.make
bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.o: ../bundles/quote_ex_service_bundle/quote_ex_service_bundle.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/bundles/quote_ex_service_bundle/quote_ex_service_bundle.cpp

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/bundles/quote_ex_service_bundle/quote_ex_service_bundle.cpp > CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.i

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/bundles/quote_ex_service_bundle/quote_ex_service_bundle.cpp -o CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.s

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.o: bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/flags.make
bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.o: bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_resources.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_resources.cpp

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_resources.cpp > CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.i

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_resources.cpp -o CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.s

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.o: bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/flags.make
bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.o: bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_init.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_init.cpp

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_init.cpp > CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.i

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_init.cpp -o CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.s

# Object files for target quote_ex_service_bundle
quote_ex_service_bundle_OBJECTS = \
"CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.o" \
"CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.o" \
"CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.o"

# External object files for target quote_ex_service_bundle
quote_ex_service_bundle_EXTERNAL_OBJECTS =

bin/bundles/libquote_ex_service_bundle.so: bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle.cpp.o
bin/bundles/libquote_ex_service_bundle.so: bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_resources.cpp.o
bin/bundles/libquote_ex_service_bundle.so: bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/quote_ex_service_bundle/cppmicroservices_init.cpp.o
bin/bundles/libquote_ex_service_bundle.so: bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/build.make
bin/bundles/libquote_ex_service_bundle.so: /home/ankit71297129/linux-sgx/external/CppMicroServices/local-install/lib/libCppMicroServices.so.4.0.0
bin/bundles/libquote_ex_service_bundle.so: bin/libutils.so
bin/bundles/libquote_ex_service_bundle.so: bin/liboal.so
bin/bundles/libquote_ex_service_bundle.so: ../../../../../external/dcap_source/prebuilt/openssl/lib/linux64/libcrypto.a
bin/bundles/libquote_ex_service_bundle.so: ../../../../../external/rdrand/src/librdrand.a
bin/bundles/libquote_ex_service_bundle.so: bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking CXX shared library ../../bin/bundles/libquote_ex_service_bundle.so"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/quote_ex_service_bundle.dir/link.txt --verbose=$(VERBOSE)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold "Appending zipped resources to quote_ex_service_bundle"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/bundles/quote_ex_service_bundle && objcopy --add-section .note.sgx.aesm_resource=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/quote_ex_service_bundle/res_0.zip /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bin/bundles/libquote_ex_service_bundle.so

# Rule to build all files generated by this target.
bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/build: bin/bundles/libquote_ex_service_bundle.so

.PHONY : bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/build

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/clean:
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle && $(CMAKE_COMMAND) -P CMakeFiles/quote_ex_service_bundle.dir/cmake_clean.cmake
.PHONY : bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/clean

bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/depend: bundles/quote_ex_service_bundle/quote_ex_service_bundle/cppmicroservices_resources.cpp
bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/depend: bundles/quote_ex_service_bundle/quote_ex_service_bundle/res_0.zip
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/bundles/quote_ex_service_bundle /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : bundles/quote_ex_service_bundle/CMakeFiles/quote_ex_service_bundle.dir/depend


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
include oal/CMakeFiles/oal.dir/depend.make

# Include the progress variables for this target.
include oal/CMakeFiles/oal.dir/progress.make

# Include the compile flags for this target's objects.
include oal/CMakeFiles/oal.dir/flags.make

oal/CMakeFiles/oal.dir/linux/aesm_thread.cpp.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/linux/aesm_thread.cpp.o: ../oal/linux/aesm_thread.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object oal/CMakeFiles/oal.dir/linux/aesm_thread.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/oal.dir/linux/aesm_thread.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/aesm_thread.cpp

oal/CMakeFiles/oal.dir/linux/aesm_thread.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/oal.dir/linux/aesm_thread.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/aesm_thread.cpp > CMakeFiles/oal.dir/linux/aesm_thread.cpp.i

oal/CMakeFiles/oal.dir/linux/aesm_thread.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/oal.dir/linux/aesm_thread.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/aesm_thread.cpp -o CMakeFiles/oal.dir/linux/aesm_thread.cpp.s

oal/CMakeFiles/oal.dir/linux/aesm_util.cpp.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/linux/aesm_util.cpp.o: ../oal/linux/aesm_util.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object oal/CMakeFiles/oal.dir/linux/aesm_util.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -fno-optimize-sibling-calls -o CMakeFiles/oal.dir/linux/aesm_util.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/aesm_util.cpp

oal/CMakeFiles/oal.dir/linux/aesm_util.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/oal.dir/linux/aesm_util.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -fno-optimize-sibling-calls -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/aesm_util.cpp > CMakeFiles/oal.dir/linux/aesm_util.cpp.i

oal/CMakeFiles/oal.dir/linux/aesm_util.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/oal.dir/linux/aesm_util.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -fno-optimize-sibling-calls -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/aesm_util.cpp -o CMakeFiles/oal.dir/linux/aesm_util.cpp.s

oal/CMakeFiles/oal.dir/linux/error_report.cpp.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/linux/error_report.cpp.o: ../oal/linux/error_report.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object oal/CMakeFiles/oal.dir/linux/error_report.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/oal.dir/linux/error_report.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/error_report.cpp

oal/CMakeFiles/oal.dir/linux/error_report.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/oal.dir/linux/error_report.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/error_report.cpp > CMakeFiles/oal.dir/linux/error_report.cpp.i

oal/CMakeFiles/oal.dir/linux/error_report.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/oal.dir/linux/error_report.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/error_report.cpp -o CMakeFiles/oal.dir/linux/error_report.cpp.s

oal/CMakeFiles/oal.dir/linux/event_strings.cpp.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/linux/event_strings.cpp.o: ../oal/linux/event_strings.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object oal/CMakeFiles/oal.dir/linux/event_strings.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/oal.dir/linux/event_strings.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/event_strings.cpp

oal/CMakeFiles/oal.dir/linux/event_strings.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/oal.dir/linux/event_strings.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/event_strings.cpp > CMakeFiles/oal.dir/linux/event_strings.cpp.i

oal/CMakeFiles/oal.dir/linux/event_strings.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/oal.dir/linux/event_strings.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/event_strings.cpp -o CMakeFiles/oal.dir/linux/event_strings.cpp.s

oal/CMakeFiles/oal.dir/linux/internal_log.cpp.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/linux/internal_log.cpp.o: ../oal/linux/internal_log.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object oal/CMakeFiles/oal.dir/linux/internal_log.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/oal.dir/linux/internal_log.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/internal_log.cpp

oal/CMakeFiles/oal.dir/linux/internal_log.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/oal.dir/linux/internal_log.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/internal_log.cpp > CMakeFiles/oal.dir/linux/internal_log.cpp.i

oal/CMakeFiles/oal.dir/linux/internal_log.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/oal.dir/linux/internal_log.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/internal_log.cpp -o CMakeFiles/oal.dir/linux/internal_log.cpp.s

oal/CMakeFiles/oal.dir/linux/oal_power.cpp.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/linux/oal_power.cpp.o: ../oal/linux/oal_power.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object oal/CMakeFiles/oal.dir/linux/oal_power.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/oal.dir/linux/oal_power.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/oal_power.cpp

oal/CMakeFiles/oal.dir/linux/oal_power.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/oal.dir/linux/oal_power.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/oal_power.cpp > CMakeFiles/oal.dir/linux/oal_power.cpp.i

oal/CMakeFiles/oal.dir/linux/oal_power.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/oal.dir/linux/oal_power.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/oal_power.cpp -o CMakeFiles/oal.dir/linux/oal_power.cpp.s

oal/CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.o: ../oal/linux/persistent_storage_table.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object oal/CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.o -c /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/persistent_storage_table.cpp

oal/CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/persistent_storage_table.cpp > CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.i

oal/CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal/linux/persistent_storage_table.cpp -o CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.s

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.o: /home/ankit71297129/linux-sgx/common/src/se_thread.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.o   -c /home/ankit71297129/linux-sgx/common/src/se_thread.c

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ankit71297129/linux-sgx/common/src/se_thread.c > CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.i

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ankit71297129/linux-sgx/common/src/se_thread.c -o CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.s

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.o: /home/ankit71297129/linux-sgx/common/src/se_trace.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.o   -c /home/ankit71297129/linux-sgx/common/src/se_trace.c

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ankit71297129/linux-sgx/common/src/se_trace.c > CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.i

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ankit71297129/linux-sgx/common/src/se_trace.c -o CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.s

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.o: oal/CMakeFiles/oal.dir/flags.make
oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.o: /home/ankit71297129/linux-sgx/common/src/se_time.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building C object oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.o"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.o   -c /home/ankit71297129/linux-sgx/common/src/se_time.c

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.i"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ankit71297129/linux-sgx/common/src/se_time.c > CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.i

oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.s"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ankit71297129/linux-sgx/common/src/se_time.c -o CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.s

# Object files for target oal
oal_OBJECTS = \
"CMakeFiles/oal.dir/linux/aesm_thread.cpp.o" \
"CMakeFiles/oal.dir/linux/aesm_util.cpp.o" \
"CMakeFiles/oal.dir/linux/error_report.cpp.o" \
"CMakeFiles/oal.dir/linux/event_strings.cpp.o" \
"CMakeFiles/oal.dir/linux/internal_log.cpp.o" \
"CMakeFiles/oal.dir/linux/oal_power.cpp.o" \
"CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.o" \
"CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.o" \
"CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.o" \
"CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.o"

# External object files for target oal
oal_EXTERNAL_OBJECTS =

bin/liboal.so: oal/CMakeFiles/oal.dir/linux/aesm_thread.cpp.o
bin/liboal.so: oal/CMakeFiles/oal.dir/linux/aesm_util.cpp.o
bin/liboal.so: oal/CMakeFiles/oal.dir/linux/error_report.cpp.o
bin/liboal.so: oal/CMakeFiles/oal.dir/linux/event_strings.cpp.o
bin/liboal.so: oal/CMakeFiles/oal.dir/linux/internal_log.cpp.o
bin/liboal.so: oal/CMakeFiles/oal.dir/linux/oal_power.cpp.o
bin/liboal.so: oal/CMakeFiles/oal.dir/linux/persistent_storage_table.cpp.o
bin/liboal.so: oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_thread.c.o
bin/liboal.so: oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_trace.c.o
bin/liboal.so: oal/CMakeFiles/oal.dir/home/ankit71297129/linux-sgx/common/src/se_time.c.o
bin/liboal.so: oal/CMakeFiles/oal.dir/build.make
bin/liboal.so: oal/CMakeFiles/oal.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Linking CXX shared library ../bin/liboal.so"
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/oal.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
oal/CMakeFiles/oal.dir/build: bin/liboal.so

.PHONY : oal/CMakeFiles/oal.dir/build

oal/CMakeFiles/oal.dir/clean:
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal && $(CMAKE_COMMAND) -P CMakeFiles/oal.dir/cmake_clean.cmake
.PHONY : oal/CMakeFiles/oal.dir/clean

oal/CMakeFiles/oal.dir/depend:
	cd /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/oal /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal /home/ankit71297129/linux-sgx/psw/ae/aesm_service/source/build/oal/CMakeFiles/oal.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : oal/CMakeFiles/oal.dir/depend


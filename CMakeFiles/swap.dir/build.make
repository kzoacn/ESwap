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
CMAKE_SOURCE_DIR = /home/kzoacn/ESwap

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kzoacn/ESwap

# Include any dependencies generated for this target.
include CMakeFiles/swap.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/swap.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/swap.dir/flags.make

CMakeFiles/swap.dir/test/swap.cpp.o: CMakeFiles/swap.dir/flags.make
CMakeFiles/swap.dir/test/swap.cpp.o: test/swap.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kzoacn/ESwap/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/swap.dir/test/swap.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/swap.dir/test/swap.cpp.o -c /home/kzoacn/ESwap/test/swap.cpp

CMakeFiles/swap.dir/test/swap.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/swap.dir/test/swap.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kzoacn/ESwap/test/swap.cpp > CMakeFiles/swap.dir/test/swap.cpp.i

CMakeFiles/swap.dir/test/swap.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/swap.dir/test/swap.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kzoacn/ESwap/test/swap.cpp -o CMakeFiles/swap.dir/test/swap.cpp.s

# Object files for target swap
swap_OBJECTS = \
"CMakeFiles/swap.dir/test/swap.cpp.o"

# External object files for target swap
swap_EXTERNAL_OBJECTS =

bin/swap: CMakeFiles/swap.dir/test/swap.cpp.o
bin/swap: CMakeFiles/swap.dir/build.make
bin/swap: /usr/lib/x86_64-linux-gnu/libssl.so
bin/swap: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/swap: /usr/lib/x86_64-linux-gnu/libboost_system.so.1.71.0
bin/swap: /usr/lib/x86_64-linux-gnu/libgmp.so
bin/swap: libESwap.so
bin/swap: /usr/local/lib/libemp-tool.so
bin/swap: /usr/lib/x86_64-linux-gnu/libssl.so
bin/swap: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/swap: /usr/lib/x86_64-linux-gnu/libboost_system.so.1.71.0
bin/swap: /usr/lib/x86_64-linux-gnu/libgmp.so
bin/swap: /usr/local/lib/libemp-tool.so
bin/swap: CMakeFiles/swap.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kzoacn/ESwap/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bin/swap"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/swap.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/swap.dir/build: bin/swap

.PHONY : CMakeFiles/swap.dir/build

CMakeFiles/swap.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/swap.dir/cmake_clean.cmake
.PHONY : CMakeFiles/swap.dir/clean

CMakeFiles/swap.dir/depend:
	cd /home/kzoacn/ESwap && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap/CMakeFiles/swap.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/swap.dir/depend


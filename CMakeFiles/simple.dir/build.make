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
include CMakeFiles/simple.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/simple.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/simple.dir/flags.make

CMakeFiles/simple.dir/test/simple.cpp.o: CMakeFiles/simple.dir/flags.make
CMakeFiles/simple.dir/test/simple.cpp.o: test/simple.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kzoacn/ESwap/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/simple.dir/test/simple.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/simple.dir/test/simple.cpp.o -c /home/kzoacn/ESwap/test/simple.cpp

CMakeFiles/simple.dir/test/simple.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/simple.dir/test/simple.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kzoacn/ESwap/test/simple.cpp > CMakeFiles/simple.dir/test/simple.cpp.i

CMakeFiles/simple.dir/test/simple.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/simple.dir/test/simple.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kzoacn/ESwap/test/simple.cpp -o CMakeFiles/simple.dir/test/simple.cpp.s

# Object files for target simple
simple_OBJECTS = \
"CMakeFiles/simple.dir/test/simple.cpp.o"

# External object files for target simple
simple_EXTERNAL_OBJECTS =

bin/simple: CMakeFiles/simple.dir/test/simple.cpp.o
bin/simple: CMakeFiles/simple.dir/build.make
bin/simple: /usr/lib/x86_64-linux-gnu/libssl.so
bin/simple: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/simple: /usr/lib/x86_64-linux-gnu/libboost_system.so.1.71.0
bin/simple: /usr/lib/x86_64-linux-gnu/libgmp.so
bin/simple: libESwap.so
bin/simple: /usr/local/lib/libemp-tool.so
bin/simple: /usr/lib/x86_64-linux-gnu/libssl.so
bin/simple: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/simple: /usr/lib/x86_64-linux-gnu/libboost_system.so.1.71.0
bin/simple: /usr/lib/x86_64-linux-gnu/libgmp.so
bin/simple: /usr/local/lib/libemp-tool.so
bin/simple: CMakeFiles/simple.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kzoacn/ESwap/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bin/simple"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/simple.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/simple.dir/build: bin/simple

.PHONY : CMakeFiles/simple.dir/build

CMakeFiles/simple.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/simple.dir/cmake_clean.cmake
.PHONY : CMakeFiles/simple.dir/clean

CMakeFiles/simple.dir/depend:
	cd /home/kzoacn/ESwap && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap/CMakeFiles/simple.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/simple.dir/depend


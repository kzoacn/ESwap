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
include CMakeFiles/ESwap.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ESwap.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ESwap.dir/flags.make

CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.o: CMakeFiles/ESwap.dir/flags.make
CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.o: ESwap/ESwap.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kzoacn/ESwap/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.o -c /home/kzoacn/ESwap/ESwap/ESwap.cpp

CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kzoacn/ESwap/ESwap/ESwap.cpp > CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.i

CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kzoacn/ESwap/ESwap/ESwap.cpp -o CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.s

# Object files for target ESwap
ESwap_OBJECTS = \
"CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.o"

# External object files for target ESwap
ESwap_EXTERNAL_OBJECTS =

libESwap.so: CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.o
libESwap.so: CMakeFiles/ESwap.dir/build.make
libESwap.so: CMakeFiles/ESwap.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kzoacn/ESwap/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libESwap.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ESwap.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ESwap.dir/build: libESwap.so

.PHONY : CMakeFiles/ESwap.dir/build

CMakeFiles/ESwap.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ESwap.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ESwap.dir/clean

CMakeFiles/ESwap.dir/depend:
	cd /home/kzoacn/ESwap && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap /home/kzoacn/ESwap/CMakeFiles/ESwap.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ESwap.dir/depend


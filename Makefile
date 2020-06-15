# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


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

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target install/local
install/local: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/usr/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local

# Special rule for the target install/local
install/local/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/usr/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local/fast

# Special rule for the target install
install: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/usr/bin/cmake -P cmake_install.cmake
.PHONY : install

# Special rule for the target install
install/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/usr/bin/cmake -P cmake_install.cmake
.PHONY : install/fast

# Special rule for the target list_install_components
list_install_components:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Available install components are: \"Unspecified\""
.PHONY : list_install_components

# Special rule for the target list_install_components
list_install_components/fast: list_install_components

.PHONY : list_install_components/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# Special rule for the target install/strip
install/strip: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing the project stripped..."
	/usr/bin/cmake -DCMAKE_INSTALL_DO_STRIP=1 -P cmake_install.cmake
.PHONY : install/strip

# Special rule for the target install/strip
install/strip/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing the project stripped..."
	/usr/bin/cmake -DCMAKE_INSTALL_DO_STRIP=1 -P cmake_install.cmake
.PHONY : install/strip/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/kzoacn/ESwap/CMakeFiles /home/kzoacn/ESwap/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/kzoacn/ESwap/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named swap

# Build rule for target.
swap: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 swap
.PHONY : swap

# fast build rule for target.
swap/fast:
	$(MAKE) -f CMakeFiles/swap.dir/build.make CMakeFiles/swap.dir/build
.PHONY : swap/fast

#=============================================================================
# Target rules for targets named simple

# Build rule for target.
simple: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 simple
.PHONY : simple

# fast build rule for target.
simple/fast:
	$(MAKE) -f CMakeFiles/simple.dir/build.make CMakeFiles/simple.dir/build
.PHONY : simple/fast

#=============================================================================
# Target rules for targets named ESwap

# Build rule for target.
ESwap: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 ESwap
.PHONY : ESwap

# fast build rule for target.
ESwap/fast:
	$(MAKE) -f CMakeFiles/ESwap.dir/build.make CMakeFiles/ESwap.dir/build
.PHONY : ESwap/fast

ESwap/ESwap.o: ESwap/ESwap.cpp.o

.PHONY : ESwap/ESwap.o

# target to build an object file
ESwap/ESwap.cpp.o:
	$(MAKE) -f CMakeFiles/ESwap.dir/build.make CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.o
.PHONY : ESwap/ESwap.cpp.o

ESwap/ESwap.i: ESwap/ESwap.cpp.i

.PHONY : ESwap/ESwap.i

# target to preprocess a source file
ESwap/ESwap.cpp.i:
	$(MAKE) -f CMakeFiles/ESwap.dir/build.make CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.i
.PHONY : ESwap/ESwap.cpp.i

ESwap/ESwap.s: ESwap/ESwap.cpp.s

.PHONY : ESwap/ESwap.s

# target to generate assembly for a file
ESwap/ESwap.cpp.s:
	$(MAKE) -f CMakeFiles/ESwap.dir/build.make CMakeFiles/ESwap.dir/ESwap/ESwap.cpp.s
.PHONY : ESwap/ESwap.cpp.s

test/simple.o: test/simple.cpp.o

.PHONY : test/simple.o

# target to build an object file
test/simple.cpp.o:
	$(MAKE) -f CMakeFiles/simple.dir/build.make CMakeFiles/simple.dir/test/simple.cpp.o
.PHONY : test/simple.cpp.o

test/simple.i: test/simple.cpp.i

.PHONY : test/simple.i

# target to preprocess a source file
test/simple.cpp.i:
	$(MAKE) -f CMakeFiles/simple.dir/build.make CMakeFiles/simple.dir/test/simple.cpp.i
.PHONY : test/simple.cpp.i

test/simple.s: test/simple.cpp.s

.PHONY : test/simple.s

# target to generate assembly for a file
test/simple.cpp.s:
	$(MAKE) -f CMakeFiles/simple.dir/build.make CMakeFiles/simple.dir/test/simple.cpp.s
.PHONY : test/simple.cpp.s

test/swap.o: test/swap.cpp.o

.PHONY : test/swap.o

# target to build an object file
test/swap.cpp.o:
	$(MAKE) -f CMakeFiles/swap.dir/build.make CMakeFiles/swap.dir/test/swap.cpp.o
.PHONY : test/swap.cpp.o

test/swap.i: test/swap.cpp.i

.PHONY : test/swap.i

# target to preprocess a source file
test/swap.cpp.i:
	$(MAKE) -f CMakeFiles/swap.dir/build.make CMakeFiles/swap.dir/test/swap.cpp.i
.PHONY : test/swap.cpp.i

test/swap.s: test/swap.cpp.s

.PHONY : test/swap.s

# target to generate assembly for a file
test/swap.cpp.s:
	$(MAKE) -f CMakeFiles/swap.dir/build.make CMakeFiles/swap.dir/test/swap.cpp.s
.PHONY : test/swap.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... install/local"
	@echo "... install"
	@echo "... list_install_components"
	@echo "... rebuild_cache"
	@echo "... edit_cache"
	@echo "... swap"
	@echo "... install/strip"
	@echo "... simple"
	@echo "... ESwap"
	@echo "... ESwap/ESwap.o"
	@echo "... ESwap/ESwap.i"
	@echo "... ESwap/ESwap.s"
	@echo "... test/simple.o"
	@echo "... test/simple.i"
	@echo "... test/simple.s"
	@echo "... test/swap.o"
	@echo "... test/swap.i"
	@echo "... test/swap.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

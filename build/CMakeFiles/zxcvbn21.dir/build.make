# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/hassan/CLionProjects/CondEncCCS24

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/hassan/CLionProjects/CondEncCCS24/build

# Utility rule file for zxcvbn21.

# Include any custom commands dependencies for this target.
include CMakeFiles/zxcvbn21.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/zxcvbn21.dir/progress.make

CMakeFiles/zxcvbn21: CMakeFiles/zxcvbn21-complete

CMakeFiles/zxcvbn21-complete: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-install
CMakeFiles/zxcvbn21-complete: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-mkdir
CMakeFiles/zxcvbn21-complete: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-download
CMakeFiles/zxcvbn21-complete: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update
CMakeFiles/zxcvbn21-complete: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-patch
CMakeFiles/zxcvbn21-complete: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-configure
CMakeFiles/zxcvbn21-complete: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-build
CMakeFiles/zxcvbn21-complete: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-install
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Completed 'zxcvbn21'"
	/usr/bin/cmake -E make_directory /home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles
	/usr/bin/cmake -E touch /home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles/zxcvbn21-complete
	/usr/bin/cmake -E touch /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-done

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update:
.PHONY : zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-build: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-configure
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Performing build step for 'zxcvbn21'"
	cd /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-build && /usr/bin/cmake -P /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-build-.cmake
	cd /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-build && /usr/bin/cmake -E touch /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-build

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-configure: zxcvbn21-prefix/tmp/zxcvbn21-cfgcmd.txt
zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-configure: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-patch
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "No configure step for 'zxcvbn21'"
	cd /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-build && /usr/bin/cmake -E echo_append
	cd /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-build && /usr/bin/cmake -E touch /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-configure

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-download: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-gitinfo.txt
zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-download: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-mkdir
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Performing download step (git clone) for 'zxcvbn21'"
	cd /home/hassan/CLionProjects/CondEncCCS24/3rdparty && /usr/bin/cmake -P /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-download-.cmake
	cd /home/hassan/CLionProjects/CondEncCCS24/3rdparty && /usr/bin/cmake -E touch /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-download

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-install: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-build
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "No install step for 'zxcvbn21'"
	cd /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-build && /usr/bin/cmake -E echo_append
	cd /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-build && /usr/bin/cmake -E touch /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-install

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-mkdir:
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Creating directories for 'zxcvbn21'"
	/usr/bin/cmake -Dcfgdir= -P /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/tmp/zxcvbn21-mkdirs.cmake
	/usr/bin/cmake -E touch /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-mkdir

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-patch: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-patch-info.txt
zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-patch: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "No patch step for 'zxcvbn21'"
	/usr/bin/cmake -E echo_append
	/usr/bin/cmake -E touch /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-patch

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update:
.PHONY : zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update

zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update: zxcvbn21-prefix/tmp/zxcvbn21-gitupdate.cmake
zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update-info.txt
zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-download
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Performing update step for 'zxcvbn21'"
	cd /home/hassan/CLionProjects/CondEncCCS24/3rdparty/zxcvbn21 && /usr/bin/cmake -Dcan_fetch=YES -P /home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/tmp/zxcvbn21-gitupdate.cmake

zxcvbn21: CMakeFiles/zxcvbn21
zxcvbn21: CMakeFiles/zxcvbn21-complete
zxcvbn21: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-build
zxcvbn21: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-configure
zxcvbn21: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-download
zxcvbn21: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-install
zxcvbn21: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-mkdir
zxcvbn21: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-patch
zxcvbn21: zxcvbn21-prefix/src/zxcvbn21-stamp/zxcvbn21-update
zxcvbn21: CMakeFiles/zxcvbn21.dir/build.make
.PHONY : zxcvbn21

# Rule to build all files generated by this target.
CMakeFiles/zxcvbn21.dir/build: zxcvbn21
.PHONY : CMakeFiles/zxcvbn21.dir/build

CMakeFiles/zxcvbn21.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/zxcvbn21.dir/cmake_clean.cmake
.PHONY : CMakeFiles/zxcvbn21.dir/clean

CMakeFiles/zxcvbn21.dir/depend:
	cd /home/hassan/CLionProjects/CondEncCCS24/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hassan/CLionProjects/CondEncCCS24 /home/hassan/CLionProjects/CondEncCCS24 /home/hassan/CLionProjects/CondEncCCS24/build /home/hassan/CLionProjects/CondEncCCS24/build /home/hassan/CLionProjects/CondEncCCS24/build/CMakeFiles/zxcvbn21.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/zxcvbn21.dir/depend


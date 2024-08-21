# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/hassan/CLionProjects/CondEncCCS24/3rdparty/plog110"
  "/home/hassan/CLionProjects/CondEncCCS24/build/plog110-prefix/src/plog110-build"
  "/home/hassan/CLionProjects/CondEncCCS24/build/plog110"
  "/home/hassan/CLionProjects/CondEncCCS24/build/plog110-prefix/tmp"
  "/home/hassan/CLionProjects/CondEncCCS24/build/plog110-prefix/src/plog110-stamp"
  "/home/hassan/CLionProjects/CondEncCCS24/build/plog110-prefix/src"
  "/home/hassan/CLionProjects/CondEncCCS24/build/plog110-prefix/src/plog110-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/hassan/CLionProjects/CondEncCCS24/build/plog110-prefix/src/plog110-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/hassan/CLionProjects/CondEncCCS24/build/plog110-prefix/src/plog110-stamp${cfgdir}") # cfgdir has leading slash
endif()

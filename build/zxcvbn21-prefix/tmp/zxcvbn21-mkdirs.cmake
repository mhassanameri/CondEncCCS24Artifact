# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/hassan/CLionProjects/CondEncCCS24/3rdparty/zxcvbn21"
  "/home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-build"
  "/home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix"
  "/home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/tmp"
  "/home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp"
  "/home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src"
  "/home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/hassan/CLionProjects/CondEncCCS24/build/zxcvbn21-prefix/src/zxcvbn21-stamp${cfgdir}") # cfgdir has leading slash
endif()

cmake_minimum_required(VERSION 3.28)
project(condenccpp)

set (condenccpp_VERSION_MAJOR 1)
set (condenccpp_VERSION_MINOR 0)
set (condenccpp_VERSION_PATCH 7)


## Set compiler flags
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-DDEBUG)
    set(CMAKE_VERBOSE_MAKEFILE true)
endif()

set(CMAKE_PREFER_SHARED_LIBRARIES $ENV{CMAKE_PREFER_SHARED_LIBRARIES})
message(STATUS "Building with shared libraries preferred: ${CMAKE_PREFER_SHARED_LIBRARIES}")

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_COMPILER ${CC})
set(CMAKE_CXX_COMPILER ${CC})
set(CMAKE_CXX_FLAGS "-Wall -std=c++17")
set (GCC_NO_COMMON_BLOCKS "NO")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/3rdparty/")
message(STATUS "Configuring dependencies: cryptopp, zxcvbn and plog")



if(${CRYPTOPP_SHARED})
    message(STATUS "Crypto++ setup to be shared.")
else()
    message(STATUS "Crypto++ setup to be compiled.")
endif()



# Zxcvbn source (always used)
set(ZXCVBN_URL https://github.com/tsyrogit/zxcvbn-c.git)
set(ZXCVBN_TAG v2.1)
set(ZXCVBN_PREFIX zxcvbn21)
message(STATUS "Setup zxcvbn from github")
include(zxcvbn)

## Plog source(always used)
set(PLOG_URL https://github.com/SergiusTheBest/plog.git)
set(PLOG_TAG 1.1.0)
set(PLOG_PREFIX plog110)
message(STATUS "Setup plog from github")
include(plog)

#set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /opt/local/lib)

include_directories("/usr/local/include")
#include_directories("/usr/local/include/cryptopp")
#include_directories("argon2/phcargon2/include")
include_directories("paillier")

include_directories( ${MY_EXTERNAL_SOURCE__DIR})

set(INSTALL_DATA_DIR etc)
set(INSTALL_BIN_DIR bin)
set(INSTALL_LIB_DIR lib/security)
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
        "${PROJECT_SOURCE_DIR}/CondEncCPPconfig.h.in"
        "${PROJECT_BINARY_DIR}/src/CondEncCPPconfig.h"
)
### Build each component
# build main source code


add_subdirectory(src)
add_subdirectory(cryptopp-cmake)
# build pam module
#add_subdirectory(src/pam_modules)




# testing
include(CTest)
ENABLE_TESTING()

add_subdirectory(test) #//TODO: we need to add the test directory

file(COPY PWDvsTyposDataSet DESTINATION test )
file(COPY GeneratePlotsPdfs DESTINATION . )

#file(COPY TestScript.py DESTINATION test )
file(COPY TestScript.sh DESTINATION test  FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)

file(COPY FixingTestInstallCryptoPP.sh  DESTINATION . FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
file(COPY Generatepdf.sh  DESTINATION GeneratePlotsPdfs FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
#set(SCRIPT_PATH "${CMAKE_BINARY_DIR}/test/TestScript.sh")


if(APPLE)
    SET(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
endif()

# For creating install packages
# add_subdirectory(install)

#INCLUDE(install/CMakeLists.txt)
INCLUDE(CPack)



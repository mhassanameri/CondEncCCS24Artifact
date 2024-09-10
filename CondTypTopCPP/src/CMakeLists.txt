### Protobuf is a strict dependency here

#set(Protobuf_PREFIX_PATH
#        "/homes/mameriek/protobuf/usr/local/include"
#        "/homes/mameriek/protobuf/usr/local/lib"
#        "/homes/mameriek/protobuf/usr/local/bin" )
#list(APPEND CMAKE_PREFIX_PATH "${Protobuf_PREFIX_PATH}")
link_directories("/usr/lib/x86_64-linux-gnu")

find_package(Protobuf REQUIRED)
#find_package(CryptoPP REQUIRED)

#target_link_libraries(YOUR_TARGET_NAME cryptopp-shared)

#include_directories("/homes/mameriek/protobuf/include/google/protobuf")
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS db.proto)
include_directories(${PROTOBUF_INCLUDE_DIRS})
message(STATUS ">>> PROTOBUF_INCLUDE_DIRS: (${PROTOBUF_INCLUDE_DIRS})")

find_library(PROTOBUF_STATIC_LIB libprotobuf.a PROTOBUF_LIBRARIES)
find_library(PROTOBUF_SHARED_LIB libprotobuf.so PROTOBUF_LIBRARIES)

find_library(GMP_STATIC_LIB libgmp.a GMP_LIBRARIES)

#find_library(LIB_ARGON2 argon2 libargon2.so libargon2.a libargon2.so.1)


if(NOT PROTOBUF_STATIC_LIB AND NOT PROTOBUF_SHARED_LIB)
  message( FATAL_ERROR "Cannot find any suitable protobuf library." )
endif()


#find_library(PAILLIER_STATIC_LIB libpaillier.a PAILLIER_LIBRARIES)

### Curl is also required
find_package(CURL REQUIRED)
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET(DEBUG 1)
endif()

### Set the sources for typtop
file(GLOB CONDTYPTOP_SRCS "*.cpp" "*.c")
file(GLOB CONDTYPTOP_HDRS "*.h" "*.hpp")
#set(CONDTYPTOP_SRCS ${CONDTYPTOP_SRCS} ${CONDTYPTOP_HDRS} ${PROTO_SRCS} ${PROTO_HDRS}
set(CONDTYPTOP_SRCS ${PROTO_SRCS} ${PROTO_HDRS}
        condtyptopconfig.h
        ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h
        condtyptop.h condtyptop.cpp
        pw_crypto.h pw_crypto.cpp
        upload.cpp
#        conditionalcrypto.h
        CryptoSymWrapperFunctions.cpp CryptoSymWrapperFunctions.h
        PaillierWrapperFunctions.cpp PaillierWrapperFunctions.h
        ConditionalEncryptionEditDistOne.cpp ConditionalEncryptionEditDistOne.h
        ConditionalEncryptionHamDistAtmostT.cpp ConditionalEncryptionHamDistAtmostT.h
        ConditionalEncryptionCAPSLOCK.cpp ConditionalEncryptionCAPSLOCK.h
        ConditionalEncryptionOR.cpp ConditionalEncryptionOR.h
        ../ShamirSS/src/GF256.cpp ../ShamirSS/src/GF256.h ../ShamirSS/src/shamir.cpp ../ShamirSS/src/shamir.h
        )

### Build the main typtop functionality (in particular, the db) as library
add_library(condtyptopdb ${CONDTYPTOP_SRCS}
        ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h
        ../ShamirSS/src/GF256.cpp ../ShamirSS/src/GF256.h ../ShamirSS/src/shamir.cpp ../ShamirSS/src/shamir.h
#        ConditionalEncryptionEditDistOne.cpp ConditionalEncryptionEditDistOne.h
#        CryptoSymWrapperFunctions.cpp CryptoSymWrapperFunctions.h
#        PaillierWrapperFunctions.cpp PaillierWrapperFunctions.h
#        ConditionalEncryptionHamDistAtmostT.cpp ConditionalEncryptionHamDistAtmostT.h
#        ConditionalEncryptionOR.cpp ConditionalEncryptionOR.h
#        ConditionalEncryptionCAPSLOCK.cpp ConditionalEncryptionCAPSLOCK.h
#        conditionalcrypto.h
        )
#add_library(condtyptopdb ${CONDTYPTOP_SRCS} )

### Build typtop as an executable (why for win32?)
#add_library(typtop1 ${TYPTOP_SRCS}
#        ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h)

add_executable(condtyptop typtop-main.cpp
        pw_crypto.h pw_crypto.cpp
        CryptoSymWrapperFunctions.cpp CryptoSymWrapperFunctions.h
        PaillierWrapperFunctions.cpp PaillierWrapperFunctions.h
#        conditionalcrypto.h
        ConditionalEncryptionEditDistOne.cpp ConditionalEncryptionEditDistOne.h
        ConditionalEncryptionHamDistAtmostT.cpp ConditionalEncryptionHamDistAtmostT.h
        ConditionalEncryptionOR.cpp ConditionalEncryptionOR.h
        ConditionalEncryptionCAPSLOCK.cpp ConditionalEncryptionCAPSLOCK.h
        ../ShamirSS/src/GF256.cpp ../ShamirSS/src/GF256.h ../ShamirSS/src/shamir.cpp ../ShamirSS/src/shamir.h
        )  # Not sure why we have win32
#../3rdparty/cryptopp565/paillier4.c

### Ad an executable for decoding base64 encoded lines, python base64 is not compatible with CryptoPP one.
### Hence, a C++ binary to deal with it.
add_executable(b64 EXCLUDE_FROM_ALL b64.cpp
#        CryptoSymWrapperFunctions.cpp CryptoSymWrapperFunctions.h
#        PaillierWrapperFunctions.cpp PaillierWrapperFunctions.h
#        conditionalcrypto.h
#        ConditionalEncryptionEditDistOne.cpp ConditionalEncryptionEditDistOne.h
#        ConditionalEncryptionHamDistAtmostT.cpp ConditionalEncryptionHamDistAtmostT.h
#        ConditionalEncryptionCAPSLOCK.cpp ConditionalEncryptionCAPSLOCK.h
#        ConditionalEncryptionOR.cpp ConditionalEncryptionOR.h
        )

#add_custom_target(Argon2 COMMAND make run
#        WORKING_DIRECTORY /Users/mameriek/Documents/GitHub/ConditionalEncryptionTypTop/CondEncCPP/cmake-build-debug/_deps/argon2-src
#        )

find_library(ARGON2_LIBRARY argon2 PATHS ${CMAKE_SOURCE_DIR}/argon2/phcargon2)
if(ARGON2_LIBRARY)
    target_link_libraries(condtyptopdb cryptopp  ${ARGON2_LIBRARY})
    target_link_libraries(condtyptop cryptopp ${ARGON2_LIBRARY})
    message(STATUS "libargon2.a found!")
else()
    message(FATAL_ERROR "libargon2.a not found!")
endif()


set(ZXCVBN_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rdparty/zxcvbn21")


### Include various header files from external libraries
target_include_directories(condtyptopdb PRIVATE ${CRYPTOPP_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS} )
target_include_directories(condtyptop PUBLIC ${CRYPTOPP_INCLUDE_DIRS}  ${CMAKE_CURRENT_BINARY_DIR} ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})
target_include_directories(b64 PUBLIC ${CRYPTOPP_INCLUDE_DIRS}  ${CMAKE_CURRENT_BINARY_DIR} ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})

### Link libraries. These are configured through 3rdparty/${lib_name}


target_link_libraries(condtyptopdb cryptopp)
target_link_libraries(condtyptopdb "${ZXCVBN_INCLUDE_DIRS}/libzxcvbn.a")
target_link_libraries(condtyptop condtyptopdb cryptopp curl)
target_link_libraries(condtyptop "${ZXCVBN_INCLUDE_DIRS}/libzxcvbn.a")
target_link_libraries(condtyptopdb ${PROTOBUF_STATIC_LIB})
target_link_libraries(b64 condtyptopdb ${PROTOBUF_STATIC_LIB})

add_dependencies(condtyptopdb cryptopp zxcvbn)


target_link_libraries(condtyptop ${GMP_STATIC_LIB})

### Attempt to follow preference for protobuf library.
if(CMAKE_PREFER_SHARED_LIBRARIES)
    if(PROTOBUF_SHARED_LIB)
        target_link_libraries(condtyptop ${PROTOBUF_SHARED_LIB})
    else(PROTOBUF_STATIC_LIB)
        target_link_libraries(condtyptop ${PROTOBUF_STATIC_LIB})
    endif()
else()
    if(PROTOBUF_STATIC_LIB)
        target_link_libraries(condtyptop ${PROTOBUF_STATIC_LIB})
    else(PROTOBUF_SHARED_LIB)
        target_link_libraries(condtyptop ${PROTOBUF_SHARED_LIB})
    endif()
endif()

INSTALL(TARGETS condtyptop
        RUNTIME DESTINATION ${INSTALL_BIN_DIR}
        PERMISSIONS SETUID WORLD_EXECUTE OWNER_EXECUTE GROUP_EXECUTE
        OWNER_WRITE GROUP_READ WORLD_READ
        OWNER_READ GROUP_READ
        )
INSTALL(DIRECTORY condtyptop.d DESTINATION ${INSTALL_DATA_DIR})
INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION ${INSTALL_DATA_DIR}/condtyptop.d/)

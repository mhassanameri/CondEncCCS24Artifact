link_directories("/usr/lib/x86_64-linux-gnu")

find_package(Protobuf REQUIRED)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS db.proto)
include_directories(${PROTOBUF_INCLUDE_DIRS})
message(STATUS ">>> PROTOBUF_INCLUDE_DIRS: (${PROTOBUF_INCLUDE_DIRS})")

find_library(PROTOBUF_STATIC_LIB libprotobuf.a PROTOBUF_LIBRARIES)
find_library(PROTOBUF_SHARED_LIB libprotobuf.so PROTOBUF_LIBRARIES)

find_library(GMP_STATIC_LIB libgmp.a GMP_LIBRARIES)
message(STATUS ">>> GMP LIBRARY: (${GMP_STATIC_LIB})")

find_library(GMP_SHARED_LIB  libgmp.so GMP_LIBRARIES)
message(STATUS ">>> GMP LIBRARY: (${GMP_SHARED_LIB})")
message(STATUS ">>> GMP INLCUDE: (${GMP_INCLUDE_DIRS})")

link_directories(${GMP_LIBRARIES})
include_directories(${GMP_INCLUDE_DIRS})
#link_libraries(${GMP_LIBRARIES})

find_package(Catch2 REQUIRED)
include_directories(${Catch2_INCLUDE_DIRS})

#SET (CRYPTOPP_LIBRARIES ${CRYPTOPP_LIBRARY})
#find_library(CRYPTOPP_STATIC_LIB libcryptopp.a CRYPTOPP_LIBRARIES)

#message(STATUS ">>> CRYPTOPP LIBRARY: (${CRYPTOPP_STATIC_LIB})")
#SET (CRYPTOPP_INCLUDE_DIRS "/usr/local/include/cryptopp")




if(NOT PROTOBUF_STATIC_LIB AND NOT PROTOBUF_SHARED_LIB)
    message( FATAL_ERROR "Cannot find any suitable protobuf library." )
endif()


find_package(CURL REQUIRED)
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET(DEBUG 1)
endif()


### Set the sources for typtop
file(GLOB CONDENCCPP_SRCS "*.cpp" "*.c")
file(GLOB CONDENCCPP_HDRS "*.h" "*.hpp")
set(CONDENCCPP_SRCS  ${CONDENCCPP_SRCS} ${CONDENCCPP_HDRS}  ${PROTO_SRCS} ${PROTO_HDRS}
#        ../main.cpp
        CondEncCPPconfig.h
        ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h
#        PK_crypto.cpp PK_crypto.h
#                conditionalcrypto.h
        CryptoSymWrapperFunctions.cpp CryptoSymWrapperFunctions.h
        PaillierWrapperFunctions.cpp PaillierWrapperFunctions.h
        ConditionalEncryptionEditDistOne.cpp ConditionalEncryptionEditDistOne.h
        ConditionalEncryptionHamDistTwo.cpp ConditionalEncryptionHamDistTwo.h
        ConditionalEncryptionCAPSLOCK.cpp ConditionalEncryptionCAPSLOCK.h
        ConditionalEncryptionOR.cpp ConditionalEncryptionOR.h

        )

message(STATUS ">>>> ${CONDENCCPP_SRCS}")

### Build the main typtop functionality (in particular, the db) as library

add_library(condenccppdb ${CONDENCCPP_SRCS}
        ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h
        )
#target_link_libraries(condenccppdb ${CRYPTOPP_STATIC_LIB})

#add_executable(condenccpp main.cpp ${CONDENCCPP_SRCS}  ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h )
add_executable(condenccpp main.cpp
        ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h
        PK_crypto.cpp PK_crypto.h
        CryptoSymWrapperFunctions.cpp CryptoSymWrapperFunctions.h
        PaillierWrapperFunctions.cpp PaillierWrapperFunctions.h
        #        conditionalcrypto.h
        ConditionalEncryptionEditDistOne.cpp ConditionalEncryptionEditDistOne.h
        ConditionalEncryptionHamDistTwo.cpp ConditionalEncryptionHamDistTwo.h
        ConditionalEncryptionOR.cpp ConditionalEncryptionOR.h
        ConditionalEncryptionCAPSLOCK.cpp ConditionalEncryptionCAPSLOCK.h
        )  # Not sure why we have win32


include_directories( ${GMP_INCLUDE_DIRS})

SET (CRYPTOPP_INCLUDE_DIRS "cryptopp-cmake/cryptopp" )
message(STATUS ">>> INCLUDE_DIRS: (${CMAKE_PROJECT_DIR} ${CRYPTOPP_INCLUDE_DIRS}, ${CMAKE_CURRENT_BINARY_DIR}, ${ZXCVBN_INCLUDE_DIRS}, ${PLOG_INCLUDE_DIRS})")
target_include_directories(condenccppdb PRIVATE ${GMP_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} "../paillier/pailliercpp.cpp" "../paillier/pailliercpp.h" ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})
target_include_directories(condenccpp PUBLIC ${GMP_INCLUDE_DIR}  ${CMAKE_CURRENT_BINARY_DIR} "../paillier/pailliercpp.cpp" "../paillier/pailliercpp.h" ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})
#target_include_directories(condenccppdb PRIVATE ${CMAKE_CURRENT_BINARY_DIR}  "../paillier"  ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})
#target_include_directories(condenccpp PUBLIC ${CMAKE_CURRENT_BINARY_DIR} "../paillier" ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})

### Link libraries. These are configured through 3rdparty/${lib_name}


target_link_libraries(condenccppdb cryptopp  ${GMP_STATIC_LIB} /home/hassan/CLionProjects/CondEncCCS24/argon2/phcargon2/libargon2.a)

#target_link_libraries(condenccpp condenccppdb ${CRYPTOPP_STATIC_LIB} zxcvbn curl)
target_link_libraries(condenccpp condenccppdb cryptopp zxcvbn curl)
target_link_libraries(condenccpp /home/hassan/CLionProjects/CondEncCCS24/argon2/phcargon2/libargon2.a)

add_dependencies(condenccppdb cryptopp zxcvbn)

target_link_libraries(condenccpp  ${GMP_STATIC_LIB})
#target_link_libraries(condenccpp ${${GMP_SHARED_LIB}})
target_link_libraries(condenccpp  ${GMP_LIBRAIES})

#target_link_libraries(condenccpp ${CRYPTOPP_STATIC_LIB})


#target_include_directories(condenccppdb PRIVATE ${CRYPTOPP_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
#target_include_directories(condenccpp PUBLIC ${CRYPTOPP_INCLUDE_DIRS}  ${CMAKE_CURRENT_BINARY_DIR})

#target_link_libraries(condenccppdb cryptopp)
#target_link_libraries(condenccpp condenccppdb cryptopp curl)


### Attempt to follow preference for protobuf library.
if(CMAKE_PREFER_SHARED_LIBRARIES)
    if(PROTOBUF_SHARED_LIB)
        target_link_libraries(condenccpp ${PROTOBUF_SHARED_LIB})
    else(PROTOBUF_STATIC_LIB)
        target_link_libraries(condenccpp ${PROTOBUF_STATIC_LIB})
    endif()
else()
    if(PROTOBUF_STATIC_LIB)
        target_link_libraries(condenccpp ${PROTOBUF_STATIC_LIB})
    else(PROTOBUF_SHARED_LIB)
        target_link_libraries(condenccpp ${PROTOBUF_SHARED_LIB})
    endif()
endif()

#
#INSTALL(TARGETS CondEncCPP
#        RUNTIME DESTINATION ${INSTALL_BIN_DIR}
#        PERMISSIONS SETUID WORLD_EXECUTE OWNER_EXECUTE GROUP_EXECUTE
#        OWNER_WRITE GROUP_READ WORLD_READ
#        OWNER_READ GROUP_READ
#        )
#INSTALL(DIRECTORY typtop.d DESTINATION ${INSTALL_DATA_DIR})
#INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION ${INSTALL_DATA_DIR}/typtop.d/)

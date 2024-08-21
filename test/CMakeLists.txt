#set(TEST_SRCS test-main.cpp test_typtop.cpp test_install.cpp
#set(TEST_SRCS
#        set(TEST_SRCS testCondEncEvaluation.cpp testCondEncEvaluation.h
link_directories("/usr/lib/x86_64-linux-gnu")

find_library(GMP_STATIC_LIB libgmp.a GMP_LIBRARIES)
#find_library(GMP_SHARED_LIB  libgmp.so GMP_LIBRARIES)
message(STATUS ">>> GMP LIBRARY: (${GMP_SHARED_LIB})")
#message(STATUS ">>> GMP INCLUDE: (${GMP_INCLUDE_DIRS})")
include_directories(${GMP_INCLUDE_DIRS})



set(TEST_SRCS test-main.cpp testCondEncEvaluation.cpp testCondEncEvaluation.h
        ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h
#        set(TEST_SRCS test-main.cpp test_pw_crypto.cpp test_install.cpp
#        set(TEST_SRCS testCondEncEvaluation.cpp testCondEncEvaluation.h
#        ../src/PaillierWrapperFunctions.cpp ../src/PaillierWrapperFunctions.h
#        ../src/ConditionalEncryptionHamDistTwo.cpp ../src/ConditionalEncryptionHamDistTwo.h
#        ../src/ConditionalEncryptionEditDistOne.cpp ../src/ConditionalEncryptionEditDistOne.h
#        ../src/CryptoSymWrapperFunctions.cpp ../src/CryptoSymWrapperFunctions.h
#        ../src/conditionalcrypto.h
#        ../src/ConditionalEncryptionCAPSLOCK.cpp ../src/ConditionalEncryptionCAPSLOCK.h
        )

#test_pw_crypto.cpp
#set(TEST_SRCS test-main.cpp test_typtop.cpp test_install.cpp

add_executable(tests ${TEST_SRCS}
        ../paillier/pailliercpp.cpp
#        test_pw_crypto.cpp
#        ../src/pw_crypto.cpp ../src/pw_crypto.h
#        ../src/PK_crypto.cpp ../src/PK_crypto.h
        #../CondEncCPPconfig.h
#        ../src/CryptoSymWrapperFunctions.cpp ../src/CryptoSymWrapperFunctions.h
#        ../src/PaillierWrapperFunctions.cpp ../src/PaillierWrapperFunctions.h
#        ../src/ConditionalEncryptionEditDistOne.cpp ../src/ConditionalEncryptionEditDistOne.h
#        ../src/ConditionalEncryptionHamDistTwo.cpp ../src/ConditionalEncryptionHamDistTwo.h
#        ../src/ConditionalEncryptionOR.cpp ../src/ConditionalEncryptionOR.h
#        ../src/conditionalcrypto.h
#        ../src/ConditionalEncryptionCAPSLOCK.cpp ../src/ConditionalEncryptionCAPSLOCK.h
#        test_condTypTop.cpp)
#        ../paillier/pailliercpp.cpp ../paillier/pailliercpp.h
#        ../src/PK_crypto.cpp ../src/PK_crypto.h
        testCondEncEvaluation.cpp testCondEncEvaluation.h
        )

#set(Protobuf_PREFIX_PATH
#        "/homes/mameriek/protobuf/usr/local/include"
#        "/homes/mameriek/protobuf/usr/local/lib"
#        "/homes/mameriek/protobuf/usr/local/bin" )
#list(APPEND CMAKE_PREFIX_PATH "${Protobuf_PREFIX_PATH}")

find_package(Protobuf REQUIRED)
# if(APPLE)
#     set(PAM_LIBS "pam")
# else()
#     set(PAM_LIBS "pam")
# endif()

message(STATUS "condenccpp lib: " ${CRYPTOPP_INCLUDE_DIRS})

#find_library(LIB_ARGON2 argon2 libargon2.so libargon2.a libargon2.so.1)


include_directories( ${GMP_INCLUDE_DIRS})
target_include_directories(tests PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src ${GMP_INCLUDE_DIRS} "../paillier/pailliercpp.cpp" ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})

#target_include_directories(tests PUBLIC ${CRYPTOPP_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src  ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})
#target_include_directories(tests PUBLIC ${${CRYPTOPP}_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})

#target_link_libraries(tests /Users/mameriek/Documents/GitHub/ConditionalEncryptionTypTop/CondEncCPP/cmake-build-debug/_deps/cryptopp-build/libcryptopp.a)
#target_link_libraries(tests /usr/local/lib/libargon2.a)
target_link_libraries(tests /home/hassan/CLionProjects/CondEncCCS24/argon2/phcargon2/libargon2.a)

#target_link_libraries(tests /usr/lib/libargon2.a)
#target_link_libraries(tests ../argon2/phcargon2/libargon2.a)



target_link_libraries(tests ${ZXCVBN_INCLUDE_DIRS}/${ZXCVBN_LIBRARIES})
target_link_libraries(tests  ${GMP_STATIC_LIB})

#target_link_libraries(tests ${${GMP_SHARED_LIB}})


#target_link_libraries(tests pam_typtop)
message(STATUS "PROTOBUF LIB: ${PROTOBUF_SHARED_LIB} ${PROTOBUF_STATIC_LIB} PROTOUBF_INCLUD_DIR>> ${protobuf_INCLUDE_DIRS} ${PROTOBUF_INCLUDE_DIRS}")

if(CMAKE_PREFER_SHARED_LIBRARIES)
    if(PROTOBUF_SHARED_LIB)
        target_link_libraries(tests ${PROTOBUF_SHARED_LIB})
    else(PROTOBUF_STATIC_LIB)
        target_link_libraries(tests ${PROTOBUF_STATIC_LIB})
    endif()
else()
    if(PROTOBUF_STATIC_LIB)
        target_link_libraries(tests ${PROTOBUF_STATIC_LIB})
    else(PROTOBUF_SHARED_LIB)
        target_link_libraries(tests ${PROTOBUF_SHARED_LIB})
    endif()
endif()
target_link_libraries(tests condenccppdb)
target_link_libraries(tests curl)
add_dependencies(tests condenccppdb zxcvbn ${PLOG_PREFIX})





enable_testing()
find_file(test_exec tests PATHS ${CMAKE_BINARY_DIR}/test)
add_test(test ${test_exec} -d yes)

include(ExternalProject)

ExternalProject_Add(
    ${ZXCVBN_PREFIX}

    GIT_REPOSITORY ${ZXCVBN_URL}
    GIT_TAG ${ZXCVBN_TAG}
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/3rdparty/${ZXCVBN_PREFIX}"

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
    CONFIGURE_COMMAND ""
    BUILD_COMMAND  make -C <SOURCE_DIR> libzxcvbn.a USE_DICT_FILE=1
    INSTALL_COMMAND ""
    # BUILD_IN_SOURCE 1
    LOG_DOWNLOAD 1
    LOG_BUILD 1
)

## zxcvbn-c headers are just in the root dir
set(ZXCVBN_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rdparty/${ZXCVBN_PREFIX}")
set(ZXCVBN_LIBRARIES "${CMAKE_STATIC_LIBRARY_PREFIX}zxcvbn${CMAKE_STATIC_LIBRARY_SUFFIX}")

#add_library(zxcvbn STATIC IMPORTED ../src/conditionalcrypto.h ../src/ConditionalEncryptionCAPSLOCK.cpp ../src/ConditionalEncryptionCAPSLOCK.h)
add_library(zxcvbn STATIC IMPORTED)
set_target_properties(zxcvbn PROPERTIES IMPORTED_LOCATION ${ZXCVBN_INCLUDE_DIRS}/${ZXCVBN_LIBRARIES})

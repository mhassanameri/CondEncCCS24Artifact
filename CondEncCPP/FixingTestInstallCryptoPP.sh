#!/bin/bash

sed -i "27s/.*/  /" "cryptopp-cmake/cryptopp/validate.h"
sed -i "297s/.*/    std::string g_argvPathHint;/" "cryptopp-cmake/cryptopp/validate.h"
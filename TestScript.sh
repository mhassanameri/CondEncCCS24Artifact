#!/bin/bash

# Path to the compiled binary
BINARY_PATH="./tests"

# Arguments to pass to the binary
ARGUMENTS="CommandLine "

# Run the binary with the arguments
$BINARY_PATH $ARGUMENTS

# Check if the binary ran successfully
if [ $? -eq 0 ]; then
    echo "Program ran successfully."
else
    echo "Program encountered an error."
fi

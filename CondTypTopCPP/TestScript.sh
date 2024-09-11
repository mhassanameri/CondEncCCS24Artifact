#!/bin/bash

# Path to the compiled binary
BINARY_PATH="./tests"


# Running The Basic Tests after Installing
BasicTestArgument="CondTypTopEval"
echo -e "5" > input_condTypTopEval.txt #More details on how the inputs are parsed will be added.
####HamDist
#
$BINARY_PATH $BasicTestArgument



# Check if the binary ran successfully
if [ $? -eq 0 ]; then
    echo "Program ran successfully."
else
    echo "Program encountered an error."
fi

#!/bin/bash

# Path to the compiled binary
BINARY_PATH="./tests"


# Running The Basic Tests after Installing
GenerateDataTable1="Table1"
echo -e "100" > Table1_input.txt #Just takes as input: the number of tests (the number of pwds we run CondEnc for its corresponding typp from the data set
####HamDist
#
$BINARY_PATH $GenerateDataTable1



# Check if the binary ran successfully
if [ $? -eq 0 ]; then
    echo "Program ran successfully."
else
    echo "Program encountered an error."
fi

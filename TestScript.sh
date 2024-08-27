#!/bin/bash

# Path to the compiled binary
BINARY_PATH="./tests"

# This argument runs the test case which generates the data required to plotting the Figure 1 of the paper and
# placing the associate data in the Table 1 of the paper.
ARGUMENTS="ArtifactCCS24"


echo  -e "PlotFig1a\n1000\n32\n2" > input.txt


#echo -e "PlotFig1aNo128\n input1\n input2\n input3\n input4 ..." > input.txt #This generate Fig1a excluding secret message of length at most 128.




# Run the binary with the arguments
$BINARY_PATH $ARGUMENTS




# Check if the binary ran successfully
if [ $? -eq 0 ]; then
    echo "Program ran successfully."
else
    echo "Program encountered an error."
fi

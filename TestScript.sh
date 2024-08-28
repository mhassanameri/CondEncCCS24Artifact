#!/bin/bash

# Path to the compiled binary
BINARY_PATH="./tests"


# will generate and initialize the .dat files which store the performance evaluation
#InitArgument= "GenerateBlankDatFiles"
#$BINARY_PATH $InitArgument



# This argument runs the test case which generates the data required to plotting the Figure 1 of the paper and
# placing the associate data in the Table 1 of the paper.
ARGUMENTS="ArtifactCCS24"

echo  -e "PlotFig1a\n10\n1\n1\n" > input.txt  # Indicating the target figure to plot the options: [PlotFig1a, PlotFig1b, PlotFig1c, PlotFig1d, PlotFig1e, PlotFig1f, PlotFig1g, PlotFig1h, PlotFig1i]
#echo  -e "100\n" > input.txt        # Number or Tests on HamDist associated with messages of length at most 8, 16, 32 Characters
#echo  -e "50\n" > input.txt         # Number or Tests on HamDist associated with messages of length at most 64 Characters
#echo  -e "5\n" > input.txt          # Number or Tests on HamDist associated with messages of length at most 128  Characters

#echo -e "PlotFig1aNo128\n input1\n input2\n input3\n input4 ..." > input.txt #This generate Fig1a excluding secret message of length at most 128.


# Run the binary with the arguments
$BINARY_PATH $ARGUMENTS




# Check if the binary ran successfully
if [ $? -eq 0 ]; then
    echo "Program ran successfully."
else
    echo "Program encountered an error."
fi

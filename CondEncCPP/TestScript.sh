#!/bin/bash

# Path to the compiled binary
BINARY_PATH="./tests"


# Running The Basic Tests after Installing
BasicTestArgument="ArtifactCCS24BasicTests"
echo -e "HamDistT\n25\n1024\n32\n2" > BasicTestInputs.txt #More details on how the inputs are parsed will be added.
####HamDist
#
$BINARY_PATH $BasicTestArgument

# will generate and initialize the .dat files which store the performance evaluation
InitArgument="GenerateBlankDatFiles"
$BINARY_PATH $InitArgument


# This argument runs the test case which generates the data required to plotting the Figure 1 of the paper and
# placing the associate data in the Table 1 of the paper.
ARGUMENTS="ArtifactCCS24"

echo  -e "PlotFig1a1b1c\n10\n2\n1\n" > input.txt  # Indicating the target figure to plot the options: [PlotFig1a1b1c, PlotFig1a1b1cNo128, PlotFig1d, PlotFig1e, PlotFig1f]
#echo  -e "PlotFig1d\n10" > input.txt  #Comment out to generate .dat for this figure
#echo  -e "PlotFig1e\n10" > input.txt  #Comment out to generate .dat for this figure
#echo  -e "PlotFig1f\n10" > input.txt  #Comment out to generate .dat for this figure

#echo -e "PlotFig1a1b1cNo128\n100\n200\n50" > input.txt #This generate Fig1a excluding secret message of length at most 128.
#echo  -e "100\n" > input.txt        # Number or Tests on HamDist associated with messages of length at most 8, 16, 32 Characters
#echo  -e "50\n" > input.txt         # Number or Tests on HamDist associated with messages of length at most 64 Characters
#echo  -e "5\n" > input.txt          # Number or Tests on HamDist associated with messages of length at most 128  Characters



# Run the binary with the arguments
$BINARY_PATH $ARGUMENTS




# Check if the binary ran successfully
if [ $? -eq 0 ]; then
    echo "Program ran successfully."
else
    echo "Program encountered an error."
fi

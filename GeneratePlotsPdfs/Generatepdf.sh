#!/bin/bash

# Script to compile a LaTeX file into a PDF

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 filename.tex"
    exit 1
fi

# Extract the filename without the extension
filename=$(basename "$1" .tex)

# Compile the LaTeX file
pdflatex "$filename.tex"

# Check if the compilation was successful
if [ $? -eq 0 ]; then
    echo "PDF generated successfully: $filename.pdf"
else
    echo "Failed to generate PDF. Check your LaTeX file for errors."
    exit 1
fi
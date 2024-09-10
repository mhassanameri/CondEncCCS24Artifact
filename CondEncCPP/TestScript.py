import subprocess

# Path to your compiled binary
binary_path = "./test"

# Run the binary using subprocess
try:
    result = subprocess.run([binary_path], check=True, text=True, capture_output=True)

    # Print the output of the binary
    print("Output:\n", result.stdout)

    # If there's any error output
    if result.stderr:
        print("Error:\n", result.stderr)

except subprocess.CalledProcessError as e:
    print(f"An error occurred while running the binary: {e}")
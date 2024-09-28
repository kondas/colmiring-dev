#!/usr/bin/env python3

import sys

# Constants
HEADER_DATA = bytes([0x78, 0x56, 0x34, 0x12])

def main(input_filename: str):
    output_filename = f'restored_{input_filename}'  # Create an output filename

    try:
        with open(input_filename, 'rb') as input_file:
            # Read the first 0x100 bytes
            header = input_file.read(0x100)

            # Check if the header matches the expected header data
            if header.startswith(HEADER_DATA):
                # Read the rest of the file after the header
                remaining_data = input_file.read()
                
                # Write the remaining data to the new file
                with open(output_filename, 'wb') as output_file:
                    output_file.write(remaining_data)

                print(f"Header removed. Restored file created: {output_filename}")
            else:
                print("The file does not start with the expected header data.")

    except FileNotFoundError:
        print(f"Error: File '{input_filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./remove_header.py <filename>")
        sys.exit(1)

    main(sys.argv[1])


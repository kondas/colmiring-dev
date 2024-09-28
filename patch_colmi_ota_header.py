#!/usr/bin/env python3

import sys

# Constants
HEADER_DATA = bytes([0x78, 0x56, 0x34, 0x12])
DATA_START_POSITION = 0x100
FIRMWARE_VERSION = "R02_3.00.06_240523"
HARDWARE_VERSION = "R02_V3.0"

def pad_string(input_string: str, length: int) -> bytes:
    """Pads a string to the specified byte length with null bytes."""
    return input_string.encode('utf-8').ljust(length, b'\x00')

def crc32(data: bytes) -> int:
    """Calculates the CRC32 checksum for the given data."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if (crc & 1) == 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF

def calculate_length_bytes(original_length: int) -> bytes:
    """Returns the original length as 4 bytes, repeated twice."""
    return original_length.to_bytes(4, byteorder='little') * 2

def main(input_filename: str):
    output_filename = f'modified_{input_filename}'  # Create an output filename

    try:
        with open(input_filename, 'rb') as original_file:
            # Read the first 0x100 bytes to check for the header
            header = original_file.read(0x100)

            # Check if the header matches the expected header data
            if header.startswith(HEADER_DATA):
                print("The header is already present. No changes made.")
                return

            # Move back to the beginning of the file to read the original data
            original_file.seek(0)
            original_data = original_file.read()

        original_length = len(original_data)

        # Prepare the header components
        crc32_bytes = crc32(original_data).to_bytes(4, byteorder='little')
        length_bytes = calculate_length_bytes(original_length)

        # Pad firmware version string
        firmware_version_padded = pad_string(FIRMWARE_VERSION, 32)

        # Calculate total header length
        total_header_length = (len(HEADER_DATA) + len(crc32_bytes) + 
                               len(length_bytes) + len(firmware_version_padded) + 
                               len(HARDWARE_VERSION))

        # Calculate padding size
        padding_size = DATA_START_POSITION - total_header_length
        padding = b'\x00' * padding_size if padding_size > 0 else b''

        # Write modified content to the new file
        with open(output_filename, 'wb') as modified_file:
            modified_file.write(HEADER_DATA)            # Write the header
            modified_file.write(crc32_bytes)            # Write the CRC32
            modified_file.write(length_bytes)            # Write length bytes
            modified_file.write(firmware_version_padded) # Write padded firmware version
            modified_file.write(HARDWARE_VERSION.encode('utf-8'))  # Write hardware version without padding
            modified_file.write(padding)                 # Write calculated padding
            modified_file.write(original_data)           # Write the original data

        print(f"Modified file created: {output_filename}")

    except FileNotFoundError:
        print(f"Error: File '{input_filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./add_header.py <filename>")
        sys.exit(1)

    main(sys.argv[1])


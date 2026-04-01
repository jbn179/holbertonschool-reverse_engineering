#!/bin/bash

# Source the messages helper
SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/messages.sh"

# Check argument provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <elf_file>"
    exit 1
fi

file_name="$1"

# Check file exists
if [ ! -f "$file_name" ]; then
    echo "Error: File '$file_name' does not exist."
    exit 1
fi

# Check it's an ELF file by reading the magic bytes
magic_check=$(readelf -h "$file_name" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "Error: '$file_name' is not a valid ELF file."
    exit 1
fi

# Extract fields using readelf
magic_number=$(readelf -h "$file_name" | grep "Magic" | awk '{$1=""; print $0}' | xargs)
class=$(readelf -h "$file_name" | grep "Class:" | awk '{print $2}')
byte_order=$(readelf -h "$file_name" | grep "Data:" | sed 's/.*Data:[[:space:]]*//' | sed 's/.*complement, //')
entry_point_address=$(readelf -h "$file_name" | grep "Entry point address:" | awk '{print $NF}')

# Display using messages.sh function
display_elf_header_info

#!/bin/sh

# Get the directory of the current script
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Format all .cpp and .h files in the script directory
echo "${SCRIPT_DIR}/.clang-format"

find "${SCRIPT_DIR}/include" -iname "*.cpp" -o -iname "*.c" -o -iname "*.hpp" -o -iname "*.h" | xargs clang-format -i
find "${SCRIPT_DIR}/src" -iname "*.cpp" -o -iname "*.c" -o -iname "*.hpp" -o -iname "*.h" | xargs clang-format -i

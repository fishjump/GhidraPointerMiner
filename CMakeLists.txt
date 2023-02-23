cmake_minimum_required(VERSION 3.0)

# Set project name and version
project(pointer-solver VERSION 1.0.0)

include($ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)

# Set the CMake export compile commands flag, which causes CMake to generate a compile_commands.json file
# in the build directory. This file is used by various IDEs and other tools to provide code completion,
# syntax highlighting, and other features.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add include directory
include_directories(include)

# Add source files
file(GLOB SOURCES "src/*.cpp")

# Add Boost library
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES})

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Create executable
add_executable(pointer-solver ${SOURCES})

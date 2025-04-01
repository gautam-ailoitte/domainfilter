# CMakeLists.txt
cmake_minimum_required(VERSION 3.10.2)
project(domainfilter)

# Set C flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src/main/cpp/include)

# Source files
set(SOURCE_FILES
        src/main/cpp/domainfilter.c
        src/main/cpp/domain_extraction.c
        src/main/cpp/domain_filter.c
)

# Add library
add_library(domainfilter SHARED ${SOURCE_FILES})

# Link libraries
target_link_libraries(domainfilter
        android
        log
)
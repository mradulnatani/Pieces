cmake_minimum_required(VERSION 3.20)
project(pieces VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)
find_package(LibArchive REQUIRED)

add_library(pieces_core STATIC
    src/json.cpp
    src/parser.cpp
    src/cli.cpp
    src/filesystem.cpp
    src/namespaces.cpp
    src/cgroup.cpp
    src/network.cpp
    src/container.cpp
)

target_include_directories(pieces_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(pieces_core
    PUBLIC
        CURL::libcurl
        LibArchive::LibArchive
)

target_compile_options(pieces_core
    PRIVATE
        -Wall -Wextra -Wpedantic
)

add_executable(pieces src/main.cpp)
target_link_libraries(pieces PRIVATE pieces_core)
target_compile_options(pieces PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(pieces_tests tests/test_pieces.cpp)
target_link_libraries(pieces_tests PRIVATE pieces_core)
target_compile_options(pieces_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME pieces_unit_tests COMMAND pieces_tests)

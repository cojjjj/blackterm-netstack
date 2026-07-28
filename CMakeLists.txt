cmake_minimum_required(VERSION 3.20)

project(
    blackterm_netstack
    VERSION 0.1.0
    DESCRIPTION "Userspace network stack built from first principles"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(
    blackterm_netstack
    src/ethernet.c
)

target_include_directories(
    blackterm_netstack
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_options(
    blackterm_netstack
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

enable_testing()

add_executable(
    test_ethernet
    tests/test_ethernet.c
)

target_link_libraries(
    test_ethernet
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_ethernet
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME ethernet
    COMMAND test_ethernet
)

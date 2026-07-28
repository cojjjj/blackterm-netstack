cmake_minimum_required(VERSION 3.20)

project(
    blackterm_netstack
    VERSION 0.3.0
    DESCRIPTION "Userspace network stack built from first principles"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(
    blackterm_netstack
    src/ethernet.c
    src/arp.c
    src/ipv4.c
    src/icmp.c
    src/netdev_linux.c
    src/udp.c
    src/dns.c

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

# Ethernet tests
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

# ARP tests
add_executable(
    test_arp
    tests/test_arp.c
)

target_link_libraries(
    test_arp
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_arp
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME arp
    COMMAND test_arp
)

# Ethernet + ARP integration tests
add_executable(
    test_arp_ethernet
    tests/test_arp_ethernet.c
)

target_link_libraries(
    test_arp_ethernet
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_arp_ethernet
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME arp_ethernet
    COMMAND test_arp_ethernet
)

# IPv4 tests
add_executable(
    test_ipv4
    tests/test_ipv4.c
)

target_link_libraries(
    test_ipv4
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_ipv4
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME ipv4
    COMMAND test_ipv4
)
# Ethernet + IPv4 integration tests
add_executable(
    test_ipv4_ethernet
    tests/test_ipv4_ethernet.c
)

target_link_libraries(
    test_ipv4_ethernet
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_ipv4_ethernet
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME ipv4_ethernet
    COMMAND test_ipv4_ethernet
)
# ICMP tests
add_executable(
    test_icmp
    tests/test_icmp.c
)

target_link_libraries(
    test_icmp
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_icmp
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME icmp
    COMMAND test_icmp
)
# Ethernet + IPv4 + ICMP integration tests
add_executable(
    test_icmp_ipv4_ethernet
    tests/test_icmp_ipv4_ethernet.c
)

target_link_libraries(
    test_icmp_ipv4_ethernet
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_icmp_ipv4_ethernet
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME icmp_ipv4_ethernet
    COMMAND test_icmp_ipv4_ethernet
)
# BLACKTERM // NETSTACK live ping utility
add_executable(
    netstack_ping
    tools/netstack_ping.c
)

target_link_libraries(
    netstack_ping
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    netstack_ping
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)
# UDP tests
add_executable(
    test_udp
    tests/test_udp.c
)

target_link_libraries(
    test_udp
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_udp
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME udp
    COMMAND test_udp
)
# DNS tests
add_executable(
    test_dns
    tests/test_dns.c
)

target_link_libraries(
    test_dns
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    test_dns
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_test(
    NAME dns
    COMMAND test_dns
)

# Live DNS client
add_executable(
    netstack_dns
    tools/netstack_dns.c
)

target_link_libraries(
    netstack_dns
    PRIVATE
    blackterm_netstack
)

target_compile_options(
    netstack_dns
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

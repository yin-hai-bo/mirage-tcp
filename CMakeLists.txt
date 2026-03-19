cmake_minimum_required(VERSION 3.16)

project(mirage_tcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(mirage_tcp STATIC
    src/ipv4_packet.cpp
    src/mirage_tcp.cpp
    src/tcp_segment.cpp
)

target_include_directories(mirage_tcp
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(mirage_tcp_example
    examples/basic_client.cpp
)
target_link_libraries(mirage_tcp_example PRIVATE mirage_tcp)

add_executable(mirage_tcp_tests
    tests/test_main.cpp
)
target_link_libraries(mirage_tcp_tests PRIVATE mirage_tcp)

enable_testing()
add_test(NAME mirage_tcp_tests COMMAND mirage_tcp_tests)

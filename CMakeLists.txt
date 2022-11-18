cmake_minimum_required(VERSION 3.22)
project(WebSocketTest)

set(CMAKE_CXX_STANDARD 20)

set(LIBS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -Wundef -Wno-unused")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native -flto -frecord-gcc-switches")

add_subdirectory(src)
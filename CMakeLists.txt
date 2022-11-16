cmake_minimum_required(VERSION 3.23)
project(WebSocketTest)

set(CMAKE_CXX_STANDARD 20)


set(LIBS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs")
#add_subdirectory("${LIBS_DIR}/asio/")
add_definitions(-DASIO_STANDALONE)

add_subdirectory(src)
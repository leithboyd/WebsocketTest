add_executable(WebSocketTest main.cpp)


if(MINGW)
    target_link_libraries(WebSocketTest ws2_32)
endif()
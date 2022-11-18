add_executable(web-socket-test main.cpp)

target_link_libraries (web-socket-test ssl crypto)


if(MINGW)
    target_link_libraries(web-socket-test ws2_32)
endif()
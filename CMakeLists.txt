cmake_minimum_required(VERSION 3.15)

project(lsassdump)

if (MSVC)
    # warning level 4
    add_compile_options(/GS-)
else()
endif()

add_definitions(-D_UNICODE)
add_executable(lsassdump src/main.cpp src/nanodump.c src/utils.c)

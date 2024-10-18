cmake_minimum_required(VERSION 3.15)

project(dumplsass)

add_definitions(-D_UNICODE)
add_executable(dumplsass dumplsass/main.cpp dumplsass/nanodump.c)

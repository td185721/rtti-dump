cmake_minimum_required(VERSION 3.15)
project(rtti_dump CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(rtti-dump src/main.cpp)

if(MSVC)
    target_compile_options(rtti-dump PRIVATE /W4 /permissive-)
else()
    target_compile_options(rtti-dump PRIVATE -Wall -Wextra -Wpedantic)
endif()

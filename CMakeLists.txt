cmake_minimum_required(VERSION 3.22)
project(ProcessHollowing)

set(CMAKE_CXX_STANDARD 17)

add_executable(ProcessHollowing src/main.cpp  src/NtDllFuncs.h)
add_executable(Payload src/payload.cpp)

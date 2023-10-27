# This file handles building each task as sub-project.
#
# Each task becomes an independent project in which you can experiment.
#
# Tasks are added as separate sub-projects so as compilation errors in
# one task don't affect another task.

cmake_minimum_required(VERSION 3.16)
project(VUT-ISA)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -pedantic -Wall -Wextra")

add_executable(dhcp-stats
        dhcp-stats.cpp
        dhcp-stats.h
        argparse.cpp
        argparse.h
        main.cpp)

target_link_libraries(dhcp-stats pcap ncurses)

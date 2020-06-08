cmake_minimum_required(VERSION 3.17)

project (xhype C ASM-ATT CXX)
set(CMAKE_CXX_FLAGS_DEBUG -std=c++11)
aux_source_directory(. DIR_SRCS)
add_executable(xhype_test ${DIR_SRCS} vthread_hlt.s)
target_link_libraries(xhype_test "-framework Hypervisor")
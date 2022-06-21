cmake_minimum_required(VERSION 3.10)
# set(CMAKE_DEBUG_POSTFIX d)

project(tun)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pthread")
# set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(src)
file(GLOB SOURCES "src/*.cpp" "src/**/*.cpp")
add_executable(tun ${SOURCES})
# set_target_properties(tun PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})

cmake_minimum_required(VERSION 2.8.11)
project(ALIGNER)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories(.)

include (FindLTTngUST REQUIRED)

add_library(tracepoint-provider SHARED tracepoint-provider.cpp)
target_link_libraries(tracepoint-provider LTTng::UST)

add_library(aligner-lib SHARED aligner-lib.cpp)
target_link_libraries(aligner-lib tracepoint-provider)

add_library(tester-lib SHARED tester-lib.cpp)
target_link_libraries(tester-lib tracepoint-provider)

link_libraries(aligner-lib)

add_executable(aligner aligner.cpp)

add_executable(tester tester.cpp)
target_link_libraries(tester tester-lib)

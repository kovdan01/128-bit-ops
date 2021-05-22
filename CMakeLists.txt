cmake_minimum_required(VERSION 3.19)

project(128-bit-ops LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/ntc")

include(ntc-dev-build)

find_package(Akrypt REQUIRED)
find_package(Catch2 REQUIRED)
find_package(benchmark REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Threads REQUIRED)

# tests-main

set(TESTS_MAIN_NAME tests-main)

add_library(${TESTS_MAIN_NAME} OBJECT
    src/tests_main.cpp)

target_compile_features(${TESTS_MAIN_NAME} PRIVATE cxx_std_20)

target_link_libraries(${TESTS_MAIN_NAME} PRIVATE Catch2::Catch2)

# tests itself

set(TESTS_NAME tests)

add_executable(${TESTS_NAME}
    src/tests.cpp
)

target_compile_features(${TESTS_NAME} PRIVATE cxx_std_20)

target_link_libraries(${TESTS_NAME} PRIVATE akrypt::akrypt)
target_link_libraries(${TESTS_NAME} PRIVATE Catch2::Catch2)
target_link_libraries(${TESTS_NAME} PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(${TESTS_NAME} PRIVATE ${TESTS_MAIN_NAME})

ntc_target(${TESTS_NAME})

# benchmark

set(BENCHMARK benchmarks)

add_executable(${BENCHMARK}
    src/benchmark.cpp
)

target_link_libraries(${BENCHMARK} PRIVATE akrypt::akrypt)
target_link_libraries(${BENCHMARK} PRIVATE benchmark::benchmark)
target_link_libraries(${BENCHMARK} PRIVATE Threads::Threads)

ntc_target(${BENCHMARK})

include(FeatureSummary)
feature_summary(WHAT ALL)

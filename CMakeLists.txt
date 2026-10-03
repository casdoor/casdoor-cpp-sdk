cmake_minimum_required(VERSION 3.16)

project(casdoor-cpp-sdk VERSION 1.0.0 LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(CASDOOR_IS_TOP_LEVEL ON)
else()
    set(CASDOOR_IS_TOP_LEVEL OFF)
endif()

option(CASDOOR_BUILD_TESTS "Build the tests of casdoor-cpp-sdk" ${CASDOOR_IS_TOP_LEVEL})
option(CASDOOR_BUILD_EXAMPLES "Build the examples of casdoor-cpp-sdk" ${CASDOOR_IS_TOP_LEVEL})

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Threads REQUIRED)

# nlohmann/json is part of the public API. Use the copy of the parent project if
# there is one, so that only one version of it ends up in the program.
if(NOT TARGET nlohmann_json::nlohmann_json)
    find_package(nlohmann_json 3.2.0 QUIET)
endif()
if(NOT TARGET nlohmann_json::nlohmann_json)
    add_library(casdoor_nlohmann_json INTERFACE)
    target_include_directories(casdoor_nlohmann_json INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/json/include>)
    add_library(nlohmann_json::nlohmann_json ALIAS casdoor_nlohmann_json)
endif()

add_library(casdoor src/casdoor.cpp)
add_library(casdoor::casdoor ALIAS casdoor)

target_compile_features(casdoor PUBLIC cxx_std_17)
target_include_directories(casdoor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cpp-httplib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/jwt-cpp/include)
target_link_libraries(casdoor
    PUBLIC
        nlohmann_json::nlohmann_json
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads)
if(WIN32)
    target_link_libraries(casdoor PRIVATE ws2_32 crypt32)
endif()

if(CASDOOR_BUILD_EXAMPLES)
    add_executable(casdoor_console_example examples/console/main.cpp)
    target_link_libraries(casdoor_console_example PRIVATE casdoor::casdoor)
endif()

if(CASDOOR_BUILD_TESTS)
    enable_testing()
    add_executable(casdoor_test tests/casdoor_test.cpp)
    target_include_directories(casdoor_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/jwt-cpp/include)
    target_link_libraries(casdoor_test PRIVATE casdoor::casdoor OpenSSL::Crypto)
    add_test(NAME casdoor_test COMMAND casdoor_test WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()

cmake_minimum_required(VERSION 3.20)

project(fuzzberg
  VERSION 1.0
  DESCRIPTION "Fuzzberg - a fuzzer for Apache Iceberg and other file-format readers"
  HOMEPAGE_URL "https://github.com/firebolt-db/fuzzberg"
  LANGUAGES CXX
)

# TODO: Split FileFormat fuzzers and Databases into separate STATIC libs
add_executable(fuzzberg src/main.cpp src/FileFormats/FileFuzzerBase.cpp src/FileFormats/csv.cpp src/FileFormats/parquet.cpp src/FileFormats/iceberg.cpp src/FileFormats/HTTPHandler.cpp src/Databases/firebolt-core/firebolt-core.cpp src/Databases/duckdb/duckdb.cpp)

target_include_directories(fuzzberg SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/third-party/radamsa/c)

add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/third-party/radamsa/lib/libradamsa.a
    COMMAND make everything
    COMMAND make lib/libradamsa.a
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/third-party/radamsa
    COMMENT "Building libradamsa.a"
    VERBATIM
)

target_link_directories(fuzzberg PRIVATE ${CMAKE_SOURCE_DIR}/third-party/radamsa/lib)

add_custom_target(radamsa_build
    DEPENDS ${CMAKE_SOURCE_DIR}/third-party/radamsa/lib/libradamsa.a
)

add_dependencies(fuzzberg radamsa_build)

# Include FetchContent for nlohmann_json
include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

# Link radamsa, curl, nlohmann_json
target_link_libraries(fuzzberg PRIVATE
    radamsa
    curl
    nlohmann_json::nlohmann_json)

add_custom_command(
  TARGET fuzzberg
  POST_BUILD
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/third-party/radamsa"
  COMMAND bash -c "make mrproper && rm -Rf lib"
  COMMENT "Cleaning up radamsa build artifacts"
  COMMENT "fuzzberg successfully built"
  VERBATIM
)
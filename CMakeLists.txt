cmake_minimum_required(VERSION 3.15)

project(lynxdns LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED true)
set(CMAKE_CXX_STANDARD 26)
message("List of compile features: ${CMAKE_CXX_COMPILE_FEATURES}")

set(SPDLOG_USE_STD_FORMAT TRUE)
add_subdirectory(thirdparty/spdlog)


file(GLOB PROJ_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)


add_compile_options(-Wall -Wextra -Wpedantic)
add_compile_options(-fsanitize=thread -fsanitize=undefined)
add_link_options(-fsanitize=thread -fsanitize=undefined -Wl,--add-needed)

add_executable(lynxdns ${PROJ_SRC})
target_include_directories(lynxdns PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/spdlog/include)
target_link_libraries(lynxdns PRIVATE spdlog::spdlog)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_PDB_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

# include(CTest)
# add_subdirectory(test)
# enable_testing()
cmake_minimum_required(VERSION 3.5)
project(easy_security)

# For Debug
# set(CMAKE_CXX_FLAGS "-g3 -fsanitize=address -fsanitize=undefined")
# set(CMAKE_CXX_FLAGS "-g3")

add_subdirectory(3rdparty)

file (GLOB ${PROJECT_NAME}_SOURCES src/*.cpp)

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SOURCES})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_link_libraries(${PROJECT_NAME} boost_circular_buffer fmt::fmt-header-only sqlite3 boost_interprocess)

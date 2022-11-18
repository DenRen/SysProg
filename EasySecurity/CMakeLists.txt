cmake_minimum_required(VERSION 3.17)
project(easy_security)

set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_FLAGS "-g3 -fsanitize=address -fsanitize=undefined")
# set(CMAKE_CXX_FLAGS "-g3")

# Add boost directories
add_subdirectory(boost/assert)
add_subdirectory(boost/circular_buffer)
add_subdirectory(boost/concept_check)
add_subdirectory(boost/config)
add_subdirectory(boost/core)
add_subdirectory(boost/move)
add_subdirectory(boost/preprocessor)
add_subdirectory(boost/static_assert)
add_subdirectory(boost/throw_exception)
add_subdirectory(boost/type_traits)

file (GLOB ${PROJECT_NAME}_SOURCES src/*.cpp)

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SOURCES})
target_link_libraries(${PROJECT_NAME} boost_circular_buffer)
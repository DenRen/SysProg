cmake_minimum_required(VERSION 3.17)
project(easy_security)

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

add_executable(easy_security main.cpp)
target_link_libraries(easy_security boost_circular_buffer)
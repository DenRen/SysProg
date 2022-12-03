cmake_minimum_required(VERSION 3.5)

project(sqlite3 LANGUAGES C)

add_library(sqlite3 src/sqlite3.c)

target_include_directories(sqlite3 INTERFACE include)

project(Spike)
cmake_minimum_required(VERSION 3.18)

add_custom_target (testme ALL DEPENDS lol)
add_custom_command (OUTPUT lol
                    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/directory name with spaces/mypy.sh" ${CMAKE_CURRENT_SOURCE_DIR}/test.py
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

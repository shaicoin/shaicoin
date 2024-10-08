cmake_minimum_required(VERSION 3.9)

project(bitcoin-tidy VERSION 1.0.0 DESCRIPTION "clang-tidy checks for Shaicoin Core")

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS False)

# TODO: Figure out how to avoid the terminfo check
find_package(LLVM REQUIRED CONFIG)
find_program(CLANG_TIDY_EXE NAMES "clang-tidy-${LLVM_VERSION_MAJOR}" "clang-tidy" HINTS ${LLVM_TOOLS_BINARY_DIR})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Found clang-tidy: ${CLANG_TIDY_EXE}")

add_library(bitcoin-tidy MODULE bitcoin-tidy.cpp logprintf.cpp)
target_include_directories(bitcoin-tidy SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})

# Disable RTTI and exceptions as necessary
if (MSVC)
    target_compile_options(bitcoin-tidy PRIVATE /GR-)
else()
    target_compile_options(bitcoin-tidy PRIVATE -fno-rtti)
    target_compile_options(bitcoin-tidy PRIVATE -fno-exceptions)
endif()

if(CMAKE_HOST_APPLE)
    # ld64 expects no undefined symbols by default
    target_link_options(bitcoin-tidy PRIVATE -Wl,-flat_namespace)
    target_link_options(bitcoin-tidy PRIVATE -Wl,-undefined -Wl,suppress)
endif()

# Add warnings
if (MSVC)
    target_compile_options(bitcoin-tidy PRIVATE /W4)
else()
    target_compile_options(bitcoin-tidy PRIVATE -Wall)
    target_compile_options(bitcoin-tidy PRIVATE -Wextra)
endif()

if(CMAKE_VERSION VERSION_LESS 3.27)
    set(CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}" "--load=${CMAKE_BINARY_DIR}/${CMAKE_SHARED_MODULE_PREFIX}bitcoin-tidy${CMAKE_SHARED_MODULE_SUFFIX}" "-checks=-*,bitcoin-*")
else()
    # CLANG_TIDY_COMMAND supports generator expressions as of 3.27
    set(CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}" "--load=$<TARGET_FILE:bitcoin-tidy>" "-checks=-*,bitcoin-*")
endif()

# Create a dummy library that runs clang-tidy tests as a side-effect of building
add_library(bitcoin-tidy-tests OBJECT EXCLUDE_FROM_ALL example_logprintf.cpp)
add_dependencies(bitcoin-tidy-tests bitcoin-tidy)

set_target_properties(bitcoin-tidy-tests PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")


install(TARGETS bitcoin-tidy LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

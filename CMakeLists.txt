cmake_minimum_required(VERSION 3.15)

project(PROPRF VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Needed for coroutines in GCC
add_compile_options(-fpermissive -fcoroutines)

# 1. Find Dependencies
set(ENABLE_SIMPLESTOT ON)
find_package(libOTe REQUIRED)

# Find GMP library
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
find_library(GMPXX_LIBRARY NAMES gmpxx)

if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY)
    message(FATAL_ERROR "Could not find GMP")
endif()

# 2. Add subdirectories
add_subdirectory(field25519)

# 3. Create an INTERFACE (Header-Only) Library for your logic
add_library(PROPRFlib INTERFACE)

# Expose your root directory headers and GMP headers to anything linking PROPRFlib
target_include_directories(PROPRFlib INTERFACE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${GMP_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/libOTe/thirdparty
)

# Link dependencies to the interface (assuming field25519 builds a target named "field25519")
target_link_libraries(PROPRFlib INTERFACE 
    oc::libOTe 
    field25519 
    ${GMP_LIBRARY} 
    ${GMPXX_LIBRARY}
)

# 4. Define your main CLI executable
add_executable(PROPRF main.cpp)

# Link the executable to our interface library
target_link_libraries(PROPRF PRIVATE PROPRFlib)

# 5. Handle Tests
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    enable_testing()
    set(BUILD_TESTING ON)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(tests) 
endif()
# Create a static library specifically for the field25519 math
add_library(field25519 STATIC fe25519.cpp)

# Allow anyone who links this library to include "fe25519.h" easily
target_include_directories(field25519 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
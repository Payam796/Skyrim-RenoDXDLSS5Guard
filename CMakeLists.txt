cmake_minimum_required(VERSION 3.21)
project(RenoDXDLSSGuard LANGUAGES CXX)

if(NOT MSVC)
  message(FATAL_ERROR "Build with MSVC (Visual Studio 2019/2022 Build Tools) targeting x64.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static CRT: the DLL has no dependency on the VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(RenoDXDLSSGuard SHARED src/RenoDXDLSSGuard.cpp src/StoreDecoder.h)
target_compile_definitions(RenoDXDLSSGuard PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_compile_options(RenoDXDLSSGuard PRIVATE /W4 /permissive- /EHsc)

# Pure-C++ unit tests for the instruction decoder.
enable_testing()
add_executable(decoder_test tests/decoder_test.cpp)
add_test(NAME decoder COMMAND decoder_test)

cmake_minimum_required(VERSION 3.21)

project(Antivirus LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(Antivirus WIN32
    Antivirus/Antivirus.cpp
    Antivirus/pch.cpp
    Antivirus/Antivirus.rc
    Antivirus/Antivirus.h
    Antivirus/framework.h
    Antivirus/pch.h
    Antivirus/Resource.h
    Antivirus/targetver.h
)

target_include_directories(Antivirus PRIVATE Antivirus)
target_compile_definitions(Antivirus PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_compile_options(Antivirus PRIVATE /utf-8)

set_target_properties(Antivirus PROPERTIES
    OUTPUT_NAME "Antivirus"
)
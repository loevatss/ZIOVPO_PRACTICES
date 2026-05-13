cmake_minimum_required(VERSION 3.21)

project(Antivirus LANGUAGES C CXX RC)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "This project supports only Windows + MSVC toolchain.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(SHARED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/Shared")
set(RPC_IDL "${SHARED_DIR}/AntivirusRpcControl.idl")

find_program(MIDL_EXECUTABLE NAMES midl.exe midl)
if(NOT MIDL_EXECUTABLE AND DEFINED ENV{WindowsSdkVerBinPath})
    file(TO_CMAKE_PATH "$ENV{WindowsSdkVerBinPath}" WINDOWS_SDK_BIN_DIR)
    find_program(
        MIDL_EXECUTABLE
        NAMES midl.exe midl
        HINTS "${WINDOWS_SDK_BIN_DIR}" "${WINDOWS_SDK_BIN_DIR}/x64" "${WINDOWS_SDK_BIN_DIR}/x86")
endif()
if(NOT MIDL_EXECUTABLE)
    set(MIDL_HINT_DIRS "")
    if(DEFINED ENV{ProgramFiles\(x86\)})
        file(TO_CMAKE_PATH "$ENV{ProgramFiles\(x86\)}" _midl_program_files_x86)
        set(_midl_windows_kits_bin_root "${_midl_program_files_x86}/Windows Kits/10/bin")
        if(EXISTS "${_midl_windows_kits_bin_root}")
            file(GLOB _midl_windows_kits_versions LIST_DIRECTORIES true "${_midl_windows_kits_bin_root}/*")
            list(SORT _midl_windows_kits_versions COMPARE NATURAL ORDER DESCENDING)
            foreach(version_dir IN LISTS _midl_windows_kits_versions)
                if(IS_DIRECTORY "${version_dir}")
                    list(APPEND MIDL_HINT_DIRS "${version_dir}")
                endif()
            endforeach()
        endif()
    endif()

    if(MIDL_HINT_DIRS)
        find_program(
            MIDL_EXECUTABLE
            NAMES midl.exe midl
            HINTS ${MIDL_HINT_DIRS}
            PATH_SUFFIXES x64 x86)
    endif()
endif()
if(NOT MIDL_EXECUTABLE)
    message(FATAL_ERROR "midl.exe was not found. Use Visual Studio 2022 environment with Windows SDK installed, or pass -DMIDL_EXECUTABLE=<full path to midl.exe>.")
endif()
message(STATUS "Using MIDL: ${MIDL_EXECUTABLE}")

function(resolve_windows_sdk_include out_var)
    set(sdk_version "${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
    if(NOT sdk_version AND DEFINED ENV{WindowsSDKVersion})
        set(sdk_version "$ENV{WindowsSDKVersion}")
    endif()

    if(sdk_version)
        string(REGEX REPLACE "[/\\]+$" "" sdk_version "${sdk_version}")
    endif()

    if(DEFINED ENV{WindowsSdkDir})
        file(TO_CMAKE_PATH "$ENV{WindowsSdkDir}" sdk_dir)
    endif()

    if(sdk_dir AND sdk_version)
        set(candidate "${sdk_dir}/Include/${sdk_version}")
        if(EXISTS "${candidate}")
            set(${out_var} "${candidate}" PARENT_SCOPE)
            return()
        endif()
    endif()

    set(${out_var} "" PARENT_SCOPE)
endfunction()

resolve_windows_sdk_include(WINDOWS_SDK_INCLUDE_ROOT)

set(MIDL_INCLUDE_DIRS "${SHARED_DIR}")
if(WINDOWS_SDK_INCLUDE_ROOT)
    list(APPEND MIDL_INCLUDE_DIRS
        "${WINDOWS_SDK_INCLUDE_ROOT}/shared"
        "${WINDOWS_SDK_INCLUDE_ROOT}/um"
        "${WINDOWS_SDK_INCLUDE_ROOT}/winrt")
else()
    set(PROGRAM_FILES_X86 "$ENV{ProgramFiles\(x86\)}")
    if(PROGRAM_FILES_X86)
        file(TO_CMAKE_PATH "${PROGRAM_FILES_X86}" PROGRAM_FILES_X86_PATH)
        set(WINDOWS_KITS_INCLUDE_ROOT "${PROGRAM_FILES_X86_PATH}/Windows Kits/10/Include")
        if(EXISTS "${WINDOWS_KITS_INCLUDE_ROOT}")
            file(GLOB WINDOWS_KITS_VERSIONS LIST_DIRECTORIES true "${WINDOWS_KITS_INCLUDE_ROOT}/*")
            list(SORT WINDOWS_KITS_VERSIONS COMPARE NATURAL ORDER DESCENDING)
            foreach(version_dir IN LISTS WINDOWS_KITS_VERSIONS)
                if(IS_DIRECTORY "${version_dir}")
                    list(APPEND MIDL_INCLUDE_DIRS
                        "${version_dir}/shared"
                        "${version_dir}/um"
                        "${version_dir}/winrt")
                endif()
            endforeach()
        endif()
    endif()
endif()

find_path(RPC_IDL_IMPORT_DIR NAMES rpc.idl PATHS ${MIDL_INCLUDE_DIRS} NO_DEFAULT_PATH)
find_path(RPCNDR_IDL_IMPORT_DIR NAMES rpcndr.idl PATHS ${MIDL_INCLUDE_DIRS} NO_DEFAULT_PATH)
if(NOT RPC_IDL_IMPORT_DIR OR NOT RPCNDR_IDL_IMPORT_DIR)
    list(APPEND MIDL_INCLUDE_DIRS "${SHARED_DIR}/MidlCompat")
    message(STATUS "Using Shared/MidlCompat fallback for rpc.idl/rpcndr.idl")
endif()

list(REMOVE_DUPLICATES MIDL_INCLUDE_DIRS)

set(MIDL_INCLUDE_ARGS "")
foreach(include_dir IN LISTS MIDL_INCLUDE_DIRS)
    list(APPEND MIDL_INCLUDE_ARGS /I "${include_dir}")
endforeach()

function(generate_rpc_sources target_name out_header out_client_stub out_server_stub)
    set(gen_dir "${CMAKE_CURRENT_BINARY_DIR}/Generated/${target_name}/${CMAKE_CFG_INTDIR}")
    set(header_file "${gen_dir}/AntivirusRpcControl.h")
    set(client_stub "${gen_dir}/AntivirusRpcControl_c.c")
    set(server_stub "${gen_dir}/AntivirusRpcControl_s.c")

    add_custom_command(
        OUTPUT "${header_file}" "${client_stub}" "${server_stub}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${gen_dir}"
        COMMAND "${MIDL_EXECUTABLE}"
                "${RPC_IDL}"
                /nologo
                /env x64
                /app_config
                /h AntivirusRpcControl.h
                /cstub AntivirusRpcControl_c.c
                /sstub AntivirusRpcControl_s.c
                /out "${gen_dir}"
                ${MIDL_INCLUDE_ARGS}
        DEPENDS "${RPC_IDL}"
        COMMENT "Generating RPC stubs for ${target_name}"
        VERBATIM)

    set(${out_header} "${header_file}" PARENT_SCOPE)
    set(${out_client_stub} "${client_stub}" PARENT_SCOPE)
    set(${out_server_stub} "${server_stub}" PARENT_SCOPE)
endfunction()

generate_rpc_sources(Antivirus ANTIVIRUS_RPC_HEADER ANTIVIRUS_RPC_CLIENT_STUB ANTIVIRUS_RPC_SERVER_STUB)
add_executable(Antivirus WIN32
    Antivirus/Antivirus.cpp
    Antivirus/pch.cpp
    Antivirus/Antivirus.rc
    Antivirus/Antivirus.h
    Antivirus/framework.h
    Antivirus/pch.h
    Antivirus/Resource.h
    Antivirus/targetver.h
    Antivirus/UserDesktopSession.cpp
    Antivirus/UserDesktopSession.h
    Antivirus/UserIsolatedStopConfirmation.cpp
    Antivirus/UserIsolatedStopConfirmation.h
    Shared/ProcessProtection.cpp
    Shared/ProcessProtection.h
    "${ANTIVIRUS_RPC_CLIENT_STUB}")

set_source_files_properties("${ANTIVIRUS_RPC_CLIENT_STUB}" PROPERTIES GENERATED TRUE)

# Shared headers + target-specific generated RPC header.
target_include_directories(Antivirus PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/Antivirus"
    "${SHARED_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/Generated/Antivirus/${CMAKE_CFG_INTDIR}")

target_compile_definitions(Antivirus PRIVATE UNICODE _UNICODE)
target_compile_options(Antivirus PRIVATE /utf-8)
target_link_libraries(Antivirus PRIVATE Advapi32 Rpcrt4 Shell32)

generate_rpc_sources(AntivirusService SERVICE_RPC_HEADER SERVICE_RPC_CLIENT_STUB SERVICE_RPC_SERVER_STUB)
add_executable(AntivirusService
    AntivirusService/service.cpp
    AntivirusService/AntivirusEngineSelfTest.cpp
    AntivirusService/AntivirusEngineSelfTest.h
    AntivirusService/AntivirusScanService.cpp
    AntivirusService/AntivirusScanService.h
    Shared/AntivirusEngine.cpp
    Shared/AntivirusEngine.h
    Shared/ProcessProtection.cpp
    Shared/ProcessProtection.h
    Shared/ServiceProtection.cpp
    Shared/ServiceProtection.h
    "${SERVICE_RPC_SERVER_STUB}")

set_source_files_properties("${SERVICE_RPC_SERVER_STUB}" PROPERTIES GENERATED TRUE)

target_include_directories(AntivirusService PRIVATE
    "${SHARED_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/Generated/AntivirusService/${CMAKE_CFG_INTDIR}")

target_compile_definitions(AntivirusService PRIVATE UNICODE _UNICODE)
target_compile_options(AntivirusService PRIVATE /utf-8)
target_link_libraries(AntivirusService PRIVATE Advapi32 Rpcrt4 Wtsapi32 Userenv)

foreach(runtime_target IN ITEMS Antivirus AntivirusService)
    set_target_properties(${runtime_target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/MinSizeRel")
endforeach()

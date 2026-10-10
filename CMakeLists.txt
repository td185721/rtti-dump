cmake_minimum_required(VERSION 3.15)
project(rtti_dump CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(rtti-dump src/main.cpp)

if(MSVC)
    target_compile_options(rtti-dump PRIVATE /W4 /permissive-)
else()
    target_compile_options(rtti-dump PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Tests: golden-file comparisons against fixture DLLs built from
# tests/fixtures/sample.cpp (see tests/fixtures/build.cmd).
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    function(golden_test name expected_rc args)
        add_test(NAME ${name}
                 COMMAND ${CMAKE_COMMAND}
                         -DTOOL=$<TARGET_FILE:rtti-dump>
                         "-DARGS=${args}"
                         -DWORKDIR=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures
                         -DEXPECTED=${CMAKE_CURRENT_SOURCE_DIR}/tests/expected/${name}.txt
                         -DEXPECTED_RC=${expected_rc}
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_golden.cmake)
    endfunction()
    golden_test(mangled 0 "sample64.dll")
    golden_test(demangled 0 "--demangle|sample64.dll")
    golden_test(x86-rejected 1 "sample32.dll")
    golden_test(usage 2 "")
endif()

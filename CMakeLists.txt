cmake_minimum_required(VERSION 3.16)
project(asterism VERSION 0.7.0.1 LANGUAGES C)


if(WIN32)
    set(CompilerDebugFlags
            CMAKE_CXX_FLAGS
            CMAKE_CXX_FLAGS_DEBUG
            CMAKE_C_FLAGS
            CMAKE_C_FLAGS_DEBUG
    )

    set(CompilerReleaseFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_MINSIZEREL
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS_MINSIZEREL 
    )

    foreach(CompilerFlag ${CompilerDebugFlags})
        string(REPLACE "/MDd" "/MTd" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()

    foreach(CompilerFlag ${CompilerReleaseFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()

    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE -D_CRT_SECURE_NO_WARNINGS)
endif()

if(UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
endif()

option(ASTERISM_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ASTERISM_COVERAGE "Build with GCC/Clang coverage instrumentation" OFF)

if((ASTERISM_SANITIZERS OR ASTERISM_COVERAGE) AND NOT CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    message(FATAL_ERROR "ASTERISM_SANITIZERS and ASTERISM_COVERAGE require GCC or Clang")
endif()

if(ASTERISM_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

if(ASTERISM_COVERAGE)
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()

add_subdirectory(3rdparty)
add_subdirectory(src/asterism)

option(UNIT_TEST "Build unit tests" ON)
if(UNIT_TEST)
    enable_testing()
    add_subdirectory(test)
endif()

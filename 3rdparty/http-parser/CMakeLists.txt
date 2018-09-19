cmake_minimum_required(VERSION 2.8)
add_library(http_parser http_parser.c)

if(WIN32)
    set(CompilerDebugFlags
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
    )

    set(CompilerReleaseFlags
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS_MINSIZEREL 
    )

    foreach(CompilerFlag ${CompilerDebugFlags})
        string(REGEX REPLACE "/W[0-4]" "/W0" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()

    foreach(CompilerFlag ${CompilerReleaseFlags})
        string(REGEX REPLACE "/W[0-4]" "/W0" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()
endif()
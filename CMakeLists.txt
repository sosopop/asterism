cmake_minimum_required(VERSION 2.8)
project(asterism C)


if(WIN32)
    if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio ([0-9]+)")
        # Note: "v110_xp" is for Visual Studio 11 2012, which is unsupported.
        if (${CMAKE_MATCH_1} EQUAL 12)
            # Visual Studio 12 2013
            set(CMAKE_GENERATOR_TOOLSET "v120_xp" CACHE STRING "CMAKE_GENERATOR_TOOLSET" FORCE)
            set(CMAKE_VS_PLATFORM_TOOLSET "v120_xp" CACHE STRING "CMAKE_VS_PLATFORM_TOOLSET" FORCE)
        elseif (${CMAKE_MATCH_1} EQUAL 14)
            # Visual Studio 14 2015
            set(CMAKE_GENERATOR_TOOLSET "v140_xp" CACHE STRING "CMAKE_GENERATOR_TOOLSET" FORCE)
            set(CMAKE_VS_PLATFORM_TOOLSET "v140_xp" CACHE STRING "CMAKE_VS_PLATFORM_TOOLSET" FORCE)
        elseif (${CMAKE_MATCH_1} EQUAL 15)
            # Visual Studio 15 2017
            set(CMAKE_GENERATOR_TOOLSET "v141_xp" CACHE STRING "CMAKE_GENERATOR_TOOLSET" FORCE)
            set(CMAKE_VS_PLATFORM_TOOLSET "v141_xp" CACHE STRING "CMAKE_VS_PLATFORM_TOOLSET" FORCE)
        endif()
    endif()

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

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE,5.02")
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE,5.01")
    endif()

    add_definitions(-D_WIN32_WINNT=0x0502 -D_CRT_NONSTDC_NO_DEPRECATE -D_CRT_SECURE_NO_WARNINGS)
endif()

if(UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -O3")
endif()

add_subdirectory(3rdparty/libuv)
add_subdirectory(3rdparty/http-parser)
add_subdirectory(3rdparty/jemalloc)
add_subdirectory(src/asterism)
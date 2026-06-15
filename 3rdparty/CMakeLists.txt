cmake_minimum_required(VERSION 3.5)

# ==========================================
# 1. http-parser Target
# ==========================================
add_library(http_parser STATIC http-parser/http_parser.c)
target_include_directories(http_parser PUBLIC http-parser)

if(MSVC)
    # Silence compiler warnings for http_parser
    target_compile_options(http_parser PRIVATE /W0)
endif()

# ==========================================
# 2. libuv Target (v1.9.1 compatibility)
# ==========================================
set(LIBUVDIR "libuv")

# Base source files common to all platforms
set(UV_SOURCES
    ${LIBUVDIR}/include/uv.h
    ${LIBUVDIR}/include/tree.h
    ${LIBUVDIR}/include/uv-errno.h
    ${LIBUVDIR}/include/uv-threadpool.h
    ${LIBUVDIR}/include/uv-version.h
    ${LIBUVDIR}/src/fs-poll.c
    ${LIBUVDIR}/src/heap-inl.h
    ${LIBUVDIR}/src/inet.c
    ${LIBUVDIR}/src/queue.h
    ${LIBUVDIR}/src/threadpool.c
    ${LIBUVDIR}/src/uv-common.c
    ${LIBUVDIR}/src/uv-common.h
    ${LIBUVDIR}/src/version.c
)

if(WIN32)
    # Windows-specific source files
    set(UV_SOURCES ${UV_SOURCES}
        ${LIBUVDIR}/include/uv-win.h
        ${LIBUVDIR}/src/win/async.c
        ${LIBUVDIR}/src/win/atomicops-inl.h
        ${LIBUVDIR}/src/win/core.c
        ${LIBUVDIR}/src/win/dl.c
        ${LIBUVDIR}/src/win/error.c
        ${LIBUVDIR}/src/win/fs.c
        ${LIBUVDIR}/src/win/fs-event.c
        ${LIBUVDIR}/src/win/getaddrinfo.c
        ${LIBUVDIR}/src/win/getnameinfo.c
        ${LIBUVDIR}/src/win/handle.c
        ${LIBUVDIR}/src/win/handle-inl.h
        ${LIBUVDIR}/src/win/internal.h
        ${LIBUVDIR}/src/win/loop-watcher.c
        ${LIBUVDIR}/src/win/pipe.c
        ${LIBUVDIR}/src/win/thread.c
        ${LIBUVDIR}/src/win/poll.c
        ${LIBUVDIR}/src/win/process.c
        ${LIBUVDIR}/src/win/process-stdio.c
        ${LIBUVDIR}/src/win/req.c
        ${LIBUVDIR}/src/win/req-inl.h
        ${LIBUVDIR}/src/win/signal.c
        ${LIBUVDIR}/src/win/stream.c
        ${LIBUVDIR}/src/win/stream-inl.h
        ${LIBUVDIR}/src/win/tcp.c
        ${LIBUVDIR}/src/win/tty.c
        ${LIBUVDIR}/src/win/timer.c
        ${LIBUVDIR}/src/win/udp.c
        ${LIBUVDIR}/src/win/util.c
        ${LIBUVDIR}/src/win/winapi.c
        ${LIBUVDIR}/src/win/winapi.h
        ${LIBUVDIR}/src/win/winsock.c
        ${LIBUVDIR}/src/win/winsock.h
        ${LIBUVDIR}/src/win/snprintf.c
    )

    add_library(uv STATIC ${UV_SOURCES})
    
    # Silence warnings in MSVC for libuv
    if(MSVC)
        target_compile_options(uv PRIVATE /W0)
    endif()

    target_link_libraries(uv PUBLIC advapi32 iphlpapi psapi userenv shell32 ws2_32)

else()
    # Unix-specific base source files
    set(UV_SOURCES ${UV_SOURCES}
        ${LIBUVDIR}/include/uv-unix.h
        ${LIBUVDIR}/include/uv-linux.h
        ${LIBUVDIR}/include/uv-sunos.h
        ${LIBUVDIR}/include/uv-darwin.h
        ${LIBUVDIR}/include/uv-bsd.h
        ${LIBUVDIR}/include/uv-aix.h
        ${LIBUVDIR}/src/unix/async.c
        ${LIBUVDIR}/src/unix/atomic-ops.h
        ${LIBUVDIR}/src/unix/core.c
        ${LIBUVDIR}/src/unix/dl.c
        ${LIBUVDIR}/src/unix/fs.c
        ${LIBUVDIR}/src/unix/getaddrinfo.c
        ${LIBUVDIR}/src/unix/getnameinfo.c
        ${LIBUVDIR}/src/unix/internal.h
        ${LIBUVDIR}/src/unix/loop.c
        ${LIBUVDIR}/src/unix/loop-watcher.c
        ${LIBUVDIR}/src/unix/pipe.c
        ${LIBUVDIR}/src/unix/poll.c
        ${LIBUVDIR}/src/unix/process.c
        ${LIBUVDIR}/src/unix/signal.c
        ${LIBUVDIR}/src/unix/spinlock.h
        ${LIBUVDIR}/src/unix/stream.c
        ${LIBUVDIR}/src/unix/tcp.c
        ${LIBUVDIR}/src/unix/thread.c
        ${LIBUVDIR}/src/unix/timer.c
        ${LIBUVDIR}/src/unix/tty.c
        ${LIBUVDIR}/src/unix/udp.c
    )

    # Platform-specific definitions and extra source files
    if(APPLE)
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/src/unix/proctitle.c
            ${LIBUVDIR}/src/unix/kqueue.c
            ${LIBUVDIR}/src/unix/darwin.c
            ${LIBUVDIR}/src/unix/fsevents.c
            ${LIBUVDIR}/src/unix/pthread-barrier.c
            ${LIBUVDIR}/src/unix/darwin-proctitle.c
        )
        set_source_files_properties(${LIBUVDIR}/src/unix/stream.c PROPERTIES COMPILE_FLAGS "-Wno-gnu-folding-constant")
    endif()

    if(NOT APPLE)
        set(UV_EXTRA_FLAGS "-Wstrict-aliasing")
    endif()

    if((${CMAKE_SYSTEM_NAME} MATCHES "Linux") OR (${CMAKE_SYSTEM_NAME} MATCHES "Android"))
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/src/unix/proctitle.c
            ${LIBUVDIR}/src/unix/linux-core.c
            ${LIBUVDIR}/src/unix/linux-inotify.c
            ${LIBUVDIR}/src/unix/linux-syscalls.c
            ${LIBUVDIR}/src/unix/linux-syscalls.h
        )
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/src/unix/sunos.c
        )
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "AIX")
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/src/unix/aic.c
        )
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "DragonFlyBSD")
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/src/unix/freebsd.c
        )
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/src/unix/openbsd.c
        )
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/src/unix/netbsd.c
        )
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "DragonFlyBSD" OR
       ${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/src/unix/kqueue.c
        )
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
        set(UV_SOURCES ${UV_SOURCES}
            ${LIBUVDIR}/include/android-ifaddrs.h
            ${LIBUVDIR}/include/pthread-barrier.h
            ${LIBUVDIR}/src/unix/android-ifaddrs.c
            ${LIBUVDIR}/src/unix/pthread-barrier.c
            ${LIBUVDIR}/src/unix/pthread-fixes.c
        )
    endif()

    add_library(uv STATIC ${UV_SOURCES})

    # Set compiler options and definitions target-specifically
    target_compile_options(uv PRIVATE -g --std=gnu89 -pedantic -Wall -Wextra -Wno-unused-parameter ${UV_EXTRA_FLAGS})
    target_compile_definitions(uv PRIVATE _LARGEFILE_SOURCE _FILE_OFFSET_BITS=64 SO_NOSIGPIPE)
    target_include_directories(uv PRIVATE ${LIBUVDIR}/src/unix)

    if(APPLE)
        target_compile_definitions(uv PRIVATE _DARWIN_USE_64_BIT_INODE=1 _DARWIN_UNLIMITED_SELECT=1)
    endif()

    if((${CMAKE_SYSTEM_NAME} MATCHES "Linux") OR (${CMAKE_SYSTEM_NAME} MATCHES "Android"))
        target_compile_definitions(uv PRIVATE _GNU_SOURCE _POSIX_C_SOURCE=200112)
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
        target_compile_definitions(uv PRIVATE __EXTENSIONS__ _XOPEN_SOURCE=500)
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "AIX")
        target_compile_definitions(uv PRIVATE _ALL_SOURCE _XOPEN_SOURCE=500 _LINUX_SOURCE_COMPAT)
    endif()

    # Link system dependencies for UNIX
    find_library(M_LIB NAMES m)
    find_package(Threads)
    target_link_libraries(uv PUBLIC ${CMAKE_THREAD_LIBS_INIT} ${M_LIB})

    if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        find_library(DL_LIB NAMES dl)
        find_library(RT_LIB NAMES rt)
        target_link_libraries(uv PUBLIC ${DL_LIB} ${RT_LIB})
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
        find_library(KSTAT_LIB NAMES kstat)
        find_library(NSL_LIB NAMES nsl)
        find_library(SENDFILE_LIB NAMES sendfile)
        find_library(SOCKET_LIB NAMES socket)
        target_link_libraries(uv PUBLIC ${KSTAT_LIB} ${NSL_LIB} ${SENDFILE_LIB} ${SOCKET_LIB})
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "AIX")
        find_library(PERFSTAT_LIB NAMES perfstat)
        target_link_libraries(uv PUBLIC ${PERFSTAT_LIB})
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "DragonFlyBSD" OR
       ${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
        find_library(KVM_LIB NAMES kvm)
        target_link_libraries(uv PUBLIC ${KVM_LIB})
    endif()
endif()

# Setup header include paths publicly propagated to any linked targets
target_include_directories(uv PUBLIC ${LIBUVDIR}/include)
target_include_directories(uv PRIVATE ${LIBUVDIR}/src)

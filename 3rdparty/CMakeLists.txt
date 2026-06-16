cmake_minimum_required(VERSION 3.16)

# libuv is maintained upstream with first-class CMake targets. Use those targets
# instead of a local source-file list so platform-specific files stay correct.
set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(ENABLE_CLANG_TIDY OFF CACHE BOOL "" FORCE)
add_subdirectory(libuv EXCLUDE_FROM_ALL)

# llhttp generated C files are intentionally not tracked by the llhttp repo.
# Use a build-local source copy so concurrent build trees never share node_modules
# or generated files.
set(LLHTTP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/llhttp")
set(LLHTTP_WORK_DIR "${CMAKE_CURRENT_BINARY_DIR}/llhttp-src")
set(LLHTTP_HEADER "${LLHTTP_WORK_DIR}/build/llhttp.h")
set(LLHTTP_GENERATED_SOURCE "${LLHTTP_WORK_DIR}/build/c/llhttp.c")
if(WIN32)
    find_program(ASTERISM_NPM_EXECUTABLE NAMES npm.cmd)
else()
    find_program(ASTERISM_NPM_EXECUTABLE NAMES npm)
endif()
if(NOT ASTERISM_NPM_EXECUTABLE)
    message(FATAL_ERROR "npm is required to generate llhttp sources")
endif()

file(COPY "${LLHTTP_DIR}/"
    DESTINATION "${LLHTTP_WORK_DIR}"
    PATTERN ".git" EXCLUDE
    PATTERN "build" EXCLUDE
    PATTERN "node_modules" EXCLUDE
)

add_custom_command(
    OUTPUT "${LLHTTP_HEADER}" "${LLHTTP_GENERATED_SOURCE}"
    COMMAND "${ASTERISM_NPM_EXECUTABLE}" ci
    COMMAND "${ASTERISM_NPM_EXECUTABLE}" run build
    WORKING_DIRECTORY "${LLHTTP_WORK_DIR}"
    DEPENDS
        "${LLHTTP_DIR}/package.json"
        "${LLHTTP_DIR}/package-lock.json"
        "${LLHTTP_DIR}/src/llhttp/http.ts"
        "${LLHTTP_DIR}/src/llhttp/constants.ts"
        "${LLHTTP_DIR}/src/native/api.c"
        "${LLHTTP_DIR}/src/native/http.c"
    COMMENT "Generating llhttp C sources"
    VERBATIM
)

add_library(llhttp STATIC
    "${LLHTTP_GENERATED_SOURCE}"
    "${LLHTTP_DIR}/src/native/api.c"
    "${LLHTTP_DIR}/src/native/http.c"
    "${LLHTTP_HEADER}"
)

target_include_directories(llhttp PUBLIC
    "${LLHTTP_WORK_DIR}/build"
    "${LLHTTP_DIR}/src/native"
)

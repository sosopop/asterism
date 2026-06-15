# Get all source files
file(GLOB ASTERISM_SOURCE "*.h" "*.c")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${ASTERISM_SOURCE})

# Separate main.c and other sources to build a static library asterism_lib
set(ASTERISM_LIB_SOURCE ${ASTERISM_SOURCE})
list(REMOVE_ITEM ASTERISM_LIB_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/main.c")

add_library(asterism_lib STATIC ${ASTERISM_LIB_SOURCE})

# Propagate includes for asterism_lib so downstream targets automatically get its headers
target_include_directories(asterism_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# System dependencies
set(SYS_LIBS)
if(WIN32)
    list(APPEND SYS_LIBS ws2_32 iphlpapi psapi userenv)
else()
    list(APPEND SYS_LIBS pthread dl m)
endif()

if(ANDROID)
    list(REMOVE_ITEM SYS_LIBS pthread)
endif()

# Link dependencies to the library. Linking publicly propagates these dependencies (and their includes)
target_link_libraries(asterism_lib PUBLIC uv http_parser PUBLIC ${SYS_LIBS})

# CLI executable target
add_executable(asterism main.c)
target_link_libraries(asterism PRIVATE asterism_lib)

if(UNIX)
    target_compile_options(asterism_lib PRIVATE -std=gnu99)
    target_compile_options(asterism PRIVATE -std=gnu99)
endif()
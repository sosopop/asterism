include_directories("../../3rdparty/libuv/include")
include_directories("../../3rdparty/http-parser")

file(GLOB ASTERISM_SOURCE "*.h" "*.c")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${ASTERISM_SOURCE})

# Separate main.c and other sources to build a static library asterism_lib
set(ASTERISM_LIB_SOURCE ${ASTERISM_SOURCE})
list(REMOVE_ITEM ASTERISM_LIB_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/main.c")

add_library(asterism_lib STATIC ${ASTERISM_LIB_SOURCE})

# CLI executable target
add_executable(asterism main.c)

if(WIN32)
    list(APPEND LINK_LIB ws2_32 iphlpapi psapi userenv)
else()
    list(APPEND LINK_LIB pthread dl m)
endif()

if(ANDROID)
    list(REMOVE_ITEM LINK_LIB pthread)
endif()

list(APPEND LINK_LIB uv http_parser)

if(UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
endif()

# Link static library itself with dependencies
target_link_libraries(asterism_lib ${LINK_LIB})

# Link CLI executable against the library
target_link_libraries(asterism asterism_lib ${LINK_LIB})
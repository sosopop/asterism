include_directories("../../3rdparty/libuv/include")
include_directories("../../3rdparty/http-parser")

aux_source_directory(. ASTERISM_SOURCE)
aux_source_directory(./test ASTERISM_SOURCE)
add_executable(asterism ${ASTERISM_SOURCE})

list(APPEND LINK_LIB uv)

if(WIN32)
    list(APPEND LINK_LIB ws2_32 iphlpapi psapi userenv)
else()
    list(APPEND LINK_LIB pthread dl m)
endif()

if(ANDROID)
    list(REMOVE_ITEM LINK_LIB pthread)
endif()

target_link_libraries(asterism ${LINK_LIB})
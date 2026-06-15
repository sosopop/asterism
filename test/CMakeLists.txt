include_directories("../3rdparty/libuv/include")
include_directories("../3rdparty/http-parser")
include_directories("../src/asterism")

set(TEST_SOURCE
    test_framework.h
    test_framework.c
    test_utils.h
    test_utils.c
    suite_utils.c
    suite_proxy.c
    suite_hooks.c
    suite_timeouts.c
    suite_portal.c
    main.c
)

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${TEST_SOURCE})

add_definitions(-DUNIT_TEST)

add_executable(asterism_test ${TEST_SOURCE})

if(WIN32)
    list(APPEND LINK_LIB ws2_32 iphlpapi psapi userenv)
else()
    list(APPEND LINK_LIB pthread dl m)
endif()

if(ANDROID)
    list(REMOVE_ITEM LINK_LIB pthread)
endif()

list(APPEND LINK_LIB uv http_parser asterism_lib)

if(UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
endif()

target_link_libraries(asterism_test ${LINK_LIB})

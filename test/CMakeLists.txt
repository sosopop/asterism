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

add_executable(asterism_test ${TEST_SOURCE})

# Define unit test macro specifically for the test suite
target_compile_definitions(asterism_test PRIVATE UNIT_TEST)

# Link against asterism_lib which already brings in all dependencies and their headers transitively
target_link_libraries(asterism_test PRIVATE asterism_lib)

add_test(NAME asterism_test COMMAND asterism_test)

if(UNIX)
    target_compile_options(asterism_test PRIVATE -std=gnu99)
endif()

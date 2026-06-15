#include "test_framework.h"
#include "test_utils.h"
#include <time.h>

static void test_timeouts_idle(void) {
    // Set idle timeout to 2 seconds for faster tests
    unsigned int idle_timeout = 2;
    test_env_t *env = test_env_create(NULL, idle_timeout);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    
    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        time_t start_time = time(NULL);
        char buffer[1024] = {0};
        
        // Blocking recv waiting for idle timeout
        int ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        // Expect connection closed by server (returns 0)
        EXPECT_EQ(ret, 0);
        
        time_t end_time = time(NULL);
        double elapsed = difftime(end_time, start_time);
        
        EXPECT_TRUE(elapsed >= (double)idle_timeout);
        EXPECT_TRUE(elapsed <= (double)(idle_timeout + 2));
        
        test_socket_close(sock);
    }
    test_env_destroy(env);
}

void register_suite_timeouts(void) {
    register_test("Timeouts", "IdleTimeout", test_timeouts_idle);
}

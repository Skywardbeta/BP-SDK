#include "bp_sdk.h"
#include "bp_bundle.h"
#include "bp_storage.h"
#include "bp_tcpcl.h"
#include "bp_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define THREAD_HANDLE HANDLE
#define THREAD_RETURN unsigned __stdcall
#define THREAD_CREATE(h, fn, arg) h = (HANDLE)_beginthreadex(NULL, 0, fn, arg, 0, NULL)
#define THREAD_JOIN(h) WaitForSingleObject(h, INFINITE); CloseHandle(h)
#define sleep_ms(ms) Sleep(ms)
#define ATOMIC_INC(v) InterlockedIncrement((volatile LONG*)&(v))
#else
#include <pthread.h>
#include <unistd.h>
#define THREAD_HANDLE pthread_t
#define THREAD_RETURN void*
#define THREAD_CREATE(h, fn, arg) pthread_create(&h, NULL, (void*(*)(void*))fn, arg)
#define THREAD_JOIN(h) pthread_join(h, NULL)
#define sleep_ms(ms) usleep((ms) * 1000)
#define ATOMIC_INC(v) __sync_fetch_and_add(&(v), 1)
#endif

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-55s", #name); \
    fflush(stdout); \
    test_##name(); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL\n    %s:%d: %lld != %lld\n", __FILE__, __LINE__, \
               (long long)(a), (long long)(b)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define PASS() do { printf("OK\n"); tests_passed++; } while(0)

typedef struct {
    int thread_id;
    int iterations;
    volatile int *success_count;
    volatile int *error_count;
} thread_args_t;

static THREAD_RETURN storage_worker(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    bp_store_t store;
    
    if (bp_store_init(&store, 1024 * 1024) != 0) {
        ATOMIC_INC(*args->error_count);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }
    
    for (int i = 0; i < args->iterations; i++) {
        char id[64];
        snprintf(id, sizeof(id), "thread%d-bundle%d", args->thread_id, i);
        
        uint8_t data[128];
        memset(data, (uint8_t)i, sizeof(data));
        
        if (bp_store_put(&store, id, data, sizeof(data), 0xFFFFFFFF) != 0) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        uint8_t *retrieved = NULL;
        size_t len = 0;
        if (bp_store_get(&store, id, &retrieved, &len) != 0) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        if (len != sizeof(data) || memcmp(retrieved, data, len) != 0) {
            bp_free(retrieved);
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        bp_free(retrieved);
        
        if (bp_store_delete(&store, id) != 0) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        ATOMIC_INC(*args->success_count);
    }
    
    bp_store_free(&store);
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

TEST(concurrent_storage_isolated) {
    #define NUM_THREADS 4
    #define ITERATIONS 100
    
    THREAD_HANDLE threads[NUM_THREADS];
    thread_args_t args[NUM_THREADS];
    volatile int success_count = 0;
    volatile int error_count = 0;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].iterations = ITERATIONS;
        args[i].success_count = &success_count;
        args[i].error_count = &error_count;
        THREAD_CREATE(threads[i], storage_worker, &args[i]);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    ASSERT_EQ(error_count, 0);
    ASSERT_EQ(success_count, NUM_THREADS * ITERATIONS);
    
    PASS();
    
    #undef NUM_THREADS
    #undef ITERATIONS
}

static bp_store_t *g_shared_store = NULL;

#ifdef _WIN32
static CRITICAL_SECTION g_store_lock;
#define STORE_LOCK() EnterCriticalSection(&g_store_lock)
#define STORE_UNLOCK() LeaveCriticalSection(&g_store_lock)
#define STORE_LOCK_INIT() InitializeCriticalSection(&g_store_lock)
#define STORE_LOCK_DESTROY() DeleteCriticalSection(&g_store_lock)
#else
static pthread_mutex_t g_store_lock = PTHREAD_MUTEX_INITIALIZER;
#define STORE_LOCK() pthread_mutex_lock(&g_store_lock)
#define STORE_UNLOCK() pthread_mutex_unlock(&g_store_lock)
#define STORE_LOCK_INIT() pthread_mutex_init(&g_store_lock, NULL)
#define STORE_LOCK_DESTROY() pthread_mutex_destroy(&g_store_lock)
#endif

static THREAD_RETURN shared_storage_worker(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    
    for (int i = 0; i < args->iterations; i++) {
        char id[64];
        snprintf(id, sizeof(id), "shared-t%d-b%d", args->thread_id, i);
        
        uint8_t data[64];
        memset(data, (uint8_t)(args->thread_id ^ i), sizeof(data));
        
        STORE_LOCK();
        int rc = bp_store_put(g_shared_store, id, data, sizeof(data), 0xFFFFFFFF);
        STORE_UNLOCK();
        
        if (rc != 0) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        uint8_t *retrieved = NULL;
        size_t len = 0;
        
        STORE_LOCK();
        rc = bp_store_get(g_shared_store, id, &retrieved, &len);
        STORE_UNLOCK();
        
        if (rc != 0) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        if (len != sizeof(data) || memcmp(retrieved, data, len) != 0) {
            bp_free(retrieved);
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        bp_free(retrieved);
        
        STORE_LOCK();
        rc = bp_store_delete(g_shared_store, id);
        STORE_UNLOCK();
        
        if (rc != 0) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        ATOMIC_INC(*args->success_count);
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

TEST(concurrent_storage_shared) {
    #define NUM_THREADS 4
    #define ITERATIONS 50
    
    bp_store_t store;
    ASSERT_EQ(bp_store_init(&store, 10 * 1024 * 1024), 0);
    g_shared_store = &store;
    
    STORE_LOCK_INIT();
    
    THREAD_HANDLE threads[NUM_THREADS];
    thread_args_t args[NUM_THREADS];
    volatile int success_count = 0;
    volatile int error_count = 0;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].iterations = ITERATIONS;
        args[i].success_count = &success_count;
        args[i].error_count = &error_count;
        THREAD_CREATE(threads[i], shared_storage_worker, &args[i]);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    STORE_LOCK_DESTROY();
    g_shared_store = NULL;
    bp_store_free(&store);
    
    ASSERT_EQ(error_count, 0);
    ASSERT_EQ(success_count, NUM_THREADS * ITERATIONS);
    
    PASS();
    
    #undef NUM_THREADS
    #undef ITERATIONS
}

static volatile int g_sdk_init_done = 0;

static THREAD_RETURN sdk_worker(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    
    while (!g_sdk_init_done) {
        sleep_ms(1);
    }
    
    for (int i = 0; i < args->iterations; i++) {
        bp_endpoint_t *ep = NULL;
        char eid[64];
        snprintf(eid, sizeof(eid), "ipn:1.%d%d", args->thread_id, i);
        
        int rc = bp_endpoint_create(eid, &ep);
        if (rc != BP_SUCCESS) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        rc = bp_endpoint_register(ep);
        if (rc != BP_SUCCESS) {
            bp_endpoint_destroy(ep);
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        rc = bp_endpoint_unregister(ep);
        if (rc != BP_SUCCESS) {
            bp_endpoint_destroy(ep);
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        rc = bp_endpoint_destroy(ep);
        if (rc != BP_SUCCESS) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        ATOMIC_INC(*args->success_count);
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

TEST(concurrent_sdk_endpoints) {
    #define NUM_THREADS 4
    #define ITERATIONS 25
    
    g_sdk_init_done = 0;
    
    int rc = bp_init("ipn:1.0", NULL);
    ASSERT_EQ(rc, BP_SUCCESS);
    
    THREAD_HANDLE threads[NUM_THREADS];
    thread_args_t args[NUM_THREADS];
    volatile int success_count = 0;
    volatile int error_count = 0;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].iterations = ITERATIONS;
        args[i].success_count = &success_count;
        args[i].error_count = &error_count;
        THREAD_CREATE(threads[i], sdk_worker, &args[i]);
    }
    
    g_sdk_init_done = 1;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    bp_shutdown();
    
    ASSERT_EQ(error_count, 0);
    ASSERT_EQ(success_count, NUM_THREADS * ITERATIONS);
    
    PASS();
    
    #undef NUM_THREADS
    #undef ITERATIONS
}

static THREAD_RETURN bundle_encode_worker(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    
    for (int i = 0; i < args->iterations; i++) {
        bp_bundle_full_t bundle;
        memset(&bundle, 0, sizeof(bundle));
        
        bundle.primary.version = 7;
        bundle.primary.dest_scheme = BP_EID_IPN;
        bundle.primary.dest_ssp[0] = 2;
        bundle.primary.dest_ssp[1] = (uint64_t)args->thread_id;
        bundle.primary.source_scheme = BP_EID_IPN;
        bundle.primary.source_ssp[0] = 1;
        bundle.primary.source_ssp[1] = (uint64_t)i;
        bundle.primary.report_scheme = BP_EID_IPN;
        bundle.primary.lifetime_ms = 3600000;
        bundle.primary.creation_ts = (uint64_t)i;
        bundle.primary.creation_seq = (uint64_t)args->thread_id;
        
        char payload[256];
        snprintf(payload, sizeof(payload), "Thread %d, iteration %d payload data", 
                 args->thread_id, i);
        bundle.payload = (uint8_t *)payload;
        bundle.payload_len = strlen(payload);
        
        uint8_t buf[1024];
        int len = bp_bundle_encode(&bundle, buf, sizeof(buf));
        if (len <= 0) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        bp_bundle_full_t decoded;
        int rc = bp_bundle_decode(buf, (size_t)len, &decoded);
        if (rc != 0) {
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        if (decoded.payload_len != bundle.payload_len ||
            memcmp(decoded.payload, bundle.payload, bundle.payload_len) != 0) {
            bp_bundle_full_free(&decoded);
            ATOMIC_INC(*args->error_count);
            continue;
        }
        
        bp_bundle_full_free(&decoded);
        ATOMIC_INC(*args->success_count);
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

TEST(concurrent_bundle_encode_decode) {
    #define NUM_THREADS 4
    #define ITERATIONS 100
    
    THREAD_HANDLE threads[NUM_THREADS];
    thread_args_t args[NUM_THREADS];
    volatile int success_count = 0;
    volatile int error_count = 0;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].iterations = ITERATIONS;
        args[i].success_count = &success_count;
        args[i].error_count = &error_count;
        THREAD_CREATE(threads[i], bundle_encode_worker, &args[i]);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    ASSERT_EQ(error_count, 0);
    ASSERT_EQ(success_count, NUM_THREADS * ITERATIONS);
    
    PASS();
    
    #undef NUM_THREADS
    #undef ITERATIONS
}

TEST(tcpcl_session_init_close) {
    tcpcl_session_t sess;
    tcpcl_session_init(&sess, -1);
    
    ASSERT_EQ(sess.fd, -1);
    ASSERT_EQ(sess.connected, 0);
    ASSERT(sess.segment_mru > 0);
    
    tcpcl_session_close(&sess);
    
    PASS();
}

TEST(tcpcl_multiple_sessions) {
    tcpcl_session_t sessions[10];
    
    for (int i = 0; i < 10; i++) {
        tcpcl_session_init(&sessions[i], i);
        ASSERT_EQ(sessions[i].fd, i);
    }
    
    for (int i = 0; i < 10; i++) {
        sessions[i].fd = -1;
        tcpcl_session_close(&sessions[i]);
    }
    
    PASS();
}

TEST(rapid_init_shutdown) {
    for (int i = 0; i < 10; i++) {
        int rc = bp_init("ipn:1.0", NULL);
        ASSERT_EQ(rc, BP_SUCCESS);
        
        bp_endpoint_t *ep = NULL;
        rc = bp_endpoint_create("ipn:1.1", &ep);
        ASSERT_EQ(rc, BP_SUCCESS);
        
        bp_endpoint_destroy(ep);
        bp_shutdown();
    }
    
    PASS();
}

TEST(memory_stress) {
    bp_store_t store;
    bp_store_init(&store, 50 * 1024 * 1024);
    
    for (int i = 0; i < 1000; i++) {
        char id[64];
        snprintf(id, sizeof(id), "stress-bundle-%d", i);
        
        size_t size = 1024 + (size_t)(i % 10000);
        uint8_t *data = bp_alloc(size);
        ASSERT(data != NULL);
        memset(data, (uint8_t)i, size);
        
        int rc = bp_store_put(&store, id, data, size, 0xFFFFFFFF);
        bp_free(data);
        ASSERT_EQ(rc, 0);
    }
    
    for (int i = 0; i < 1000; i++) {
        char id[64];
        snprintf(id, sizeof(id), "stress-bundle-%d", i);
        
        int rc = bp_store_delete(&store, id);
        ASSERT_EQ(rc, 0);
    }
    
    bp_store_free(&store);
    
    PASS();
}

int main(void) {
    printf("\n=== BP-SDK Concurrency & Thread Safety Tests ===\n\n");
    
    printf("Concurrent Storage Tests:\n");
    RUN_TEST(concurrent_storage_isolated);
    RUN_TEST(concurrent_storage_shared);
    
    printf("\nConcurrent Bundle Tests:\n");
    RUN_TEST(concurrent_bundle_encode_decode);
    
    printf("\nConcurrent SDK Tests:\n");
    RUN_TEST(concurrent_sdk_endpoints);
    RUN_TEST(rapid_init_shutdown);
    
    printf("\nTCPCL Session Tests:\n");
    RUN_TEST(tcpcl_session_init_close);
    RUN_TEST(tcpcl_multiple_sessions);
    
    printf("\nStress Tests:\n");
    RUN_TEST(memory_stress);
    
    printf("\n=== Results: %d passed, %d failed ===\n\n", tests_passed, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}


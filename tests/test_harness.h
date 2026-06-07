/*
 * test_harness.h - minimal shared assertions for BP-SDK test executables.
 *
 * Each test file is its own executable; including this header gives it the
 * tests_passed/tests_failed counters plus RUN_TEST/ASSERT/PASS/TEST_SUMMARY.
 */
#ifndef BP_TEST_HARNESS_H
#define BP_TEST_HARNESS_H

#include <stdio.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); fflush(stdout); test_##name(); \
} while (0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    line %d: %s\n", __LINE__, #cond); \
        tests_failed++; return; \
    } \
} while (0)

#define PASS() do { printf("OK\n"); tests_passed++; } while (0)

#define TEST_SUMMARY() do { \
    printf("\n  %d passed, %d failed\n", tests_passed, tests_failed); \
} while (0)

#endif

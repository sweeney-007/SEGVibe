/* Helpers for task tests, fuzz drivers and perf drivers. Included after the
 * candidate code. Every name starts with segv_ or is an upper-case macro. */
#ifndef SEGV_HARNESS_H
#define SEGV_HARNESS_H

#include <time.h>

static int segv_checks, segv_fails;
static int segv_quiet;               /* allocation-failure runs ignore wrong results */
static volatile long segv_sink;      /* keeps perf work from being optimized away */
static uint64_t segv_rng = 88172645463325252ULL;

#define SEGV_FAIL_AT(line, ...)                                                   \
    do {                                                                          \
        segv_fails++;                                                             \
        if (!segv_quiet && segv_fails <= 20) {                                    \
            fprintf(stderr, "SEGV_FAIL %s:%d: ", __FILE__, line);                      \
            fprintf(stderr, __VA_ARGS__);                                         \
            fputc('\n', stderr);                                                  \
        }                                                                         \
    } while (0)

#define CHECK(c)                                                                  \
    do { segv_checks++; if (!(c)) SEGV_FAIL_AT(__LINE__, "%s", #c); } while (0)

#define CHECK_INT(got, want)                                                      \
    do {                                                                          \
        long long g_ = (long long)(got), w_ = (long long)(want);                  \
        segv_checks++;                                                            \
        if (g_ != w_) SEGV_FAIL_AT(__LINE__, "%s == %lld, expected %lld", #got, g_, w_); \
    } while (0)

#define CHECK_STR(got, want)                                                      \
    do {                                                                          \
        const char *g_ = (got), *w_ = (want);                                     \
        segv_checks++;                                                            \
        if (!g_ || !w_ ? g_ != w_ : strcmp(g_, w_) != 0)                          \
            SEGV_FAIL_AT(__LINE__, "%s == \"%s\", expected \"%s\"", #got,         \
                         g_ ? g_ : "(null)", w_ ? w_ : "(null)");                 \
    } while (0)

static uint64_t segv_rand(void) {
    segv_rng ^= segv_rng >> 12; segv_rng ^= segv_rng << 25; segv_rng ^= segv_rng >> 27;
    return segv_rng * 2685821657736338717ULL;
}

/* uniform integer in [lo, hi] */
static long segv_rand_int(long lo, long hi) {
    return lo + (long)(segv_rand() % (uint64_t)(hi - lo + 1));
}

/* heap string of exactly n chars from alphabet; exact size so overreads hit a redzone */
static char *segv_rand_str_n(size_t n, const char *alphabet) {
    size_t k = strlen(alphabet);
    char *s = malloc(n + 1);
    for (size_t i = 0; i < n; i++) s[i] = alphabet[segv_rand() % k];
    s[n] = 0;
    return s;
}

/* heap string of random length 0..maxlen */
static char *segv_rand_str(size_t maxlen, const char *alphabet) {
    return segv_rand_str_n((size_t)segv_rand_int(0, (long)maxlen), alphabet);
}

/* heap int array of exactly n values in [lo, hi] */
static int *segv_rand_ints(size_t n, int lo, int hi) {
    int *a = malloc((n ? n : 1) * sizeof(int));
    for (size_t i = 0; i < n; i++) a[i] = (int)segv_rand_int(lo, hi);
    return a;
}

static int segv_cmp_int(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

static long long segv_now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

#endif

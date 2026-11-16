/* Implementation of the SEGVibe allocation tracker (compiled without the
 * force-included header, so it calls the real allocator). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void *p;          /* NULL = empty slot, TOMB = deleted */
    size_t size;
    const char *file;
    int line;
} Block;

#define TOMB ((void *)1)

static Block *tab;
static size_t cap, used;     /* used counts live + tombstones */
static size_t live_bytes, peak_bytes, peak_total, max_alloc;
static long n_allocs, fail_at = -1, fail_count;

typedef struct { FILE *f; const char *file; int line; } OpenFile;
static OpenFile files[256];

static size_t slot(void *p) {
    uintptr_t x = (uintptr_t)p;
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33;
    return (size_t)x & (cap - 1);
}

static void put(void *p, size_t size, const char *file, int line);

static void grow(void) {
    Block *old = tab; size_t oldcap = cap;
    cap = cap ? cap * 2 : 1024;
    tab = calloc(cap, sizeof(Block));
    used = 0;
    for (size_t i = 0; i < oldcap; i++)
        if (old[i].p && old[i].p != TOMB) put(old[i].p, old[i].size, old[i].file, old[i].line);
    free(old);
}

static void put(void *p, size_t size, const char *file, int line) {
    if ((used + 1) * 2 > cap) grow();
    size_t i = slot(p);
    while (tab[i].p && tab[i].p != TOMB) i = (i + 1) & (cap - 1);
    if (!tab[i].p) used++;
    tab[i] = (Block){p, size, file, line};
}

static Block *find(void *p) {
    if (!cap) return NULL;
    size_t i = slot(p);
    while (tab[i].p) {
        if (tab[i].p == p) return &tab[i];
        i = (i + 1) & (cap - 1);
    }
    return NULL;
}

static int should_fail(size_t n, const char *file, int line) {
    if (fail_at < 0) {
        const char *e = getenv("SEGV_FAIL_ALLOC");
        fail_at = e ? atol(e) : 0;
        e = getenv("SEGV_MAX_ALLOC");
        max_alloc = e ? (size_t)atoll(e) : (size_t)1 << 30;
    }
    if (n > max_alloc) {   /* refuse huge requests instead of paging the machine to death */
        fprintf(stderr, "SEGV_BIGALLOC %zu %s:%d\n", n, file, line);
        return 1;
    }
    n_allocs++;
    if (fail_at > 0 && n_allocs == fail_at) { fail_count++; return 1; }
    return 0;
}

static void track(void *p, size_t n, const char *file, int line) {
    if (!p) return;
    put(p, n, file, line);
    live_bytes += n;
    if (live_bytes > peak_bytes) peak_bytes = live_bytes;
    if (live_bytes > peak_total) peak_total = live_bytes;
}

static void untrack(void *p) {
    Block *b = find(p);
    if (b) { live_bytes -= b->size; b->p = TOMB; }
}

void *segv_malloc(size_t n, const char *file, int line) {
    if (should_fail(n, file, line)) return NULL;
    void *p = malloc(n);
    track(p, n, file, line);
    return p;
}

void *segv_calloc(size_t c, size_t n, const char *file, int line) {
    if (c && n > SIZE_MAX / c) return NULL;
    if (should_fail(c * n, file, line)) return NULL;
    void *p = calloc(c, n);
    track(p, c * n, file, line);
    return p;
}

void *segv_realloc(void *p, size_t n, const char *file, int line) {
    if (should_fail(n, file, line)) return NULL;
    void *q = realloc(p, n);
    if (!q && n) return NULL;          /* p is still valid and still tracked */
    if (p) untrack(p);
    track(q, n, file, line);
    return q;
}

void segv_free(void *p) {
    if (!p) return;
    untrack(p);
    free(p);
}

char *segv_strdup(const char *s, const char *file, int line) {
    size_t n = strlen(s) + 1;
    char *d = segv_malloc(n, file, line);
    if (d) memcpy(d, s, n);
    return d;
}

char *segv_strndup(const char *s, size_t n, const char *file, int line) {
    size_t k = 0;
    while (k < n && s[k]) k++;
    char *d = segv_malloc(k + 1, file, line);
    if (d) { memcpy(d, s, k); d[k] = 0; }
    return d;
}

FILE *segv_fopen(const char *path, const char *mode, const char *file, int line) {
    if (should_fail(0, file, line)) return NULL;
    FILE *f = fopen(path, mode);
    if (f)
        for (int i = 0; i < 256; i++)
            if (!files[i].f) { files[i] = (OpenFile){f, file, line}; break; }
    return f;
}

int segv_fclose(FILE *fp) {
    for (int i = 0; i < 256; i++)
        if (files[i].f == fp) files[i].f = NULL;
    return fclose(fp);
}

void segv_track_reset_peak(void) { peak_bytes = live_bytes; }
size_t segv_track_peak(void) { return peak_bytes; }
size_t segv_track_live(void) { return live_bytes; }

/* One line per allocation site that still has live blocks:
 *   SEGV_LEAK <blocks> <bytes> <file>:<line>
 *   SEGV_FILE_LEAK <file>:<line>                                       */
void segv_track_report(void) {
    for (size_t i = 0; i < cap; i++) {
        Block *b = &tab[i];
        if (!b->p || b->p == TOMB) continue;
        long blocks = 0; size_t bytes = 0;
        const char *file = b->file; int line = b->line;
        for (size_t j = i; j < cap; j++) {   /* aggregate this site, then clear it */
            Block *c = &tab[j];
            if (c->p && c->p != TOMB && c->line == line && strcmp(c->file, file) == 0) {
                blocks++; bytes += c->size; c->p = TOMB;
            }
        }
        fprintf(stderr, "SEGV_LEAK %ld %zu %s:%d\n", blocks, bytes, file, line);
    }
    for (int i = 0; i < 256; i++)
        if (files[i].f) fprintf(stderr, "SEGV_FILE_LEAK %s:%d\n", files[i].file, files[i].line);
    fprintf(stderr, "SEGV_ALLOCS %ld failed=%ld\n", n_allocs, fail_count);
    fprintf(stderr, "SEGV_PEAK %zu\n", peak_total);
}

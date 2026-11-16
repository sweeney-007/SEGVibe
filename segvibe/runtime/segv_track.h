/* SEGVibe allocation tracker, force-included (-include) into the build.
 *
 * Routes malloc/calloc/realloc/free/strdup/strndup/fopen/fclose through
 * counting wrappers, so the harness can report leaked blocks and open files
 * with the line that allocated them, measure peak heap use, and make the
 * k-th allocation fail (SEGV_FAIL_ALLOC=k) to test error paths.
 * Works the same on macOS (where LeakSanitizer is unavailable) and Linux.
 */
#ifndef SEGV_TRACK_H
#define SEGV_TRACK_H

#include "segv_std.h"

void *segv_malloc(size_t n, const char *file, int line);
void *segv_calloc(size_t c, size_t n, const char *file, int line);
void *segv_realloc(void *p, size_t n, const char *file, int line);
void segv_free(void *p);
char *segv_strdup(const char *s, const char *file, int line);
char *segv_strndup(const char *s, size_t n, const char *file, int line);
FILE *segv_fopen(const char *path, const char *mode, const char *file, int line);
int segv_fclose(FILE *fp);

void segv_track_reset_peak(void);
size_t segv_track_peak(void);
size_t segv_track_live(void);
void segv_track_report(void);

#undef malloc
#undef calloc
#undef realloc
#undef free
#undef strdup
#undef strndup
#define malloc(n) segv_malloc((n), __FILE__, __LINE__)
#define calloc(c, n) segv_calloc((c), (n), __FILE__, __LINE__)
#define realloc(p, n) segv_realloc((p), (n), __FILE__, __LINE__)
#define free(p) segv_free(p)
#define strdup(s) segv_strdup((s), __FILE__, __LINE__)
#define strndup(s, n) segv_strndup((s), (n), __FILE__, __LINE__)
#define fopen(p, m) segv_fopen((p), (m), __FILE__, __LINE__)
#define fclose(f) segv_fclose(f)

#endif

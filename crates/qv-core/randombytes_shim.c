/*
 * randombytes_shim.c
 *
 * Provides the `randombytes` function required by SMAUG-T and HAETAE reference
 * implementations. It provides one reviewed cross-platform OS-entropy path
 * (getrandom / arc4random / /dev/urandom) in place of the upstream platform
 * adapters. The separate SMAUG-T rng.c KAT/seed-expander implementation is
 * deliberately not linked by build.rs.
 */

#include <stddef.h>
#include <stdint.h>

#if defined(__linux__)
# include <errno.h>
# include <stdlib.h>
# include <sys/random.h>

int randombytes(uint8_t *x, size_t xlen) {
    size_t done = 0;
    while (done < xlen) {
        ssize_t n = getrandom(x + done, xlen - done, 0);
        if (n > 0) {
            done += (size_t)n;
        } else if (n == 0 || errno != EINTR) {
            /* EINTR: signal interrupted the syscall — retry.
             * Anything else (ENOSYS, EFAULT, …): abort rather than
             * spinning forever or silently returning weak randomness. */
            abort();
        }
    }
    return 0;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
# include <stdlib.h>

int randombytes(uint8_t *x, size_t xlen) {
    arc4random_buf(x, xlen);
    return 0;
}

#else
/* Fallback: read from /dev/urandom. Aborts on failure instead of silently
 * returning weak randomness. */
# include <stdio.h>
# include <stdlib.h>

int randombytes(uint8_t *x, size_t xlen) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        abort();
    }
    size_t done = 0;
    while (done < xlen) {
        size_t n = fread(x + done, 1, xlen - done, f);
        if (n == 0) {
            fclose(f);
            abort();
        }
        done += n;
    }
    fclose(f);
    return 0;
}
#endif

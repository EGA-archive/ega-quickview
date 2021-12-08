#ifndef __CRYPT4GH_DEBUG_H_INCLUDED__
#define __CRYPT4GH_DEBUG_H_INCLUDED__

/* #include <stdlib.h> */
/* #include <stddef.h> */
/* #include <unistd.h> */
#include <stdint.h>

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* for stpcpy */
#endif

#include <string.h>
#include <stdio.h>


#define E(fmt,...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#define D1(...)
#define D2(...)
#define D3(...)
#define H1(...)
#define H2(...)
#define H3(...)

#ifdef DEBUG

#undef E
#define E(fmt,...) fprintf(stderr, "%40s | " fmt "\n", __FUNCTION__, ##__VA_ARGS__)

#define DEBUG_FUNC(level, fmt, ...) fprintf(stderr, "%40s |" level " " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
/* #define DEBUG_FUNC(level, fmt, ...) fprintf(stderr, "%-10s(%3d)%22s |" level " " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__) */

/*
 * Prints byte array to its hexadecimal representation
 */
static inline void
H(const char* level, const char* leading, void* v, size_t len) {
  fprintf(stderr, EGA_PREFIX "%s%s: ", level, leading);
    size_t _i = 0;
    uint8_t* _p = (uint8_t*)v;
    for(;_i<len;_i++){ fprintf(stderr, "%02x", _p[_i] ); }
    fprintf(stderr, "\n");
}

#define LEVEL1 ""
#define LEVEL2 "    "
#define LEVEL3 "        "

#if DEBUG > 0
#undef D1
#define D1(fmt, ...) DEBUG_FUNC(LEVEL1, fmt, ##__VA_ARGS__)
#undef H1
#define H1(...) H(LEVEL1, ##__VA_ARGS__)
#endif

#if DEBUG > 1
#undef D2
#define D2(fmt, ...) DEBUG_FUNC(LEVEL2, fmt, ##__VA_ARGS__)
#undef H2
#define H2(...) H(LEVEL3, ##__VA_ARGS__)
#endif

#if DEBUG > 2
#undef D3
#define D3(fmt, ...) DEBUG_FUNC(LEVEL3, fmt, ##__VA_ARGS__)
#undef H3
#define H3(...) H(LEVEL3, ##__VA_ARGS__)
#endif


#endif /* !DEBUG */

#endif /* !__CRYPT4GH_DEBUG_H_INCLUDED__ */

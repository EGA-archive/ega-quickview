/*
 * Copyright (c) 1999-2003 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DEFINES_H
#define _DEFINES_H

/* Constants */

#ifndef STDIN_FILENO
# define STDIN_FILENO    0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO   1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO   2
#endif

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#ifndef HAVE_U_INT
typedef unsigned int u_int;
#endif

#ifndef HAVE_INTXX_T
typedef signed char int8_t;
# if (SIZEOF_SHORT_INT == 2)
typedef short int int16_t;
# else
#   error "16 bit int type not found."
# endif
# if (SIZEOF_INT == 4)
typedef int int32_t;
# else
#   error "32 bit int type not found."
# endif
#endif

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#ifndef HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# else
typedef unsigned char u_int8_t;
#  if (SIZEOF_SHORT_INT == 2)
typedef unsigned short int u_int16_t;
#  else
#    error "16 bit int type not found."
#  endif
#  if (SIZEOF_INT == 4)
typedef unsigned int u_int32_t;
#  else
#    error "32 bit int type not found."
#  endif
# endif
#define __BIT_TYPES_DEFINED__
#endif

#if !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#define LLONG_MIN LONG_LONG_MIN
#endif
#if !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#define LLONG_MAX LONG_LONG_MAX
#endif

#ifndef UINT32_MAX
# if defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  if (SIZEOF_INT == 4)
#    define UINT32_MAX	UINT_MAX
#  endif
# endif
#endif

/* 64-bit types */
#ifndef HAVE_INT64_T
# if (SIZEOF_LONG_INT == 8)
typedef long int int64_t;
# else
#  if (SIZEOF_LONG_LONG_INT == 8)
typedef long long int int64_t;
#  endif
# endif
#endif
#ifndef HAVE_U_INT64_T
# if (SIZEOF_LONG_INT == 8)
typedef unsigned long int u_int64_t;
# else
#  if (SIZEOF_LONG_LONG_INT == 8)
typedef unsigned long long int u_int64_t;
#  endif
# endif
#endif

#ifndef HAVE_UINTXX_T
typedef u_int8_t uint8_t;
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;
typedef u_int64_t uint64_t;
#endif

#ifndef HAVE_U_CHAR
typedef unsigned char u_char;
# define HAVE_U_CHAR
#endif /* HAVE_U_CHAR */

#ifndef ULLONG_MAX
# define ULLONG_MAX ((unsigned long long)-1)
#endif

#ifndef SIZE_T_MAX
#define SIZE_T_MAX ULONG_MAX
#endif /* SIZE_T_MAX */

#ifndef HAVE_SIZE_T
typedef unsigned int size_t;
# define HAVE_SIZE_T
# define SIZE_T_MAX UINT_MAX
#endif /* HAVE_SIZE_T */

#ifndef SIZE_MAX
#define SIZE_MAX SIZE_T_MAX
#endif

#ifndef INT32_MAX
# if (SIZEOF_INT == 4)
#  define INT32_MAX INT_MAX
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX LONG_MAX
# else
#  error "need INT32_MAX"
# endif
#endif

#ifndef INT64_MAX
# if (SIZEOF_INT == 8)
#  define INT64_MAX INT_MAX
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX LONG_MAX
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# else
#  error "need INT64_MAX"
# endif
#endif

#ifndef HAVE_SSIZE_T
typedef int ssize_t;
#define SSIZE_MAX INT_MAX
# define HAVE_SSIZE_T
#endif /* HAVE_SSIZE_T */

/* Macros */

#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#endif


#if !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#endif /* !defined(__GNUC__) || (__GNUC__ < 2) */

/* We don't use OpenBSD, so we don't have __sentinel__ nor __bounded__*/
# define __sentinel__
# define __bounded__(x, y, z)

#if !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#endif

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#ifndef BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef WORDS_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# else /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#endif /* BYTE_ORDER */

/* Function replacement / compatibility hacks */

#if !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#endif /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#if !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#elif !defined(HAVE___func__)
#  define __func__ ""
#endif

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#if defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4RANDOM_UNIFORM) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#endif

#ifndef __predict_true
# if defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(exp)     __builtin_expect(((exp) != 0), 1)
#  define __predict_false(exp)    __builtin_expect(((exp) != 0), 0)
# else
#  define __predict_true(exp)     ((exp) != 0)
#  define __predict_false(exp)    ((exp) != 0)
# endif /* gcc version */
#endif /* __predict_true */

#endif /* _DEFINES_H */

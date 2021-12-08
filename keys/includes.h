/* $OpenBSD: includes.h,v 1.54 2006/07/22 20:48:23 stevesk Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file includes most of the needed system headers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef INCLUDES_H
#define INCLUDES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* activate extra prototypes for glibc */
#endif

#include <sodium.h>

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#endif
#ifdef HAVE_BSTRING_H
# include <bstring.h>
#endif
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif
#ifdef HAVE_UTIME_H
# include <utime.h>
#endif
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h> /* for timespeccmp if present */
#endif

#ifdef HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#endif

#if defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#endif

#include <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#ifdef GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#endif

#ifdef WITH_OPENSSL
#include <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#endif

#include "defines.h"
#include "openbsd-compat/openbsd-compat.h"
#include "debug.h"

#endif /* INCLUDES_H */

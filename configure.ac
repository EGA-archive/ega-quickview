# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([egafs],[1.0],[frederic.haziza@crg.eu])

AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([src/config.h])

# Store the auxiliary build tools (e.g., install-sh, config.sub, config.guess) in this dir (build-aux)
#AC_CONFIG_AUX_DIR([build-aux])

AC_LANG([C])

AC_PROG_CC([cc gcc])
AC_PROG_CPP
AC_PROG_AWK
AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])

AC_C_INLINE
# AC_C_BIGENDIAN

is_apple="no"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[
#ifdef __APPLE__ or __MACH__
int ok;
#else
choke me
#endif
]])], [ is_apple="yes" ], [])


# First of all, we need libfuse3, libsodium, glib2.0 and pthreads
fuse_lib="fuse3"
fuse_func="fuse_session_mount"
fuse_link="https://github.com/libfuse/libfuse"
if test "$is_apple" = "yes"; then
   fuse_lib="fuse"
   fuse_func="fuse_mount"
   fuse_link="https://github.com/osxfuse/fuse"
   CPPFLAGS="$CPPFLAGS -D_REENTRANT -DFUSE_USE_VERSION=26"
fi

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
PKG_CHECK_MODULES([EGAQV], [$fuse_lib >= 2.3 glib-2.0 libsodium])

dnl AC_SEARCH_LIBS([$fuse_func], [$fuse_lib], [],
dnl 		[AC_MSG_ERROR("$fuse_lib is required. Install it from $fuse_link.")])

dnl AC_SEARCH_LIBS([sodium_init], [sodium], [],
dnl 	       [AC_MSG_ERROR("libsodium is required. Install it from https://libsodium.org/.")])

dnl AC_SEARCH_LIBS([pthread_mutex_lock], [pthread], [],
dnl                [AC_MSG_ERROR("pthread is required")])

dnl AC_SEARCH_LIBS([g_hash_table_new_full], [glib-2.0], [],
dnl                [AC_MSG_ERROR("glib-2.0 is required. Install it from https://developer.gnome.org/glib/stable/.")])

CFLAGS="${CFLAGS} $(${PKG_CONFIG} --cflags glib-2.0 $fuse_lib libsodium)"
LDFLAGS="$LDFLAGS $(${PKG_CONFIG} --libs glib-2.0 $fuse_lib libsodium)"

##########################################
# Checking for libcrypt4gh-keys
##########################################
with_crypt4gh_keys=no

# Checking if already installed
AC_SEARCH_LIBS([crypt4gh_private_key_from_file], [c4gh-keys], [with_crypt4gh_keys=yes], [])

if test "$with_crypt4gh_keys" != "yes"; then

   # Trying with the ./keys subdirectory
   AC_MSG_CHECKING([if libc4gh-keys is in the ./keys sub-directory])
   saved_CFLAGS="$CFLAGS"
   saved_LDFLAGS="$LDFLAGS"
   saved_LIBS="$LIBS"
   CFLAGS="$CFLAGS -I./keys/src/include"
   LDFLAGS="$LDFLAGS -L./keys"
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include "crypt4gh/key.h"
			]], [[
        const char* filename = "c4gh.sec";
        char* passphrase = "secret";
        unsigned char seckey[crypto_kx_SECRETKEYBYTES];
        unsigned char pubkey[crypto_kx_PUBLICKEYBYTES];
	crypt4gh_private_key_from_file(filename,passphrase,seckey,pubkey);
			]])],
		[ # Found it
		  with_crypt4gh_keys=yes
		  CFLAGS="$saved_CFLAGS -I./keys/src/include"
		  LDFLAGS="$saved_LDFLAGS -L./keys -L./keys/src/openssh -L./keys/src/openbsd-compat"
		  LIBS="$saved_LIBS -lopenssh -lopenbsd-compat $(${PKG_CONFIG} --libs openssl)"
		  EXTRA_DEPS="keys/openssh/libopenssh.a keys/openbsd-compat/libopenbsd-compat.a"
		  AC_MSG_RESULT([yes])
		],
		[ AC_MSG_RESULT([no]) ])
else
	CFLAGS="${CFLAGS} $(${PKG_CONFIG} --cflags libcrypt4gh-keys)"
	LDFLAGS="$LDFLAGS $(${PKG_CONFIG} --libs libcrypt4gh-keys)"

fi

# libc4gh-keys not found: we bail out
if test "$with_crypt4gh_keys" != "yes"; then
  AC_MSG_ERROR([libc4gh-keys is required but not found.

    Please install it first from the 'keys' subdirectory with:

         pushd ./keys
         autoreconf
         ./configure
         make
         popd

    See https://github.com/silverdaz/libcrypt4gh-keys for further instructions

  ])
fi

if test "$GCC" = "yes"; then
   AC_MSG_CHECKING([if $CC accepts -fno-builtin-memset])
   saved_CFLAGS="$CFLAGS"
   CFLAGS="$CFLAGS -fno-builtin-memset"
   AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <string.h> ]],
		[[ char b[10]; memset(b, 0, sizeof(b)); ]])],
	[ AC_MSG_RESULT([yes]) ],
	[ AC_MSG_RESULT([no])
	  CFLAGS="$saved_CFLAGS" ]
	)

   AC_MSG_CHECKING([gcc version])
   GCC_VER=`$CC -v 2>&1 | $AWK '/gcc version /{print $3}'`
   case $GCC_VER in
	1.*) no_attrib_nonnull=1 ;;
	2.8* | 2.9*)
	     no_attrib_nonnull=1
	     ;;
	2.*) no_attrib_nonnull=1 ;;
	*) ;;
   esac
   AC_MSG_RESULT([$GCC_VER])
fi

#######################################################
# Miscellaneous checks
#######################################################

AC_MSG_CHECKING([if compiler allows __attribute__ on return types])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#include <stdlib.h>
__attribute__((__unused__)) static void foo(void){return;}]],
    [[ exit(0); ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_DEFINE(NO_ATTRIBUTE_ON_RETURN_TYPE, 1,
	 [compiler does not accept __attribute__ on return types]) ]
)

AC_MSG_CHECKING([if compiler allows __attribute__ prototype args])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#include <stdlib.h>
typedef void foo(const char *, ...) __attribute__((format(printf, 1, 2)));]],
    [[ exit(0); ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_DEFINE(NO_ATTRIBUTE_ON_PROTOTYPE_ARGS, 1,
	 [compiler does not accept __attribute__ on prototype args]) ]
)

if test "x$no_attrib_nonnull" != "x1" ; then
	AC_DEFINE([HAVE_ATTRIBUTE__NONNULL__], [1], [Have attribute nonnull])
fi

AC_CACHE_CHECK([whether $CC implements __FUNCTION__], ac_cv_cc_implements___FUNCTION__, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]],
		[[ printf("%s", __FUNCTION__); ]])],
	[ ac_cv_cc_implements___FUNCTION__="yes" ],
	[ ac_cv_cc_implements___FUNCTION__="no"
	])
])
if test "x$ac_cv_cc_implements___FUNCTION__" = "xyes" ; then
	AC_DEFINE([HAVE___FUNCTION__], [1],
		[Define if compiler implements __FUNCTION__])
fi


# Readpassphrase from system or from the BSD-compatible. Use libbsd instead?
AC_CHECK_HEADERS([ \
	readpassphrase.h \
	pwd.h \
	grp.h \
])

#######################################################
# Type checks
#######################################################

# Check for  long long datatypes
AC_TYPE_OFF_T

#Check datatype sizes
AC_CHECK_SIZEOF([int])

# More checks for data types
AC_CACHE_CHECK([for uintXX_t types], ac_cv_have_uintxx_t, [
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
			]], [[
	uint8_t a;
	uint32_t b;
	uint64_t c;
	a = b = c = 1;
			]])],
		[ ac_cv_have_uintxx_t="yes" ], [ ac_cv_have_uintxx_t="no"
		])
	])
if test "x$ac_cv_have_uintxx_t" = "xyes" ; then
	AC_DEFINE([HAVE_UINTXX_T], [1],
		[define if you have uintxx_t data type])
fi

if (test -z "$have_uintxx_t" && \
	   test "x$ac_cv_header_stdint_h" = "xyes")
then
    AC_MSG_CHECKING([for uintXX_t types in stdint.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <stdint.h> ]],
	[[ uint8_t a; uint32_t b; uint64_t c; a = b = c = 1;]])],
		[
			AC_DEFINE([HAVE_UINTXX_T])
			AC_MSG_RESULT([yes])
		], [ AC_MSG_RESULT([no])
	])
fi

AC_CACHE_CHECK([for size_t], ac_cv_have_size_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ size_t foo; foo = 1235; ]])],
	[ ac_cv_have_size_t="yes" ], [ ac_cv_have_size_t="no"
	])
])
if test "x$ac_cv_have_size_t" = "xyes" ; then
	AC_DEFINE([HAVE_SIZE_T], [1], [define if you have size_t data type])
fi

#######################################################
# Debug options
#######################################################

debug_flag=no
AC_ARG_WITH([debug],
	[  --with-debug		Build main code with -g -DDEBUG=xxx],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"; then
			DEBUG="-DDEBUG=${withval}"
			debug_flag=yes
		fi
	]
)
AC_ARG_WITH([debug-prefix],
	[  --with-debug-prefix		Use prefix in debug statements],
	[
		if "x${debug_flag}" = "xyes" && test -n "$withval" ; then
			DEBUG="${DEBUG} -DDEBUG_PREFIX=${withval}"
		fi
	]
)

syslog_flag=no
AC_ARG_WITH([syslog],
	[  --with-syslog		Build main code with -DHAVE_SYSLOG_H],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"; then
			AC_CHECK_HEADERS([syslog.h])
			syslog_flag=yes
		fi
	]
)
AC_ARG_WITH([syslog-level],
	[  --with-syslog-level		Use the given syslog level],
	[
		if "x${syslog_flag}" = "xyes" && test -n "$withval" ; then
			CPPFLAGS="${CPPFLAGS} -DHAVE_SYSLOG_LEVEL=${withval}"
		fi
	]
)


#######################################################
# Debug options
#######################################################
AC_ARG_WITH([header-size],
	[  --with-header-size		Preset the header hint with a given size],
	[

		if test -n "$withval"; then
			CPPFLAGS="${CPPFLAGS} -DDEFAULT_HEADER_SIZE=${withval}"
		fi
	]
)

#######################################################

AC_SUBST([EXTRA_DEPS], [$EXTRA_DEPS])
AC_SUBST([DEBUG], [$DEBUG])
AC_SUBST([DEPEND], [$(cat $srcdir/src/.depend)])

AC_CONFIG_FILES([Makefile])


AC_OUTPUT

#if test "x$debug_flag" != "xno"; then
   # Print summary of options
   echo ""
   echo "            Compiler: ${CC}"
   echo "      Compiler flags: ${CFLAGS}"
   echo "  Preprocessor flags: ${CPPFLAGS}"
   echo "         Definitions: ${DEFS} $DEBUG"
   echo "        Linker flags: ${LDFLAGS}"
   echo "                LIBS: ${LIBS}"
   echo ""
#fi

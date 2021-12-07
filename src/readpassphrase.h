#pragma once

#ifdef HAVE_READPASSPHRASE

#include <readpassphrase.h>

#else

/* use the BSD function in readpassphrase.c */
#define RPP_ECHO_OFF    0x00		/* Turn off echo (default). */
#define RPP_ECHO_ON     0x01		/* Leave echo on. */
#define RPP_REQUIRE_TTY 0x02		/* Fail if there is no tty. */
#define RPP_FORCELOWER  0x04		/* Force input to lower case. */
#define RPP_FORCEUPPER  0x08		/* Force input to upper case. */
#define RPP_SEVENBIT    0x10		/* Strip the high bit from input. */
#define RPP_STDIN       0x20		/* Read from stdin, not /dev/tty */

char* readpassphrase(const char *prompt, char *buf, size_t bufsiz, int flags);

#endif

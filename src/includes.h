#pragma once

#define _GNU_SOURCE /* avoid implicit declaration of *pt* functions */

#define PACKAGE_VERSION "1.0"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fuse.h>
#include <fuse_lowlevel.h>

#ifndef FUSE_VERSION
#define FUSE_VERSION (FUSE_MAJOR_VERSION * 10 + FUSE_MINOR_VERSION)
#endif


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <glib.h>
#include <limits.h>
#include <readpassphrase.h>

#include <strings.h>
#include <libgen.h>
#include <darwin_compat.h>


#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#include <sodium.h>

#include <crypt4gh/key.h>

#ifndef _PATH_TTY
# define _PATH_TTY "/dev/tty"
#endif

/* #if !defined(__GNUC__) || (__GNUC__ < 2) */
/* # define __attribute__(x) */
/* #endif /\* !defined(__GNUC__) || (__GNUC__ < 2) *\/ */

/* #if !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__) */
/* # define __nonnull__(x) */
/* #endif */

# define __attribute__(x)
# define __nonnull__(x)

#ifndef MAP_LOCKED
#  define MAP_LOCKED 0
#endif

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#  define MAP_ANONYMOUS MAP_ANON
#endif


/* SSH protocol definitions */
#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_SYMLINK            20
#define SSH_FXP_STATUS            101
#define SSH_FXP_HANDLE            102
#define SSH_FXP_DATA              103
#define SSH_FXP_NAME              104
#define SSH_FXP_ATTRS             105
#define SSH_FXP_EXTENDED          200
#define SSH_FXP_EXTENDED_REPLY    201

#define SSH_FILEXFER_ATTR_SIZE          0x00000001
#define SSH_FILEXFER_ATTR_UIDGID        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS   0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME     0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED      0x80000000

#define SSH_FX_OK                            0
#define SSH_FX_EOF                           1
#define SSH_FX_NO_SUCH_FILE                  2
#define SSH_FX_PERMISSION_DENIED             3
#define SSH_FX_FAILURE                       4
#define SSH_FX_BAD_MESSAGE                   5
#define SSH_FX_NO_CONNECTION                 6
#define SSH_FX_CONNECTION_LOST               7
#define SSH_FX_OP_UNSUPPORTED                8

#define SSH_FXF_READ            0x00000001
#define SSH_FXF_WRITE           0x00000002
#define SSH_FXF_APPEND          0x00000004
#define SSH_FXF_CREAT           0x00000008
#define SSH_FXF_TRUNC           0x00000010
#define SSH_FXF_EXCL            0x00000020

/* statvfs@openssh.com f_flag flags */
#define SSH2_FXE_STATVFS_ST_RDONLY	0x00000001
#define SSH2_FXE_STATVFS_ST_NOSUID	0x00000002

#define SFTP_EXT_POSIX_RENAME "posix-rename@openssh.com"
#define SFTP_EXT_STATVFS "statvfs@openssh.com"
#define SFTP_EXT_HARDLINK "hardlink@openssh.com"
#define SFTP_EXT_FSYNC "fsync@openssh.com"

#define PROTO_VERSION 3

#include "crypt4gh.h"

struct ega_config {

  uid_t uid;
  gid_t gid;
  time_t mounted_at;
  int direct_io;

  int debug;
  int verbose;
  int foreground;
  char *progname;
  int show_version;
  int show_help;

  char *mountpoint;
  char *host;
  char *base_path;
  mode_t mnt_mode;

  unsigned int dir_cache;
  unsigned int file_cache;
  unsigned int c4gh_decrypt;

  struct fuse_operations *op;
  
  /* multithreaded */
  int singlethread;
  int clone_fd;
  int max_idle_threads;
};

extern struct ega_config config;

#define DEBUG_FUNC(color, kw, fmt, ...) fprintf(stderr, color "" kw "\x1b[0m " fmt "\n", ##__VA_ARGS__)
#define ERROR_FUNC(kw, fmt, ...) fprintf(stderr, "\x1b[31m" kw " Error:\x1b[0m " fmt "\n", ##__VA_ARGS__)


#include "sshfs/cache.h"
#include "sshfs/sshfs.h"
#include "c4ghfs.h"



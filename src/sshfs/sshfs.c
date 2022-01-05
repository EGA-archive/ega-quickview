/*
  SSH file system
  Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "includes.h"

/* Debug color: Cyan */
#define D1(format, ...) if(sshfs.debug > 0) DEBUG_FUNC("\x1b[36m", "[SSH]", format, ##__VA_ARGS__)
#define D2(format, ...) if(sshfs.debug > 1) DEBUG_FUNC("\x1b[36m", "[SSH]", "     " format, ##__VA_ARGS__)
#define D3(format, ...) if(sshfs.debug > 2) DEBUG_FUNC("\x1b[36m", "[SSH]", "          " format, ##__VA_ARGS__)
#define E(fmt, ...) ERROR_FUNC("[SSH]", fmt, ##__VA_ARGS__)


#define MY_EOF 1

#define MAX_REPLY_LEN (1 << 17)

/* Asynchronous readdir parameters */
#define READDIR_START 2
#define READDIR_MAX 32

/*
   Handling of multiple SFTP connections
   --------------------------------------

   An SFTP server is free to return responses to outstanding requests in arbitrary
   order. However, execution of requests may only be re-ordered and parallelized as long
   as "the results in the responses will be the same as if [the client] had sent the
   requests one at a time and waited for the response in each case".
   (https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.1).

   When using multiple connections, this requirement applies independently for each
   connection. We therefore have to make sure in SSHFS that the way in which we distribute
   requests between connections does not affect the responses that we get.

   In general, this is a tricky problem to solve since for each incoming request we have
   to determine which other in-flight requests may interact with it, and then either
   transmit the request through the same connection or (if there are multiple connections
   involved) wait for the other requests to complete. This means that e.g. a readdir
   request would have to block on most other activity in the same directory, eliminating a
   major advantage of using multiple connections.

   In practice, we can luckily take advantage of the knowledge that most FUSE requests are
   the result of (synchronous) syscalls from userspace that will block until the
   corresponding FUSE response has been sent.

   If -o sshfs_sync is used, SSHFS always waits for the SFTP server response before
   returning a FUSE response to userspace. If userspace makes concurrent system calls,
   there is no ordering guarantee in the first place, so we do not have to worry about
   (re-)ordering within SSHFS either.

   For requests that originate in the kernel (rather than userspace), the situation is
   slightly different. Transmission of FUSE requests and responses is decoupled (there are
   no synchronous calls) and there is no formal specification that defines if reordering
   is permitted. However, the Linux kernel seems to avoid submitting any concurrent
   requests that would give different results depending on execution order and (as of
   kernel 4.20 with writeback caching disabled) the only kind of kernel originated
   requests are read() requests for read-ahead. Since libfuse internally uses multiple
   threads, SSHFS does not necessarily receive requests in the order in which they were
   sent by the kernel. Unless there is a major bug in FUSE, there is therefore no need to
   worry about correct sequencing of such calls even when using multiple SFTP connections.

   If -o sshfs_sync is *not* used, then write() syscalls will return to userspace before
   SSHFS has received responses from the SFTP server. If userspace then issues a second
   syscall related to the same file (and only one connection is in-use), SFTP ordering
   guarantees will ensure that the response takes into account the preceding writes. If
   multiple connections are in use, this has to be ensured by SSHFS instead.

   The easiest way to do so would be to bind specific SFTP connections to file
   handles. Unfortunately, not all requests for the same dentry are guaranteed to come
   from the same file handle and some requests may come without any file handle. We
   therefore maintain a separate mapping from currently open files to SFTP connections. If
   a request comes in for a path contained in sshfs.conntab and its result could be
   changed by a pending write() operation, it will always be executed with the
   associated SFTP connection.

   There are additional subtleties for requests that affect multiple paths.  For example,
   if both source and destination of a rename() request are currently open, which
   connection should be used?

   This problem is again hard in general, but solvable since we only have to worry about
   the effects of pending write() calls. For rename() and link(), it does not matter if a
   pending write is executed before or after the operation. For readdir(), it is possible
   that a pending write() will change the length of the file. However, SSHFS currently
   does not return attribute information for readdir(), so this does not pose problems
   either. Should SSHFS implement a readdirplus() handler (which provides file names and
   attributes) this is a problem that will need to be solved.
*/


struct dir_handle {
	struct buffer buf;
	struct conn *conn;
};

struct request;
typedef void (*request_func)(struct request *);

struct request {
	unsigned int want_reply;
	sem_t ready;
	uint8_t reply_type;
	uint32_t id;
	int replied;
	int error;
	struct buffer reply;
	struct timeval start;
	void *data;
	request_func end_func;
	size_t len;
	struct list_head list;
	struct conn *conn;
};

struct read_req {
	struct sshfs_io *sio;
	struct list_head list;
	struct buffer data;
	size_t size;
	ssize_t res;
};


struct conntab_entry {
	unsigned refcount;
	struct conn *conn;
};

struct sshfs {
	int debug;

	char *command;
	struct fuse_args args;

	int no_check_root;

	unsigned max_read;
	unsigned ssh_ver;

	int sync_read;
	int sync_readdir;

	int reconnect;
	int delay_connect;

	GHashTable *reqtab;
	GHashTable *conntab;
	pthread_mutex_t lock;
	int max_conns;
	struct conn *conns;

	int connvers;
	int server_version;

	unsigned blksize;
	unsigned outstanding_len;
	unsigned max_outstanding_len;
	pthread_cond_t outstanding_cond;

	int ext_statvfs;

	/* statistics */
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t num_sent;
	uint64_t num_received;
	unsigned int min_rtt;
	unsigned int max_rtt;
	uint64_t total_rtt;
	unsigned int num_connect;
};

static struct sshfs sshfs;

static const char *ssh_opts[] = {
	"AddressFamily",
	"BatchMode",
	"BindAddress",
	"BindInterface",
	"CertificateFile",
	"ChallengeResponseAuthentication",
	"CheckHostIP",
	"Cipher",
	"Ciphers",
	"Compression",
	"CompressionLevel",
	"ConnectionAttempts",
	"ConnectTimeout",
	"ControlMaster",
	"ControlPath",
	"ControlPersist",
	"FingerprintHash",
	"GlobalKnownHostsFile",
	"GSSAPIAuthentication",
	"GSSAPIDelegateCredentials",
	"HostbasedAuthentication",
	"HostbasedKeyTypes",
	"HostKeyAlgorithms",
	"HostKeyAlias",
	"HostName",
	"IdentitiesOnly",
	"IdentityFile",
	"IdentityAgent",
	"IPQoS",
	"KbdInteractiveAuthentication",
	"KbdInteractiveDevices",
	"KexAlgorithms",
	"LocalCommand",
	"LogLevel",
	"MACs",
	"NoHostAuthenticationForLocalhost",
	"NumberOfPasswordPrompts",
	"PasswordAuthentication",
	"PermitLocalCommand",
	"PKCS11Provider",
	"Port",
	"PreferredAuthentications",
	"ProxyCommand",
	"ProxyJump",
	"ProxyUseFdpass",
	"PubkeyAcceptedKeyTypes",
	"PubkeyAuthentication",
	"RekeyLimit",
	"RevokedHostKeys",
	"RhostsRSAAuthentication",
	"RSAAuthentication",
	"ServerAliveCountMax",
	"ServerAliveInterval",
	"SmartcardDevice",
	"StrictHostKeyChecking",
	"TCPKeepAlive",
	"UpdateHostKeys",
	"UsePrivilegedPort",
	"UserKnownHostsFile",
	"VerifyHostKeyDNS",
	"VisualHostKey",
	NULL,
};

enum {
	KEY_PORT,
	//KEY_COMPRESS,
	KEY_CONFIGFILE,
};

static const char *type_name(uint8_t type)
{
	switch(type) {
	case SSH_FXP_INIT:           return "INIT";
	case SSH_FXP_VERSION:        return "VERSION";
	case SSH_FXP_OPEN:           return "OPEN";
	case SSH_FXP_CLOSE:          return "CLOSE";
	case SSH_FXP_READ:           return "READ";
	case SSH_FXP_WRITE:          return "WRITE";
	case SSH_FXP_LSTAT:          return "LSTAT";
	case SSH_FXP_FSTAT:          return "FSTAT";
	case SSH_FXP_SETSTAT:        return "SETSTAT";
	case SSH_FXP_FSETSTAT:       return "FSETSTAT";
	case SSH_FXP_OPENDIR:        return "OPENDIR";
	case SSH_FXP_READDIR:        return "READDIR";
	case SSH_FXP_REMOVE:         return "REMOVE";
	case SSH_FXP_MKDIR:          return "MKDIR";
	case SSH_FXP_RMDIR:          return "RMDIR";
	case SSH_FXP_REALPATH:       return "REALPATH";
	case SSH_FXP_STAT:           return "STAT";
	case SSH_FXP_RENAME:         return "RENAME";
	case SSH_FXP_READLINK:       return "READLINK";
	case SSH_FXP_SYMLINK:        return "SYMLINK";
	case SSH_FXP_STATUS:         return "STATUS";
	case SSH_FXP_HANDLE:         return "HANDLE";
	case SSH_FXP_DATA:           return "DATA";
	case SSH_FXP_NAME:           return "NAME";
	case SSH_FXP_ATTRS:          return "ATTRS";
	case SSH_FXP_EXTENDED:       return "EXTENDED";
	case SSH_FXP_EXTENDED_REPLY: return "EXTENDED_REPLY";
	default:                     return "???";
	}
}

#define list_entry(ptr, type, member) ({				\
      const typeof( ((type *)0)->member ) *__mptr = (ptr);		\
      (type *)( (char *)__mptr - offsetof(type,member) );})


#define ssh_add_arg(arg) ((fuse_opt_add_arg(&sshfs.args, arg) == -1)?1:0)

static void list_init(struct list_head *head)
{
	head->next = head;
	head->prev = head;
}

static void list_add(struct list_head *new, struct list_head *head)
{
	struct list_head *prev = head;
	struct list_head *next = head->next;
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static void list_del(struct list_head *entry)
{
	struct list_head *prev = entry->prev;
	struct list_head *next = entry->next;
	next->prev = prev;
	prev->next = next;

}

static int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void buf_init(struct buffer *buf, size_t size)
{
	if (size) {
		buf->p = (uint8_t *) malloc(size);
		if (!buf->p) {
			fprintf(stderr, "sshfs: memory allocation failed\n");
			abort();
		}
	} else
		buf->p = NULL;
	buf->len = 0;
	buf->size = size;
}

static inline void buf_free(struct buffer *buf)
{
	free(buf->p);
}

static inline void buf_finish(struct buffer *buf)
{
	buf->len = buf->size;
}

static inline void buf_clear(struct buffer *buf)
{
	buf_free(buf);
	buf_init(buf, 0);
}

static void buf_resize(struct buffer *buf, size_t len)
{
	buf->size = (buf->len + len + 63) & ~31;
	buf->p = (uint8_t *) realloc(buf->p, buf->size);
	if (!buf->p) {
		fprintf(stderr, "sshfs: memory allocation failed\n");
		abort();
	}
}

static inline void buf_check_add(struct buffer *buf, size_t len)
{
	if (buf->len + len > buf->size)
		buf_resize(buf, len);
}

#define _buf_add_mem(b, d, l)			\
	buf_check_add(b, l);			\
	memcpy(b->p + b->len, d, l);		\
	b->len += l;


static inline void buf_add_mem(struct buffer *buf, const void *data,
                               size_t len)
{
	_buf_add_mem(buf, data, len);
}

static inline void buf_add_buf(struct buffer *buf, const struct buffer *bufa)
{
	_buf_add_mem(buf, bufa->p, bufa->len);
}

static inline void buf_add_uint8(struct buffer *buf, uint8_t val)
{
	_buf_add_mem(buf, &val, 1);
}

static inline void buf_add_uint32(struct buffer *buf, uint32_t val)
{
	uint32_t nval = htonl(val);
	_buf_add_mem(buf, &nval, 4);
}

static inline void buf_add_uint64(struct buffer *buf, uint64_t val)
{
	buf_add_uint32(buf, val >> 32);
	buf_add_uint32(buf, val & 0xffffffff);
}

static inline void buf_add_data(struct buffer *buf, const struct buffer *data)
{
	buf_add_uint32(buf, data->len);
	buf_add_mem(buf, data->p, data->len);
}

static inline void buf_add_string(struct buffer *buf, const char *str)
{
	struct buffer data;
	data.p = (uint8_t *) str;
	data.len = strlen(str);
	buf_add_data(buf, &data);
}

static inline void buf_add_path(struct buffer *buf, const char *path)
{
        D3("buf_add_path: %s", path);

	char *realpath = g_strdup_printf("%s/%s",
					 (config.base_path)?config.base_path:"",   /* trailing / already trimmed */
					 (path)?((*path=='/')?(path+1):path):"."); /* trim the leading / */
	buf_add_string(buf, realpath);
	g_free(realpath);
}

static int buf_check_get(struct buffer *buf, size_t len)
{
	if (buf->len + len > buf->size) {
		fprintf(stderr, "buffer too short\n");
		return -1;
	} else
		return 0;
}

static inline int buf_get_mem(struct buffer *buf, void *data, size_t len)
{
	if (buf_check_get(buf, len) == -1)
		return -1;
	memcpy(data, buf->p + buf->len, len);
	buf->len += len;
	return 0;
}

static inline int buf_get_uint8(struct buffer *buf, uint8_t *val)
{
	return buf_get_mem(buf, val, 1);
}

static inline int buf_get_uint32(struct buffer *buf, uint32_t *val)
{
	uint32_t nval;
	if (buf_get_mem(buf, &nval, 4) == -1)
		return -1;
	*val = ntohl(nval);
	return 0;
}

static inline int buf_get_uint64(struct buffer *buf, uint64_t *val)
{
	uint32_t val1;
	uint32_t val2;
	if (buf_get_uint32(buf, &val1) == -1 ||
	    buf_get_uint32(buf, &val2) == -1) {
		return -1;
	}
	*val = ((uint64_t) val1 << 32) + val2;
	return 0;
}

static inline int buf_get_data(struct buffer *buf, struct buffer *data)
{
	uint32_t len;
	if (buf_get_uint32(buf, &len) == -1 || len > buf->size - buf->len)
		return -1;
	buf_init(data, len + 1);
	data->size = len;
	if (buf_get_mem(buf, data->p, data->size) == -1) {
		buf_free(data);
		return -1;
	}
	return 0;
}

static inline int buf_get_string(struct buffer *buf, char **str)
{
	struct buffer data;
	if (buf_get_data(buf, &data) == -1)
		return -1;
	data.p[data.size] = '\0';
	*str = (char *) data.p;
	return 0;
}

static int buf_get_attrs(struct buffer *buf, struct stat *stbuf, int *flagsp)
{
	uint32_t flags;
	uint64_t size = 0;
	uint32_t uid = 0;
	uint32_t gid = 0;
	uint32_t atime = 0;
	uint32_t mtime = 0;
	uint32_t mode = S_IFREG | 0777;
	ino_t ino = 0;

	if (buf_get_uint32(buf, &flags) == -1)
		return -EIO;
	if (flagsp)
		*flagsp = flags;
	if ((flags & SSH_FILEXFER_ATTR_SIZE) &&
	    buf_get_uint64(buf, &size) == -1)
		return -EIO;
	if ((flags & SSH_FILEXFER_ATTR_UIDGID) &&
	    (buf_get_uint32(buf, &uid) == -1 ||
	     buf_get_uint32(buf, &gid) == -1))
		return -EIO;
	if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) &&
	    buf_get_uint32(buf, &mode) == -1)
		return -EIO;
	if ((flags & SSH_FILEXFER_ATTR_ACMODTIME)) {
		if (buf_get_uint32(buf, &atime) == -1 ||
		    buf_get_uint32(buf, &mtime) == -1)
			return -EIO;
	}
	if ((flags & SSH_FILEXFER_ATTR_EXTENDED)) {
		uint32_t extcount;
		unsigned i;
		if (buf_get_uint32(buf, &extcount) == -1)
			return -EIO;
		for (i = 0; i < extcount; i++) {
			struct buffer tmp;
			if (buf_get_data(buf, &tmp) == -1)
				return -EIO;
			buf_free(&tmp);
			if (buf_get_data(buf, &tmp) == -1)
			  return -EIO;
			buf_free(&tmp);
		}
	}

	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_ino = ino;
	stbuf->st_mode = mode;
	stbuf->st_nlink = 1;
	stbuf->st_size = size;
	if (sshfs.blksize) {
		stbuf->st_blksize = sshfs.blksize;
		stbuf->st_blocks = ((size + sshfs.blksize - 1) &
			~((unsigned long long) sshfs.blksize - 1)) >> 9;
	}
	stbuf->st_uid = uid;
	stbuf->st_gid = gid;
	stbuf->st_atime = atime;
	stbuf->st_ctime = stbuf->st_mtime = mtime;
	return 0;
}

static int buf_get_statvfs(struct buffer *buf, struct statvfs *stbuf)
{
	uint64_t bsize;
	uint64_t frsize;
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint64_t files;
	uint64_t ffree;
	uint64_t favail;
	uint64_t fsid;
	uint64_t flag;
	uint64_t namemax;

	if (buf_get_uint64(buf, &bsize) == -1 ||
	    buf_get_uint64(buf, &frsize) == -1 ||
	    buf_get_uint64(buf, &blocks) == -1 ||
	    buf_get_uint64(buf, &bfree) == -1 ||
	    buf_get_uint64(buf, &bavail) == -1 ||
	    buf_get_uint64(buf, &files) == -1 ||
	    buf_get_uint64(buf, &ffree) == -1 ||
	    buf_get_uint64(buf, &favail) == -1 ||
	    buf_get_uint64(buf, &fsid) == -1 ||
	    buf_get_uint64(buf, &flag) == -1 ||
	    buf_get_uint64(buf, &namemax) == -1) {
		return -1;
	}

	memset(stbuf, 0, sizeof(struct statvfs));
	stbuf->f_bsize = bsize;
	stbuf->f_frsize = frsize;
	stbuf->f_blocks = blocks;
	stbuf->f_bfree = bfree;
	stbuf->f_bavail = bavail;
	stbuf->f_files = files;
	stbuf->f_ffree = ffree;
	stbuf->f_favail = favail;
	stbuf->f_namemax = namemax;

	return 0;
}

static int buf_get_entries(struct buffer *buf, void *dbuf,
                           fuse_fill_dir_t filler)
{
	uint32_t count;
	unsigned i;

	if (buf_get_uint32(buf, &count) == -1)
		return -EIO;

	for (i = 0; i < count; i++) {
		int err = -1;
		char *name;
		char *longname;
		struct stat stbuf;
		if (buf_get_string(buf, &name) == -1)
			return -EIO;
		if (buf_get_string(buf, &longname) != -1) {
			free(longname);
			err = buf_get_attrs(buf, &stbuf, NULL);
			if (!err) {
#ifdef __APPLE__
				filler(dbuf, name, &stbuf, 0);
#else
				filler(dbuf, name, &stbuf, 0, 0);
#endif
			}
		}
		free(name);
		if (err)
			return err;
	}
	return 0;
}


static struct conn* get_conn(const struct sshfs_file *sf,
			     const char *path)
{
	struct conntab_entry *ce;
	int i;

	if (sshfs.max_conns == 1)
		return &sshfs.conns[0];

	if (sf != NULL)
		return sf->conn;

	if (path != NULL) {
		pthread_mutex_lock(&sshfs.lock);
		ce = g_hash_table_lookup(sshfs.conntab, path);

		if (ce != NULL) {
			struct conn *conn = ce->conn;
			pthread_mutex_unlock(&sshfs.lock);
			return conn;
		}
		pthread_mutex_unlock(&sshfs.lock);
	}

	int best_index = 0;
	uint64_t best_score = ~0ULL; /* smaller is better */
	for (i = 0; i < sshfs.max_conns; i++) {
		uint64_t score = ((uint64_t) sshfs.conns[i].req_count << 43) +
				 ((uint64_t) sshfs.conns[i].dir_count << 22) +
				 ((uint64_t) sshfs.conns[i].file_count << 1) +
				 (uint64_t) (sshfs.conns[i].rfd >= 0 ? 0 : 1);
		if (score < best_score) {
			best_index = i;
			best_score = score;
		}
	}
	return &sshfs.conns[best_index];
}

static int pty_master(char **name)
{
	int mfd;

	mfd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	if (mfd == -1) {
		perror("failed to open pty");
		return -1;
	}
	if (grantpt(mfd) != 0) {
		perror("grantpt");
		return -1;
	}
	if (unlockpt(mfd) != 0) {
		perror("unlockpt");
		return -1;
	}
	*name = ptsname(mfd);

	return mfd;
}

static void replace_arg(char **argp, const char *newarg)
{
	free(*argp);
	*argp = strdup(newarg);
	if (*argp == NULL) {
		fprintf(stderr, "sshfs: memory allocation failed\n");
		abort();
	}
}

static int start_ssh(struct conn *conn)
{
	int sockpair[2];
	int pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair) == -1) {
		perror("failed to create socket pair");
		return -1;
	}
	conn->rfd = sockpair[0];
	conn->wfd = sockpair[0];

	pid = fork();
	if (pid == -1) {
		perror("failed to fork");
		close(sockpair[1]);
		return -1;
	} else if (pid == 0) {
		int devnull;

		devnull = open("/dev/null", O_WRONLY);

		if (dup2(sockpair[1], 0) == -1 || dup2(sockpair[1], 1) == -1) {
			perror("failed to redirect input/output");
			_exit(1);
		}
		if (!config.foreground && devnull != -1)
			dup2(devnull, 2);

		close(devnull);
		close(sockpair[0]);
		close(sockpair[1]);

		switch (fork()) {
		case -1:
			perror("failed to fork");
			_exit(1);
		case 0:
			break;
		default:
			_exit(0);
		}
		chdir("/");
		/*
		 * Avoid processes hanging trying to stat() OLDPWD if it is in
		 * the mount point. This can be removed if sshfs opens the
		 * mount point after establishing the ssh connection.
		 */
		unsetenv("OLDPWD");

		if (sshfs.debug) {
			int i;

			fprintf(stderr, "executing");
			for (i = 0; i < sshfs.args.argc; i++)
				fprintf(stderr, " <%s>",
					sshfs.args.argv[i]);
			fprintf(stderr, "\n");
		}

		execvp(sshfs.args.argv[0], sshfs.args.argv);
		fprintf(stderr, "failed to execute '%s': %s\n",
			sshfs.args.argv[0], strerror(errno));
		_exit(1);
	}
	waitpid(pid, NULL, 0);
	close(sockpair[1]);
	return 0;
}

static int connect_to(struct conn *conn, char *host, char *port)
{
	int err;
	int sock;
	int opt;
	struct addrinfo *ai;
	struct addrinfo hint;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = PF_INET;
	hint.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, port, &hint, &ai);
	if (err) {
		fprintf(stderr, "failed to resolve %s:%s: %s\n", host, port,
			gai_strerror(err));
		return -1;
	}
	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == -1) {
		perror("failed to create socket");
		freeaddrinfo(ai);
		return -1;
	}
	err = connect(sock, ai->ai_addr, ai->ai_addrlen);
	if (err == -1) {
		perror("failed to connect");
		freeaddrinfo(ai);
		close(sock);
		return -1;
	}
	opt = 1;
	err = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	if (err == -1)
		perror("warning: failed to set TCP_NODELAY");

	freeaddrinfo(ai);

	conn->rfd = sock;
	conn->wfd = sock;
	return 0;
}

static int do_write(struct conn *conn, struct iovec *iov, size_t count)
{
	int res;
	while (count) {
		res = writev(conn->wfd, iov, count);
		if (res == -1) {
			perror("write");
			return -1;
		} else if (res == 0) {
			fprintf(stderr, "zero write\n");
			return -1;
		}
		do {
			if ((unsigned) res < iov->iov_len) {
				iov->iov_len -= res;
				iov->iov_base += res;
				break;
			} else {
				res -= iov->iov_len;
				count --;
				iov ++;
			}
		} while(count);
	}
	return 0;
}

static uint32_t sftp_get_id(void)
{
	static uint32_t idctr;
	return idctr++;
}

static void buf_to_iov(const struct buffer *buf, struct iovec *iov)
{
	iov->iov_base = buf->p;
	iov->iov_len = buf->len;
}

static size_t iov_length(const struct iovec *iov, unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

#define SFTP_MAX_IOV 3

static int sftp_send_iov(struct conn *conn, uint8_t type, uint32_t id,
                         struct iovec iov[], size_t count)
{
	int res;
	struct buffer buf;
	struct iovec iovout[SFTP_MAX_IOV];
	unsigned i;
	unsigned nout = 0;

	assert(count <= SFTP_MAX_IOV - 1);
	buf_init(&buf, 9);
	buf_add_uint32(&buf, iov_length(iov, count) + 5);
	buf_add_uint8(&buf, type);
	buf_add_uint32(&buf, id);
	buf_to_iov(&buf, &iovout[nout++]);
	for (i = 0; i < count; i++)
		iovout[nout++] = iov[i];
	pthread_mutex_lock(&conn->lock_write);
	res = do_write(conn, iovout, nout);
	pthread_mutex_unlock(&conn->lock_write);
	buf_free(&buf);
	return res;
}

static int do_read(struct conn *conn, struct buffer *buf)
{
	int res;
	uint8_t *p = buf->p;
	size_t size = buf->size;
	while (size) {
		res = read(conn->rfd, p, size);
		if (res == -1) {
			perror("read");
			return -1;
		} else if (res == 0) {
			fprintf(stderr, "remote host has disconnected\n");
			return -1;
		}
		size -= res;
		p += res;
	}
	return 0;
}

static int sftp_read(struct conn *conn, uint8_t *type, struct buffer *buf)
{
	int res;
	struct buffer buf2;
	uint32_t len;
	buf_init(&buf2, 5);
	res = do_read(conn, &buf2);
	if (res != -1) {
		if (buf_get_uint32(&buf2, &len) == -1)
			return -1;
		if (len > MAX_REPLY_LEN) {
			fprintf(stderr, "reply len too large: %u\n", len);
			return -1;
		}
		if (buf_get_uint8(&buf2, type) == -1)
			return -1;
		buf_init(buf, len - 1);
		res = do_read(conn, buf);
	}
	buf_free(&buf2);
	return res;
}

static void request_free(struct request *req)
{
	if (req->end_func)
		req->end_func(req);

	req->conn->req_count--;

	buf_free(&req->reply);
	sem_destroy(&req->ready);
	g_free(req);
}

static void chunk_free(struct read_chunk *chunk)
{
	while (!list_empty(&chunk->reqs)) {
		struct read_req *rreq;

		rreq = list_entry(chunk->reqs.prev, struct read_req, list);
		list_del(&rreq->list);
		buf_free(&rreq->data);
		g_free(rreq);
	}
	g_free(chunk);
}

static void chunk_put(struct read_chunk *chunk)
{
	if (chunk) {
		chunk->refs--;
		if (!chunk->refs)
			chunk_free(chunk);
	}
}

static void chunk_put_locked(struct read_chunk *chunk)
{
	pthread_mutex_lock(&sshfs.lock);
	chunk_put(chunk);
	pthread_mutex_unlock(&sshfs.lock);
}

static int clean_req(void *key, struct request *req, gpointer user_data)
{
	(void) key;
	struct conn* conn = (struct conn*) user_data;

	if (req->conn != conn)
		return FALSE;

	req->error = -EIO;
	if (req->want_reply)
		sem_post(&req->ready);
	else
		request_free(req);

	return TRUE;
}

static int process_one_request(struct conn *conn)
{
	int res;
	struct buffer buf;
	uint8_t type;
	struct request *req;
	uint32_t id;

	buf_init(&buf, 0);
	res = sftp_read(conn, &type, &buf);
	if (res == -1)
		return -1;
	if (buf_get_uint32(&buf, &id) == -1)
		return -1;

	pthread_mutex_lock(&sshfs.lock);
	req = (struct request *)
		g_hash_table_lookup(sshfs.reqtab, GUINT_TO_POINTER(id));
	if (req == NULL)
		fprintf(stderr, "request %i not found\n", id);
	else {
		int was_over;

		was_over = sshfs.outstanding_len > sshfs.max_outstanding_len;
		sshfs.outstanding_len -= req->len;
		if (was_over &&
		    sshfs.outstanding_len <= sshfs.max_outstanding_len) {
			pthread_cond_broadcast(&sshfs.outstanding_cond);
		}
		g_hash_table_remove(sshfs.reqtab, GUINT_TO_POINTER(id));
	}
	pthread_mutex_unlock(&sshfs.lock);
	if (req != NULL) {
		if (sshfs.debug) {
			struct timeval now;
			unsigned int difftime;
			unsigned msgsize = buf.size + 5;

			gettimeofday(&now, NULL);
			difftime = (now.tv_sec - req->start.tv_sec) * 1000;
			difftime += (now.tv_usec - req->start.tv_usec) / 1000;
			D3("[%05i] %14s %8ubytes (%ims)", id,
			      type_name(type), msgsize, difftime);

			if (difftime < sshfs.min_rtt || !sshfs.num_received)
				sshfs.min_rtt = difftime;
			if (difftime > sshfs.max_rtt)
				sshfs.max_rtt = difftime;
			sshfs.total_rtt += difftime;
			sshfs.num_received++;
			sshfs.bytes_received += msgsize;
		}
		req->reply = buf;
		req->reply_type = type;
		req->replied = 1;
		if (req->want_reply)
			sem_post(&req->ready);
		else {
			pthread_mutex_lock(&sshfs.lock);
			request_free(req);
			pthread_mutex_unlock(&sshfs.lock);
		}
	} else
		buf_free(&buf);

	return 0;
}

static void close_conn(struct conn *conn)
{
	close(conn->rfd);
	if (conn->rfd != conn->wfd)
		close(conn->wfd);
	conn->rfd = -1;
	conn->wfd = -1;
}

static void *process_requests(void *data_)
{
	struct conn *conn = data_;

	while (1) {
		if (process_one_request(conn) == -1)
			break;
	}

	pthread_mutex_lock(&sshfs.lock);
	conn->processing_thread_started = 0;
	close_conn(conn);
	g_hash_table_foreach_remove(sshfs.reqtab, (GHRFunc) clean_req, conn);
	conn->connver = ++sshfs.connvers;
	sshfs.outstanding_len = 0;
	pthread_cond_broadcast(&sshfs.outstanding_cond);
	pthread_mutex_unlock(&sshfs.lock);

	if (!sshfs.reconnect) {
		/* harakiri */
		kill(getpid(), SIGTERM);
	}
	return NULL;
}

static int sftp_init_reply_ok(struct conn *conn, struct buffer *buf,
                              uint32_t *version)
{
	uint32_t len;
	uint8_t type;

	if (buf_get_uint32(buf, &len) == -1)
		return -1;

	if (len < 5 || len > MAX_REPLY_LEN)
		return 1;

	if (buf_get_uint8(buf, &type) == -1)
		return -1;

	if (type != SSH_FXP_VERSION)
		return 1;

	if (buf_get_uint32(buf, version) == -1)
		return -1;

	D1("Server version: %u", *version);

	if (len > 5) {
		struct buffer buf2;

		buf_init(&buf2, len - 5);
		if (do_read(conn, &buf2) == -1) {
			buf_free(&buf2);
			return -1;
		}

		do {
			char *ext = NULL;
			char *extdata = NULL;

			if (buf_get_string(&buf2, &ext) == -1 ||
			    buf_get_string(&buf2, &extdata) == -1) {
				buf_free(&buf2);
				free(ext);
				free(extdata);
				return -1;
			}

			D1("Extension: %s <%s>", ext, extdata);

			if (strcmp(ext, SFTP_EXT_STATVFS) == 0 &&
			    strcmp(extdata, "2") == 0)
				sshfs.ext_statvfs = 1;

			free(ext);
			free(extdata);
		} while (buf2.len < buf2.size);
		buf_free(&buf2);
	}
	return 0;
}

static int sftp_find_init_reply(struct conn *conn, uint32_t *version)
{
	int res;
	struct buffer buf;

	buf_init(&buf, 9);
	res = do_read(conn, &buf);
	while (res != -1) {
		struct buffer buf2;

		res = sftp_init_reply_ok(conn, &buf, version);
		if (res <= 0)
			break;

		/* Iterate over any rubbish until the version reply is found */
		//D3("%c", *buf.p);
		memmove(buf.p, buf.p + 1, buf.size - 1);
		buf.len = 0;
		buf2.p = buf.p + buf.size - 1;
		buf2.size = 1;
		res = do_read(conn, &buf2);
	}
	buf_free(&buf);
	return res;
}

static int sftp_init(struct conn *conn)
{
	int res = -1;
	uint32_t version = 0;
	struct buffer buf;
	buf_init(&buf, 0);
	if (sftp_send_iov(conn, SSH_FXP_INIT, PROTO_VERSION, NULL, 0) == -1)
		goto out;

	if (sftp_find_init_reply(conn, &version) == -1)
		goto out;

	sshfs.server_version = version;
	if (version > PROTO_VERSION) {
		fprintf(stderr,
			"Warning: server uses version: %i, we support: %i\n",
			version, PROTO_VERSION);
	}
	res = 0;

out:
	buf_free(&buf);
	return res;
}

static int sftp_error_to_errno(uint32_t error)
{
	switch (error) {
	case SSH_FX_OK:                return 0;
	case SSH_FX_NO_SUCH_FILE:      return ENOENT;
	case SSH_FX_PERMISSION_DENIED: return EACCES;
	case SSH_FX_FAILURE:           return EPERM;
	case SSH_FX_BAD_MESSAGE:       return EBADMSG;
	case SSH_FX_NO_CONNECTION:     return ENOTCONN;
	case SSH_FX_CONNECTION_LOST:   return ECONNABORTED;
	case SSH_FX_OP_UNSUPPORTED:    return EOPNOTSUPP;
	default:                       return EIO;
	}
}


static int sftp_check_root(struct conn *conn, const char *base_path)
{
	int flags;
	uint32_t id = sftp_get_id();
	uint32_t replid;
	uint8_t type;
	struct buffer buf;
	struct stat stbuf;
	struct iovec iov[1];
	int err = -1;
	const char *remote_dir = base_path[0] ? base_path : ".";

	buf_init(&buf, 0);
	buf_add_string(&buf, remote_dir);
	buf_to_iov(&buf, &iov[0]);
	if (sftp_send_iov(conn, SSH_FXP_LSTAT, id, iov, 1) == -1)
		goto out;
	buf_clear(&buf);
	if (sftp_read(conn, &type, &buf) == -1)
		goto out;
	if (type != SSH_FXP_ATTRS && type != SSH_FXP_STATUS) {
		fprintf(stderr, "protocol error\n");
		goto out;
	}
	if (buf_get_uint32(&buf, &replid) == -1)
		goto out;
	if (replid != id) {
		fprintf(stderr, "bad reply ID\n");
		goto out;
	}
	if (type == SSH_FXP_STATUS) {
		uint32_t serr;
		if (buf_get_uint32(&buf, &serr) == -1)
			goto out;

		fprintf(stderr, "%s:%s: %s\n", config.host, remote_dir,
			strerror(sftp_error_to_errno(serr)));

		goto out;
	}

	int err2 = buf_get_attrs(&buf, &stbuf, &flags);
	if (err2) {
		err = err2;
		goto out;
	}

	if (!(flags & SSH_FILEXFER_ATTR_PERMISSIONS))
		goto out;

	if (!S_ISDIR(stbuf.st_mode)) {
		fprintf(stderr, "%s:%s: Not a directory\n", config.host,
			remote_dir);
		goto out;
	}

	err = 0;

out:
	buf_free(&buf);
	return err;
}

static int connect_remote(struct conn *conn)
{
	int err;

	err = start_ssh(conn);
	if (!err)
		err = sftp_init(conn);

	if (err)
		close_conn(conn);
	else
		sshfs.num_connect++;

	return err;
}

static int start_processing_thread(struct conn *conn)
{
	int err;
	pthread_t thread_id;
	sigset_t oldset;
	sigset_t newset;

	if (conn->processing_thread_started)
		return 0;

	if (conn->rfd == -1) {
		err = connect_remote(conn);
		if (err)
			return -EIO;
	}

	sigemptyset(&newset);
	sigaddset(&newset, SIGTERM);
	sigaddset(&newset, SIGINT);
	sigaddset(&newset, SIGHUP);
	sigaddset(&newset, SIGQUIT);
	pthread_sigmask(SIG_BLOCK, &newset, &oldset);
	err = pthread_create(&thread_id, NULL, process_requests, conn);
	if (err) {
		fprintf(stderr, "failed to create thread: %s\n", strerror(err));
		return -EIO;
	}
	pthread_detach(thread_id);
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	conn->processing_thread_started = 1;
	return 0;
}

static int sftp_request_wait(struct request *req, uint8_t type,
                             uint8_t expect_type, struct buffer *outbuf)
{
	int err;

	if (req->error) {
		err = req->error;
		goto out;
	}
	while (sem_wait(&req->ready));
	if (req->error) {
		err = req->error;
		goto out;
	}
	err = -EIO;
	if (req->reply_type != expect_type &&
	    req->reply_type != SSH_FXP_STATUS) {
		fprintf(stderr, "protocol error\n");
		goto out;
	}
	if (req->reply_type == SSH_FXP_STATUS) {
		uint32_t serr;
		if (buf_get_uint32(&req->reply, &serr) == -1)
			goto out;

		switch (serr) {
		case SSH_FX_OK:
			if (expect_type == SSH_FXP_STATUS)
				err = 0;
			else
				err = -EIO;
			break;

		case SSH_FX_EOF:
			if (type == SSH_FXP_READ || type == SSH_FXP_READDIR)
				err = MY_EOF;
			else
				err = -EIO;
			break;

		case SSH_FX_FAILURE:
			if (type == SSH_FXP_RMDIR)
				err = -ENOTEMPTY;
			else
				err = -EPERM;
			break;

		default:
			err = -sftp_error_to_errno(serr);
		}
	} else {
		buf_init(outbuf, req->reply.size - req->reply.len);
		buf_get_mem(&req->reply, outbuf->p, outbuf->size);
		err = 0;
	}

out:
	pthread_mutex_lock(&sshfs.lock);
	request_free(req);
	pthread_mutex_unlock(&sshfs.lock);
	return err;
}

static int sftp_request_send(struct conn *conn, uint8_t type, struct iovec *iov,
			     size_t count, request_func begin_func, request_func end_func,
			     int want_reply, void *data, struct request **reqp)
{
	int err;
	uint32_t id;
	struct request *req = g_new0(struct request, 1);

	req->want_reply = want_reply;
	req->end_func = end_func;
	req->data = data;
	sem_init(&req->ready, 0, 0);
	buf_init(&req->reply, 0);
	pthread_mutex_lock(&sshfs.lock);
	if (begin_func)
		begin_func(req);
	id = sftp_get_id();
	req->id = id;
	req->conn = conn;
	req->conn->req_count++;
	err = start_processing_thread(conn);
	if (err) {
		pthread_mutex_unlock(&sshfs.lock);
		goto out;
	}
	req->len = iov_length(iov, count) + 9;
	sshfs.outstanding_len += req->len;
	while (sshfs.outstanding_len > sshfs.max_outstanding_len)
		pthread_cond_wait(&sshfs.outstanding_cond, &sshfs.lock);

	g_hash_table_insert(sshfs.reqtab, GUINT_TO_POINTER(id), req);
	if (sshfs.debug) {
		gettimeofday(&req->start, NULL);
		sshfs.num_sent++;
		sshfs.bytes_sent += req->len;
	}
	D2("[%05i] %s", id, type_name(type));
	pthread_mutex_unlock(&sshfs.lock);

	err = -EIO;
	if (sftp_send_iov(conn, type, id, iov, count) == -1) {
		gboolean rmed;

		pthread_mutex_lock(&sshfs.lock);
		rmed = g_hash_table_remove(sshfs.reqtab, GUINT_TO_POINTER(id));
		pthread_mutex_unlock(&sshfs.lock);

		if (!rmed && !want_reply) {
			/* request already freed */
			return err;
		}
		goto out;
	}
	if (want_reply)
		*reqp = req;
	return 0;

out:
	req->error = err;
	if (!want_reply)
		sftp_request_wait(req, type, 0, NULL);
	else
		*reqp = req;

	return err;
}

static int sftp_request_iov(struct conn *conn, uint8_t type, struct iovec *iov,
			    size_t count, uint8_t expect_type, struct buffer *outbuf)
{
	int err;
	struct request *req;

	err = sftp_request_send(conn, type, iov, count, NULL, NULL,
				expect_type, NULL, &req);
	if (expect_type == 0)
		return err;

	return sftp_request_wait(req, type, expect_type, outbuf);
}

static int sftp_request(struct conn *conn, uint8_t type, const struct buffer *buf,
			uint8_t expect_type, struct buffer *outbuf)
{
	struct iovec iov;

	buf_to_iov(buf, &iov);
	return sftp_request_iov(conn, type, &iov, 1, expect_type, outbuf);
}

static int sftp_readdir_send(struct conn *conn, struct request **req,
			     struct buffer *handle)
{
	struct iovec iov;

	buf_to_iov(handle, &iov);
	return sftp_request_send(conn, SSH_FXP_READDIR, &iov, 1, NULL, NULL,
				 SSH_FXP_NAME, NULL, req);
}

static int sshfs_req_pending(struct request *req)
{
	if (g_hash_table_lookup(sshfs.reqtab, GUINT_TO_POINTER(req->id)))
		return 1;
	else
		return 0;
}

static int sftp_readdir_async(struct conn *conn, struct buffer *handle,
			      void *buf, off_t offset, fuse_fill_dir_t filler)
{
    D3("READDIR async");
	int err = 0;
	int outstanding = 0;
	int max = READDIR_START;
	GList *list = NULL;

	int done = 0;

	//assert(offset == 0);
	while (!done || outstanding) {
		struct request *req;
		struct buffer name;
		int tmperr;

		while (!done && outstanding < max) {
			tmperr = sftp_readdir_send(conn, &req, handle);

			if (tmperr && !done) {
				err = tmperr;
				done = 1;
				break;
			}

			list = g_list_append(list, req);
			outstanding++;
		}

		if (outstanding) {
			GList *first;
			/* wait for response to next request */
			first = g_list_first(list);
			req = first->data;
			list = g_list_delete_link(list, first);
			outstanding--;

			if (done) {
				/* We need to cache want_reply, since processing
				   thread may free req right after unlock() if
				   want_reply == 0 */
				int want_reply;
				pthread_mutex_lock(&sshfs.lock);
				if (sshfs_req_pending(req))
					req->want_reply = 0;
				want_reply = req->want_reply;
				pthread_mutex_unlock(&sshfs.lock);
				if (!want_reply)
					continue;
			}

			tmperr = sftp_request_wait(req, SSH_FXP_READDIR,
						    SSH_FXP_NAME, &name);

			if (tmperr && !done) {
				err = tmperr;
				if (err == MY_EOF)
					err = 0;
				done = 1;
			}
			if (!done) {
				err = buf_get_entries(&name, buf, filler);
				buf_free(&name);

				/* increase number of outstanding requests */
				if (max < READDIR_MAX)
					max++;

				if (err)
					done = 1;
			}
		}
	}
	assert(list == NULL);

	return err;
}

static int sftp_readdir_sync(struct conn *conn, struct buffer *handle,
			     void *buf, off_t offset, fuse_fill_dir_t filler)
{
    D3("READDIR sync");
	int err;
	//assert(offset == 0);
	do {
		struct buffer name;
		err = sftp_request(conn, SSH_FXP_READDIR, handle, SSH_FXP_NAME, &name);
		if (!err) {
			err = buf_get_entries(&name, buf, filler);
			buf_free(&name);
		}
	} while (!err);
	if (err == MY_EOF)
		err = 0;

	return err;
}

static int sshfs_opendir(const char *path, struct fuse_file_info *fi)
{
        D1("OPENDIR %s", path);
	int err;
	struct conn *conn;
	struct buffer buf;
	struct dir_handle *handle;

	handle = g_new0(struct dir_handle, 1);
	if(handle == NULL)
		return -ENOMEM;

	// Commutes with pending write(), so we can use any connection
	conn = get_conn(NULL, NULL);
	buf_init(&buf, 0);
	buf_add_path(&buf, path);
	err = sftp_request(conn, SSH_FXP_OPENDIR, &buf, SSH_FXP_HANDLE, &handle->buf);
	if (!err) {
		buf_finish(&handle->buf);
		pthread_mutex_lock(&sshfs.lock);
		handle->conn = conn;
		handle->conn->dir_count++;
		pthread_mutex_unlock(&sshfs.lock);
		fi->fh = (unsigned long) handle;
	} else
		g_free(handle);
	buf_free(&buf);
	return err;
}

#ifdef __APPLE__
static int sshfs_readdir(const char *path, void *dbuf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
#else
static int sshfs_readdir(const char *path, void *dbuf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
#endif
{
        D1("READDIR %s | offset " OFF_FMT, path, offset);
	(void) path;
	int err;
	struct dir_handle *handle;

	handle = (struct dir_handle*) fi->fh;

	if (sshfs.sync_readdir)
		err = sftp_readdir_sync(handle->conn, &handle->buf, dbuf, offset, filler);
	else
		err = sftp_readdir_async(handle->conn, &handle->buf, dbuf, offset, filler);

	return err;
}

static int sshfs_releasedir(const char *path, struct fuse_file_info *fi)
{
        D1("RELEASEDIR %s", path);
	(void) path;
	int err;
	struct dir_handle *handle;

	handle = (struct dir_handle*) fi->fh;
	err = sftp_request(handle->conn, SSH_FXP_CLOSE, &handle->buf, 0, NULL);
	pthread_mutex_lock(&sshfs.lock);
	handle->conn->dir_count--;
	pthread_mutex_unlock(&sshfs.lock);
	buf_free(&handle->buf);
	g_free(handle);
	return err;
}


static inline int sshfs_file_is_conn(struct sshfs_file *sf)
{
	int ret;

	pthread_mutex_lock(&sshfs.lock);
	ret = (sf->connver == sf->conn->connver);
	pthread_mutex_unlock(&sshfs.lock);

	return ret;
}

static inline struct sshfs_file *get_sshfs_file(struct fuse_file_info *fi)
{
	return (struct sshfs_file *) (uintptr_t) fi->fh;
}

static int sshfs_open(const char *path, struct fuse_file_info *fi)
{
        D1("OPEN %s", path);
	int err;
	int err2;
	struct buffer buf;
	struct buffer outbuf;
	struct stat stbuf;
	struct sshfs_file *sf;
	struct request *open_req;
	struct conntab_entry *ce;
	uint32_t pflags = 0;
	struct iovec iov;
	uint8_t type;

	if (fi->flags & O_CREAT ||
	    fi->flags & O_EXCL  ||
	    fi->flags & O_TRUNC ||
	    fi->flags & O_APPEND ||
	    (fi->flags & O_ACCMODE) != O_RDONLY
	    )
	  return -EPERM;

	if (config.direct_io)
		fi->direct_io = 1;

	pflags = SSH_FXF_READ;
	
	sf = g_new0(struct sshfs_file, 1);
	list_init(&sf->write_reqs);
	pthread_cond_init(&sf->write_finished, NULL);
	/* Assume random read after open */
	sf->is_seq = 0;
	sf->next_pos = 0;
	pthread_mutex_lock(&sshfs.lock);
	if (sshfs.max_conns > 1) {
		ce = g_hash_table_lookup(sshfs.conntab, path);
		if (!ce) {
			ce = g_malloc(sizeof(struct conntab_entry));
			ce->refcount = 0;
			ce->conn = get_conn(NULL, NULL);
			g_hash_table_insert(sshfs.conntab, g_strdup(path), ce);
		}
		sf->conn = ce->conn;
		ce->refcount++;
		sf->conn->file_count++;
		assert(sf->conn->file_count > 0);
	} else {
		sf->conn = &sshfs.conns[0];
		ce = NULL; // only to silence compiler warning
	}
	sf->connver = sf->conn->connver;
	pthread_mutex_unlock(&sshfs.lock);
	buf_init(&buf, 0);
	buf_add_path(&buf, path);
	buf_add_uint32(&buf, pflags);
	buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
	buf_add_uint32(&buf, 0);
	buf_to_iov(&buf, &iov);
	sftp_request_send(sf->conn, SSH_FXP_OPEN, &iov, 1, NULL, NULL, 1, NULL,
			  &open_req);
	buf_clear(&buf);
	buf_add_path(&buf, path);
	type = SSH_FXP_LSTAT;
	err2 = sftp_request(sf->conn, type, &buf, SSH_FXP_ATTRS, &outbuf);
	if (!err2) {
		err2 = buf_get_attrs(&outbuf, &stbuf, NULL);
		buf_free(&outbuf);
	}
	err = sftp_request_wait(open_req, SSH_FXP_OPEN, SSH_FXP_HANDLE,
				&sf->handle);
	if (!err && err2) {
		buf_finish(&sf->handle);
		sftp_request(sf->conn, SSH_FXP_CLOSE, &sf->handle, 0, NULL);
		buf_free(&sf->handle);
		err = err2;
	}

	if (!err) {
		if (config.dir_cache)
			cache_add_attr(path, &stbuf);
		buf_finish(&sf->handle);
		sf->remote_size = stbuf.st_size;
		fi->fh = (unsigned long) sf;
	} else {
		if (config.dir_cache)
			cache_invalidate(path);
		if (sshfs.max_conns > 1) {
			pthread_mutex_lock(&sshfs.lock);
			sf->conn->file_count--;
			ce->refcount--;
			if(ce->refcount == 0) {
				g_hash_table_remove(sshfs.conntab, path);
				g_free(ce);
			}
			pthread_mutex_unlock(&sshfs.lock);
		}
		g_free(sf);
	}
	buf_free(&buf);
	return err;
}

static int sshfs_release(const char *path, struct fuse_file_info *fi)
{
        D1("RELEASE %s", path);
	struct sshfs_file *sf = get_sshfs_file(fi);
	struct buffer *handle = &sf->handle;
	struct conntab_entry *ce;
	if (sf && sshfs_file_is_conn(sf)) {
		sftp_request(sf->conn, SSH_FXP_CLOSE, handle, 0, NULL);
	}
	buf_free(handle);
	chunk_put_locked(sf->readahead);
	if (sshfs.max_conns > 1) {
		pthread_mutex_lock(&sshfs.lock);
		sf->conn->file_count--;
		ce = g_hash_table_lookup(sshfs.conntab, path);
		ce->refcount--;
		if(ce->refcount == 0) {
			g_hash_table_remove(sshfs.conntab, path);
			g_free(ce);
		}
		pthread_mutex_unlock(&sshfs.lock);
	}
	g_free(sf);
	return 0;
}

static void sshfs_read_end(struct request *req)
{
	struct read_req *rreq = (struct read_req *) req->data;
	if (req->error)
		rreq->res = req->error;
	else if (req->replied) {
		rreq->res = -EIO;

		if (req->reply_type == SSH_FXP_STATUS) {
			uint32_t serr;
			if (buf_get_uint32(&req->reply, &serr) != -1) {
				if (serr == SSH_FX_EOF)
					rreq->res = 0;
				else
					rreq->res = -sftp_error_to_errno(serr);
			}
		} else if (req->reply_type == SSH_FXP_DATA) {
			uint32_t retsize;
			if (buf_get_uint32(&req->reply, &retsize) != -1) {
				if (retsize > rreq->size) {
					fprintf(stderr, "long read\n");
				} else if (buf_check_get(&req->reply, retsize) != -1) {
					rreq->res = retsize;
					rreq->data = req->reply;
					buf_init(&req->reply, 0);
				}
			}
		} else {
			fprintf(stderr, "protocol error\n");
		}
	} else {
		rreq->res = -EIO;
	}

	rreq->sio->num_reqs--;
	if (!rreq->sio->num_reqs)
		pthread_cond_broadcast(&rreq->sio->finished);
}

static void sshfs_read_begin(struct request *req)
{
	struct read_req *rreq = (struct read_req *) req->data;
	rreq->sio->num_reqs++;
}

static struct read_chunk *sshfs_send_read(struct sshfs_file *sf, size_t size,
					  off_t offset)
{
	struct read_chunk *chunk = g_new0(struct read_chunk, 1);
	struct buffer *handle = &sf->handle;

	pthread_cond_init(&chunk->sio.finished, NULL);
	list_init(&chunk->reqs);
	chunk->size = size;
	chunk->offset = offset;
	chunk->refs = 1;

	while (size) {
		int err;
		struct buffer buf;
		struct iovec iov[1];
		struct read_req *rreq;
		size_t bsize = size < sshfs.max_read ? size : sshfs.max_read;

		rreq = g_new0(struct read_req, 1);
		rreq->sio = &chunk->sio;
		rreq->size = bsize;
		buf_init(&rreq->data, 0);
		list_add(&rreq->list, &chunk->reqs);

		buf_init(&buf, 0);
		buf_add_buf(&buf, handle);
		buf_add_uint64(&buf, offset);
		buf_add_uint32(&buf, bsize);
		buf_to_iov(&buf, &iov[0]);
		err = sftp_request_send(sf->conn, SSH_FXP_READ, iov, 1,
					sshfs_read_begin,
					sshfs_read_end,
					0, rreq, NULL);

		buf_free(&buf);
		if (err)
			break;

		size -= bsize;
		offset += bsize;
	}

	return chunk;
}

static int wait_chunk(struct read_chunk *chunk, char *buf, size_t size)
{
	int res = 0;
	struct read_req *rreq;

	pthread_mutex_lock(&sshfs.lock);
	while (chunk->sio.num_reqs)
	       pthread_cond_wait(&chunk->sio.finished, &sshfs.lock);
	pthread_mutex_unlock(&sshfs.lock);


	if (chunk->sio.error) {
		if (chunk->sio.error != MY_EOF)
			res = chunk->sio.error;

		goto out;
	}

	while (!list_empty(&chunk->reqs) && size) {
		rreq = list_entry(chunk->reqs.prev, struct read_req, list);

		if (rreq->res < 0) {
			chunk->sio.error = rreq->res;
			break;
		} if (rreq->res == 0) {
			chunk->sio.error = MY_EOF;
			break;
		} else if (size < (size_t) rreq->res) {
			buf_get_mem(&rreq->data, buf, size);
			rreq->res -= size;
			rreq->size -= size;
			res += size;
			break;
		} else {
			buf_get_mem(&rreq->data, buf, rreq->res);
			res += rreq->res;
			if ((size_t) rreq->res < rreq->size) {
				chunk->sio.error = MY_EOF;
				break;
			}
			buf += rreq->res;
			size -= rreq->res;
			list_del(&rreq->list);
			buf_free(&rreq->data);
			g_free(rreq);
		}
	}

	if (res > 0) {
		chunk->offset += res;
		chunk->size -= res;
	}

out:
	chunk_put_locked(chunk);
	return res;
}

static int sshfs_sync_read(struct sshfs_file *sf, char *buf, size_t size,
                           off_t offset)
{
	struct read_chunk *chunk;

	chunk = sshfs_send_read(sf, size, offset);
	return wait_chunk(chunk, buf, size);
}

static void submit_read(struct sshfs_file *sf, size_t size, off_t offset,
                        struct read_chunk **chunkp)
{
	struct read_chunk *chunk;

	chunk = sshfs_send_read(sf, size, offset);
	pthread_mutex_lock(&sshfs.lock);
	chunk_put(*chunkp);
	*chunkp = chunk;
	chunk->refs++;
	pthread_mutex_unlock(&sshfs.lock);
}

static struct read_chunk *search_read_chunk(struct sshfs_file *sf, off_t offset)
{
	struct read_chunk *ch = sf->readahead;
	if (ch && ch->offset == offset) {
		ch->refs++;
		return ch;
	} else
		return NULL;
}

static int sshfs_async_read(struct sshfs_file *sf, char *rbuf, size_t size,
                            off_t offset)
{
	int res = 0;
	size_t total = 0;
	struct read_chunk *chunk;
	struct read_chunk *chunk_prev = NULL;
	size_t origsize = size;
	int curr_is_seq;

	pthread_mutex_lock(&sshfs.lock);
	curr_is_seq = sf->is_seq;
	sf->is_seq = (sf->next_pos == offset);
	sf->next_pos = offset + size;
	chunk = search_read_chunk(sf, offset);
	pthread_mutex_unlock(&sshfs.lock);

	if (chunk && chunk->size < size) {
		chunk_prev = chunk;
		size -= chunk->size;
		offset += chunk->size;
		chunk = NULL;
	}

	if (!chunk)
		submit_read(sf, size, offset, &chunk);

	if (curr_is_seq && chunk && chunk->size <= size)
		submit_read(sf, origsize, offset + size, &sf->readahead);

	if (chunk_prev) {
		size_t prev_size = chunk_prev->size;
		res = wait_chunk(chunk_prev, rbuf, prev_size);
		if (res < (int) prev_size) {
			chunk_put_locked(chunk);
			return res;
		}
		rbuf += res;
		total += res;
	}
	res = wait_chunk(chunk, rbuf, size);
	if (res > 0)
		total += res;
	if (res < 0)
		return res;

	return total;
}

static int sshfs_read(const char *path, char *rbuf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
        D1("READ %s | offset " OFF_FMT " | size %zu", path, offset, size);
	struct sshfs_file *sf = get_sshfs_file(fi);
	(void) path;

	if (!sf || !sshfs_file_is_conn(sf))
		return -EIO;

	if (sshfs.sync_read)
		return sshfs_sync_read(sf, rbuf, size, offset);
	else
		return sshfs_async_read(sf, rbuf, size, offset);
}

static int sshfs_ext_statvfs(const char *path, struct statvfs *stbuf)
{
	int err;
	struct buffer buf;
	struct buffer outbuf;
	buf_init(&buf, 0);
	buf_add_string(&buf, SFTP_EXT_STATVFS);
	buf_add_path(&buf, path);
	err = sftp_request(get_conn(NULL, NULL), SSH_FXP_EXTENDED, &buf,
			   SSH_FXP_EXTENDED_REPLY, &outbuf);
	if (!err) {
		if (buf_get_statvfs(&outbuf, stbuf) == -1)
			err = -EIO;
		buf_free(&outbuf);
	}
	buf_free(&buf);
	return err;
}


static int sshfs_statfs(const char *path, struct statvfs *buf)
{
        D1("STATFS %s", path);
	if (sshfs.ext_statvfs)
		return sshfs_ext_statvfs(path, buf);

	buf->f_namemax = 255;
	buf->f_bsize = sshfs.blksize;
	/*
	 * df seems to use f_bsize instead of f_frsize, so make them the same
	 */
	buf->f_frsize = buf->f_bsize;
	buf->f_blocks = buf->f_bfree =  buf->f_bavail =
		1000ULL * 1024 * 1024 * 1024 / buf->f_frsize;
	buf->f_files = buf->f_ffree = 1000000000;
	return 0;
}

#ifdef __APPLE__
static int sshfs_getattr(const char *path, struct stat *stbuf)
#else
static int sshfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
#endif
{
        D1("GETATTR %s", path);
	int err;
	struct buffer buf;
	struct buffer outbuf;
	struct sshfs_file *sf = NULL;

#ifndef __APPLE__
	if (fi != NULL && (sf = get_sshfs_file(fi)) != NULL) {
	  if (!sshfs_file_is_conn(sf))
	    return -EIO;
	}
#endif

	buf_init(&buf, 0);
#ifndef __APPLE__
	if(sf == NULL) {
#endif
		buf_add_path(&buf, path);
		err = sftp_request(get_conn(sf, path), SSH_FXP_LSTAT, &buf, SSH_FXP_ATTRS, &outbuf);
#ifndef __APPLE__
	}
	else {
		buf_add_buf(&buf, &sf->handle);
		err = sftp_request(sf->conn, SSH_FXP_FSTAT, &buf, SSH_FXP_ATTRS, &outbuf);
	}
#endif
	if (!err) {
		err = buf_get_attrs(&outbuf, stbuf, NULL);
#ifdef __APPLE__
		stbuf->st_blksize = 0;
#endif
		buf_free(&outbuf);
	}
	buf_free(&buf);
	return err;
}

static int processing_init(void)
{
	int i;

	signal(SIGPIPE, SIG_IGN);

	pthread_mutex_init(&sshfs.lock, NULL);
	for (i = 0; i < sshfs.max_conns; i++)
		pthread_mutex_init(&sshfs.conns[i].lock_write, NULL);
	pthread_cond_init(&sshfs.outstanding_cond, NULL);
	sshfs.reqtab = g_hash_table_new(NULL, NULL);
	if (!sshfs.reqtab) {
		fprintf(stderr, "failed to create hash table\n");
		return -1;
	}
	if (sshfs.max_conns > 1) {
		sshfs.conntab = g_hash_table_new_full(g_str_hash, g_str_equal,
						      g_free, NULL);
		if (!sshfs.conntab) {
			fprintf(stderr, "failed to create hash table\n");
			return -1;
		}
	}
	return 0;
}



static int is_ssh_opt(const char *arg)
{
	if (arg[0] != '-') {
		unsigned arglen = strlen(arg);
		const char **o;
		for (o = ssh_opts; *o; o++) {
			unsigned olen = strlen(*o);
			if (arglen > olen && arg[olen] == '=' &&
			    strncasecmp(arg, *o, olen) == 0)
				return 1;
		}
	}
	return 0;
}


// Behaves similarly to strtok(), but allows for the ' ' delimiter to be escaped
// by '\ '.
static char *tokenize_on_space(char *str)
{
	static char *pos = NULL;
	char *start = NULL;

	if (str)
		pos = str;

	if (!pos)
		return NULL;

	// trim any leading spaces
	while (*pos == ' ')
		pos++;

	start = pos;

	while (pos && *pos != '\0') {
		// break on space, but not on '\ '
		if (*pos == ' ' && *(pos - 1) != '\\') {
			break;
		}
		pos++;
	}

	if (*pos == '\0') {
		pos = NULL;
	}
	else {
		*pos = '\0';
		pos++;
	}

	return start;
}

static void set_ssh_command(void)
{
	char *token = NULL;
	int i = 0;

	token = tokenize_on_space(sshfs.command);
	while (token != NULL) {
		if (i == 0) {
			replace_arg(&sshfs.args.argv[0], token);
		} else {
			if (fuse_opt_insert_arg(&sshfs.args, i, token) == -1)
				_exit(1);
		}
		i++;

		token = tokenize_on_space(NULL);
	}
}

int ssh_connect(void)
{
	int res;

	res = processing_init();
	if (res == -1)
		return -1;

	if (!sshfs.delay_connect) {
		if (connect_remote(&sshfs.conns[0]) == -1)
			return -1;

		if (!sshfs.no_check_root &&
		    sftp_check_root(&sshfs.conns[0], config.base_path) != 0)
			return -1;

	}
	return 0;
}

#ifdef __APPLE__
static void *sshfs_init(struct fuse_conn_info *conn)
#else
static void *sshfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
#endif
{
  D1("INIT");

#ifdef __APPLE__
	/* Readahead should be done by kernel or sshfs but not both */
	if (conn->async_read)
		sshfs.sync_read = 1;
#else
  /* Readahead should be done by kernel or sshfs but not both */
	if (conn->capable & FUSE_CAP_ASYNC_READ)
		sshfs.sync_read = 1;

	// These workarounds require the "path" argument.
	cfg->nullpath_ok = 0;

	// When using multiple connections, release() needs to know the path
	if (sshfs.max_conns > 1)
		cfg->nullpath_ok = 0;

	// Lookup of . and .. is supported
	conn->capable |= FUSE_CAP_EXPORT_SUPPORT;

	// SFTP only supports 1-second time resolution
	conn->time_gran = 1000000000;
#endif

	if (!sshfs.delay_connect)
		start_processing_thread(&sshfs.conns[0]);

#ifdef __APPLE__
#if FUSE_VERSION >= 29
	// When using multiple connections, release() needs to know the path
	if (sshfs.max_conns > 1)
	  sshfs_oper.flag_nullpath_ok = 0;
#endif
#endif

	return NULL;
}

void
sshfs_destroy(void *userdata)
{
  D1("DESTROY");

  int i;

  /* close the connections */
  if(sshfs.conns){
    struct conn *conn = NULL;
    D1("Closing the %d connections", sshfs.max_conns);
    for (i = 0; i < sshfs.max_conns; i++) {
      struct conn *conn = &sshfs.conns[i];
      D1("Connection %d: rfd %d | wfd: %d", i, conn->rfd, conn->wfd);
      if(conn->rfd > 0)
	close(conn->rfd);
      if(conn->wfd > 0 && conn->wfd != conn->rfd)
	close(conn->wfd);
    }
    free(sshfs.conns);
  }

  /* clean the ssh args */
  D2("Cleaning the ssh args");
  fuse_opt_free_args(&sshfs.args);
}


struct fuse_operations sshfs_oper = {
  .init       = sshfs_init,
  .getattr    = sshfs_getattr,
  .opendir    = sshfs_opendir,
  .readdir    = sshfs_readdir,
  .releasedir = sshfs_releasedir,
  .open       = sshfs_open,
  .release    = sshfs_release,
  .read       = sshfs_read,
  .statfs     = sshfs_statfs,

#ifdef __APPLE__
#if FUSE_VERSION >= 29
  .flag_nullpath_ok = 1,
  .flag_nopath = 1,
#endif
#endif

};

void sshfs_print_options(void)
{
	printf("\n"
"SSH Options:\n"
"    -o reconnect           reconnect to server\n"
"    -o delay_connect       delay connection to server\n"
"    -o sshfs_sync          synchronous writes\n"
"    -o no_readahead        synchronous reads (no speculative readahead)\n"
"    -o sync_readdir        synchronous readdir\n"
"    -o ssh_command=CMD     execute CMD instead of 'ssh'\n"
"    -o no_check_root       don't check for existence of 'dir' on server\n"
"    -o max_conns=N         open parallel SSH connections\n"
"    -o SSHOPT=VAL          ssh options (see man ssh_config)\n"
);
}

#define SSHFS_OPT(t, p, v) { t, offsetof(struct sshfs, p), v }

static struct fuse_opt sshfs_opts[] = {

    SSHFS_OPT("ssh_debug",    debug, 1),
    SSHFS_OPT("ssh_debug=%u", debug, 0),

    SSHFS_OPT("ssh_command=%s",    command, 0),
    SSHFS_OPT("ssh_protocol=%u",   ssh_ver, 0),
    SSHFS_OPT("-1",                ssh_ver, 1),
    SSHFS_OPT("no_readahead",      sync_read, 1),
    SSHFS_OPT("sync_readdir",      sync_readdir, 1),
    SSHFS_OPT("reconnect",         reconnect, 1),
    SSHFS_OPT("no_check_root",     no_check_root, 1),
    SSHFS_OPT("delay_connect",     delay_connect, 1),
    SSHFS_OPT("max_conns=%u",      max_conns, 1),


    FUSE_OPT_KEY("-p ",            KEY_PORT),
    //FUSE_OPT_KEY("-C",             KEY_COMPRESS),
    FUSE_OPT_KEY("-F ",            KEY_CONFIGFILE),

    FUSE_OPT_END
};


static int
sshfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
  (void) outargs; (void) data;
  char *tmp;

  switch (key) {
  case FUSE_OPT_KEY_OPT:
    if (is_ssh_opt(arg)) {
      tmp = g_strdup_printf("-o%s", arg);
      ssh_add_arg(tmp);
      g_free(tmp);
      return 0;
    }
    /* Pass through */
    return 1;

  case FUSE_OPT_KEY_NONOPT:
    /* Pass through */
    return 1;

  case KEY_PORT:
    tmp = g_strdup_printf("-oPort=%s", arg + 2);
    ssh_add_arg(tmp);
    g_free(tmp);
    return 0;

  case KEY_CONFIGFILE:
    tmp = g_strdup_printf("-F%s", arg + 2);
    ssh_add_arg(tmp);
    g_free(tmp);
    return 0;
    
  default:
    fprintf(stderr, "internal error\n");
    abort();
  }
}

int
sshfs_parse_options(struct fuse_args *args)
{
	sshfs.blksize = 0;
	/* SFTP spec says all servers should allow at least 32k I/O */
	sshfs.max_read = CRYPT4GH_CIPHERSEGMENT_SIZE;
	sshfs.ssh_ver = 2;
	sshfs.max_conns = 1;
	sshfs.delay_connect = 0;
	sshfs.max_outstanding_len = ~0;


  if(ssh_add_arg("ssh")    ||
     ssh_add_arg("-x")     ||
     ssh_add_arg("-a")     ||
     ssh_add_arg("-oClearAllForwardings=yes")
     )
    return 1;
      
  if(fuse_opt_parse(args, &sshfs, sshfs_opts, sshfs_opt_proc))
    return 2;

  if (sshfs.max_conns <= 0) {
    fprintf(stderr, "value of max_conns option must be at least 1\n");
    exit(1);
  }

  D2("Preparing %d connections", sshfs.max_conns);
  sshfs.conns = g_new0(struct conn, sshfs.max_conns);
  int i;
  for (i = 0; i < sshfs.max_conns; i++) {
    sshfs.conns[i].rfd = -1;
    sshfs.conns[i].wfd = -1;
  }

  if (sshfs.command)
    set_ssh_command();

  if( ssh_add_arg("-s")    ||
      ssh_add_arg(config.host) ||
      ssh_add_arg("sftp")
      )
    return 3;

  /* SFTP spec says all servers should allow at least 32k I/O */
  if (sshfs.max_read > CRYPT4GH_CIPHERSEGMENT_SIZE)
    sshfs.max_read = CRYPT4GH_CIPHERSEGMENT_SIZE;

  if(sshfs.debug)
    config.foreground = 1;

  return 0;
}


void
sshfs_print_stats(void)
{
  unsigned int avg_rtt = 0;

  if (sshfs.num_sent)
    avg_rtt = sshfs.total_rtt / sshfs.num_sent;

  fprintf(stderr, "\n"
	  "sent:               %llu messages, %llu bytes\n"
	  "received:           %llu messages, %llu bytes\n"
	  "rtt min/max/avg:    %ums/%ums/%ums\n"
	  "num connect:        %u\n",
	  (unsigned long long) sshfs.num_sent,
	  (unsigned long long) sshfs.bytes_sent,
	  (unsigned long long) sshfs.num_received,
	  (unsigned long long) sshfs.bytes_received,
	  sshfs.min_rtt, sshfs.max_rtt, avg_rtt,
	  sshfs.num_connect);
}

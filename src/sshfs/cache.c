/*
  Caching file system proxy
  Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "includes.h"

/* Debug color: Green */
#define D1(format, ...) if(cache.debug > 0) DEBUG_FUNC("\x1b[32m", "[CACHE]", format, ##__VA_ARGS__)
#define D2(format, ...) if(cache.debug > 1) DEBUG_FUNC("\x1b[32m", "[CACHE]", "     " format, ##__VA_ARGS__)
#define D3(format, ...) if(cache.debug > 2) DEBUG_FUNC("\x1b[32m", "[CACHE]", "          " format, ##__VA_ARGS__)
#define E(fmt, ...) ERROR_FUNC("[CACHE]", fmt, ##__VA_ARGS__)

#define DEFAULT_CACHE_TIMEOUT_SECS            300 //20
#define DEFAULT_MAX_CACHE_SIZE                10000
#define DEFAULT_CACHE_CLEAN_INTERVAL_SECS     60
#define DEFAULT_MIN_CACHE_CLEAN_INTERVAL_SECS 5

struct cache {
	int debug;
	unsigned int stat_timeout_secs;
	unsigned int dir_timeout_secs;
	unsigned int max_size;
	unsigned int clean_interval_secs;
	unsigned int min_clean_interval_secs;
	struct fuse_operations *next_oper;
	GHashTable *table;
	pthread_mutex_t lock;
	time_t last_cleaned;

        unsigned int   statvfs_timeout_secs;
        unsigned int   statvfs_set;
	time_t         statvfs_valid;
        struct statvfs statvfs;
};

static struct cache cache;

struct node {
	struct stat stat;
	time_t stat_valid;
	char **dir;
	time_t dir_valid;
	time_t valid;
};

struct readdir_handle {
	const char *path;
	void *buf;
	fuse_fill_dir_t filler;
	GPtrArray *dir;
};

struct cache_file_handle {
	/* Did we send an open request to the underlying fs? */
	int is_open;

	/* If so, this will hold its handle */
	unsigned long fs_fh;
};

static void free_node(gpointer node_)
{
	struct node *node = (struct node *) node_;
	g_strfreev(node->dir);
	g_free(node);
}

static int cache_clean_entry(void *key_, struct node *node, time_t *now)
{
	(void) key_;
	if (*now > node->valid)
		return TRUE;
	else
		return FALSE;
}

static void cache_clean(void)
{
	time_t now = time(NULL);
	if (now > cache.last_cleaned + cache.min_clean_interval_secs &&
	    (g_hash_table_size(cache.table) > cache.max_size ||
	     now > cache.last_cleaned + cache.clean_interval_secs)) {
		g_hash_table_foreach_remove(cache.table,
					    (GHRFunc) cache_clean_entry, &now);
		cache.last_cleaned = now;
	}
}

static struct node *cache_lookup(const char *path)
{
	return (struct node *) g_hash_table_lookup(cache.table, path);
}

static void cache_purge(const char *path)
{
	g_hash_table_remove(cache.table, path);
}

static void cache_purge_parent(const char *path)
{
	const char *s = strrchr(path, '/');
	if (s) {
		if (s == path)
			g_hash_table_remove(cache.table, "/");
		else {
			char *parent = g_strndup(path, s - path);
			cache_purge(parent);
			g_free(parent);
		}
	}
}

void cache_invalidate(const char *path)
{
	pthread_mutex_lock(&cache.lock);
	cache_purge(path);
	pthread_mutex_unlock(&cache.lock);
}

static void cache_invalidate_dir(const char *path)
{
	pthread_mutex_lock(&cache.lock);
	cache_purge(path);
	cache_purge_parent(path);
	pthread_mutex_unlock(&cache.lock);
}

static int cache_del_children(const char *key, void *val_, const char *path)
{
	(void) val_;
	if (strncmp(key, path, strlen(path)) == 0)
		return TRUE;
	else
		return FALSE;
}

static struct node *cache_get(const char *path)
{
	struct node *node = cache_lookup(path);
	if (node == NULL) {
		char *pathcopy = g_strdup(path);
		node = g_new0(struct node, 1);
		g_hash_table_insert(cache.table, pathcopy, node);
	}
	return node;
}

void cache_add_attr(const char *path, const struct stat *stbuf)
{
  if(stbuf){
    D1("Adding %s -> attr(st_ino=" INO_FMT ")", path, stbuf->st_ino);
  } else {
    D1("Adding %s -> attr(none)", path);
  }
	struct node *node;

	pthread_mutex_lock(&cache.lock);
	node = cache_get(path);
	node->stat = *stbuf;
	node->stat_valid = time(NULL) + cache.stat_timeout_secs;
	if (node->stat_valid > node->valid)
	  node->valid = node->stat_valid;
	cache_clean();
	pthread_mutex_unlock(&cache.lock);
}

static int cache_get_statvfs(const char *path, struct statvfs *stbuf)
{
  int err = -EAGAIN;
  pthread_mutex_lock(&cache.lock);
  if (cache.statvfs_set) {
    time_t now = time(NULL);
    if (cache.statvfs_valid - now >= 0) {
      *stbuf = cache.statvfs;
      err = 0;
    } else {
      D1("statvfs expired for %s", path);
      cache.statvfs_set = 0;
    }
  }
  pthread_mutex_unlock(&cache.lock);
  return err;
}

void cache_add_statvfs(const char *path, const struct statvfs *stbuf)
{
  if(!stbuf)
    return;

  pthread_mutex_lock(&cache.lock);
  cache.statvfs = *stbuf;
  cache.statvfs_valid = time(NULL) + cache.statvfs_timeout_secs;
  cache.statvfs_set = 1;
  pthread_mutex_unlock(&cache.lock);
}


static void cache_add_dir(const char *path, char **dir)
{
	struct node *node;

	pthread_mutex_lock(&cache.lock);
	node = cache_get(path);
	g_strfreev(node->dir);
	node->dir = dir;
	node->dir_valid = time(NULL) + cache.dir_timeout_secs;
	if (node->dir_valid > node->valid)
		node->valid = node->dir_valid;
	cache_clean();
	pthread_mutex_unlock(&cache.lock);
}

static size_t my_strnlen(const char *s, size_t maxsize)
{
	const char *p;
	for (p = s; maxsize && *p; maxsize--, p++);
	return p - s;
}

static int cache_get_attr(const char *path, struct stat *stbuf)
{
	struct node *node;
	int err = -EAGAIN;
	pthread_mutex_lock(&cache.lock);
	node = cache_lookup(path);
	if (node != NULL) {
		time_t now = time(NULL);
		if (node->stat_valid - now >= 0) {
			*stbuf = node->stat;
			err = 0;
		} else
		  D1("stat expired for %s", path);

	}
	pthread_mutex_unlock(&cache.lock);
	return err;
}

static void *cache_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	void *res;

	res = cache.next_oper->init(conn, cfg);

	// Cache requires a path for each request
	cfg->nullpath_ok = 0;

	pthread_mutex_init(&cache.lock, NULL);
	cache.table = g_hash_table_new_full(g_str_hash, g_str_equal,
					    g_free, free_node);
	if (cache.table == NULL) {
	  fprintf(stderr, "failed to create cache\n");
	  return NULL;
	}

	return res;
}


static void cache_destroy(void *userdata)
{
  if(cache.next_oper->destroy)
    cache.next_oper->destroy(userdata);

  g_hash_table_destroy(cache.table);
  cache.table = NULL;
}


static int cache_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
        D1("GETATTR %s", path);
	int err = cache_get_attr(path, stbuf);
	if (err) {
		err = cache.next_oper->getattr(path, stbuf, fi);
		D2("from underlying fs: %s", strerror((err>0)?err:-err));
		if (!err)
			cache_add_attr(path, stbuf);
	}
	return err;
}

static int cache_statfs(const char *path, struct statvfs *buf)
{
        D1("STATFS %s", path);
	int err = cache_get_statvfs(path, buf);
	if (err) {
		err = cache.next_oper->statfs(path, buf);
		D2("from underlying fs: %s", strerror((err>0)?err:-err));
		if (!err)
			cache_add_statvfs(path, buf);
	}
	return err;
}

static int cache_opendir(const char *path, struct fuse_file_info *fi)
{
        D1("OPENDIR %s", path);
	(void) path;
	struct cache_file_handle *cfi;

	cfi = malloc(sizeof(struct cache_file_handle));
	if(cfi == NULL)
		return -ENOMEM;
	cfi->is_open = 0;
	fi->fh = (unsigned long) cfi;
	return 0;
}

static int cache_releasedir(const char *path, struct fuse_file_info *fi)
{
        D1("RELEASEDIR %s", path);
	int err;
	struct cache_file_handle *cfi;

	cfi = (struct cache_file_handle*) fi->fh;

	if(cfi->is_open) {
		fi->fh = cfi->fs_fh;
		err = cache.next_oper->releasedir(path, fi);
	} else
		err = 0;

	free(cfi);
	return err;
}

static int cache_dirfill (void *buf, const char *name, const struct stat *stbuf, off_t off, enum fuse_fill_dir_flags flags)
{
  D2("FILLER %s", name);
	int err;
	struct readdir_handle *ch;

	ch = (struct readdir_handle*) buf;
	err = ch->filler(ch->buf, name, stbuf, off, flags);
	if (!err) {
		g_ptr_array_add(ch->dir, g_strdup(name));
		if (stbuf->st_mode & S_IFMT) {
			char *fullpath;
			const char *basepath = !ch->path[1] ? "" : ch->path;

			fullpath = g_strdup_printf("%s/%s", basepath, name);
			cache_add_attr(fullpath, stbuf);
			g_free(fullpath);
		}
	}
	return err;
}

static int cache_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
        D1("READDIR %s", path);
	struct readdir_handle ch;
	struct cache_file_handle *cfi;
	int err;
	char **dir;
	struct node *node;

	assert(offset == 0);

	pthread_mutex_lock(&cache.lock);
	node = cache_lookup(path);
	if (node != NULL && node->dir != NULL) {
		time_t now = time(NULL);
		if (node->dir_valid - now >= 0) {
			for(dir = node->dir; *dir != NULL; dir++)
				// FIXME: What about st_mode?
				filler(buf, *dir, NULL, 0, 0);
			pthread_mutex_unlock(&cache.lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&cache.lock);

	cfi = (struct cache_file_handle*) fi->fh;
	if(cfi->is_open)
		fi->fh = cfi->fs_fh;
	else {
		if(cache.next_oper->opendir) {
			err = cache.next_oper->opendir(path, fi);
			if(err)
				return err;
		}
		cfi->is_open = 1;
		cfi->fs_fh = fi->fh;
	}

	ch.path = path;
	ch.buf = buf;
	ch.filler = filler;
	ch.dir = g_ptr_array_new();
	err = cache.next_oper->readdir(path, &ch, cache_dirfill, offset, fi, flags);
	g_ptr_array_add(ch.dir, NULL);
	dir = (char **) ch.dir->pdata;
	if (!err) {
		cache_add_dir(path, dir);
	} else {
		g_strfreev(dir);
	}
	g_ptr_array_free(ch.dir, FALSE);

	return err;
}


struct fuse_operations *cache_wrap(struct fuse_operations *oper)
{
  static struct fuse_operations cache_oper;
  cache.next_oper = oper;

  cache_oper.init     = cache_init;
  cache_oper.destroy  = cache_destroy;

  cache_oper.getattr  = oper->getattr ? cache_getattr : NULL;
  cache_oper.opendir  = cache_opendir;
  cache_oper.readdir  = oper->readdir ? cache_readdir : NULL;
  cache_oper.releasedir = cache_releasedir;

  cache_oper.statfs   = oper->statfs ? cache_statfs : NULL;

  /* passthrough */
  cache_oper.open     = oper->open;
  cache_oper.read     = oper->read;
  cache_oper.release  = oper->release;

  return &cache_oper;
}

void cache_print_options(void)
{
#define DEFAULT_CACHE_TIMEOUT_SECS            300 //20
#define DEFAULT_MAX_CACHE_SIZE                10000
#define DEFAULT_CACHE_CLEAN_INTERVAL_SECS     60
#define DEFAULT_MIN_CACHE_CLEAN_INTERVAL_SECS 5

	printf("\n"
"Cache Options:\n"
"    -o dcache_max_size=N   sets the maximum size of the directory cache (default: %u)\n"
"    -o dcache_timeout=N    sets timeout for directory cache in seconds (default: %u)\n"
"    -o dcache_{stat,dir}_timeout=N\n"
"                           sets separate timeout for {attributes, names}\n"
"    -o dcache_clean_interval=N\n"
"                           sets the interval for automatic cleaning of the cache (default: %u)\n"
"    -o dcache_min_clean_interval=N\n"
"                           sets the interval for forced cleaning of the cache if full (default: %u)\n",
	       DEFAULT_MAX_CACHE_SIZE,
	       DEFAULT_CACHE_TIMEOUT_SECS,
	       DEFAULT_CACHE_CLEAN_INTERVAL_SECS,
	       DEFAULT_MIN_CACHE_CLEAN_INTERVAL_SECS
	       );
}

#define CACHE_OPT(t, p, v) { t, offsetof(struct cache, p), v }

static const struct fuse_opt cache_opts[] = {

    CACHE_OPT("dcache_timeout=%u",            stat_timeout_secs,       0),
    CACHE_OPT("dcache_timeout=%u",            dir_timeout_secs,        0),
    CACHE_OPT("dcache_timeout=%u",            statvfs_timeout_secs,    0),

    CACHE_OPT("dcache_stat_timeout=%u",       stat_timeout_secs,       0),
    CACHE_OPT("dcache_statvfs_timeout=%u",    statvfs_timeout_secs,    0),
    CACHE_OPT("dcache_dir_timeout=%u",        dir_timeout_secs,        0),

    CACHE_OPT("dcache_max_size=%u",           max_size,                0),
    CACHE_OPT("dcache_clean_interval=%u",     clean_interval_secs,     0),
    CACHE_OPT("dcache_min_clean_interval=%u", min_clean_interval_secs, 0),

    CACHE_OPT("cache_debug",    debug, 1),
    CACHE_OPT("cache_debug=%u", debug, 0),

    FUSE_OPT_END
};

int cache_parse_options(struct fuse_args *args)
{
	cache.stat_timeout_secs = DEFAULT_CACHE_TIMEOUT_SECS;
	cache.statvfs_timeout_secs = DEFAULT_CACHE_TIMEOUT_SECS;
	cache.dir_timeout_secs = DEFAULT_CACHE_TIMEOUT_SECS;
	cache.max_size = DEFAULT_MAX_CACHE_SIZE;
	cache.clean_interval_secs = DEFAULT_CACHE_CLEAN_INTERVAL_SECS;
	cache.min_clean_interval_secs = DEFAULT_MIN_CACHE_CLEAN_INTERVAL_SECS;

	return fuse_opt_parse(args, &cache, cache_opts, NULL);
}

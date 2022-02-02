#include "includes.h"

#define ROOT_ATTRS_TIMEOUT   30.0 /* half a minute */
#define DIR_ATTRS_TIMEOUT    24 * 3600.0 /* one day */
#define DEFAULT_BASE_PATH    "/outbox"
//#define DEFAULT_MAX_THREADS  10


/* Debug color: Yellow */
#define D1(format, ...) if(config.debug > 0) DEBUG_FUNC("\x1b[33m", "[EGAQV]", format, ##__VA_ARGS__)
#define D2(format, ...) if(config.debug > 1) DEBUG_FUNC("\x1b[33m", "[EGAQV]", "     " format, ##__VA_ARGS__)
#define D3(format, ...) if(config.debug > 2) DEBUG_FUNC("\x1b[33m", "[EGAQV]", "          " format, ##__VA_ARGS__)
#define E(fmt, ...) ERROR_FUNC("[EGAQV]", fmt, ##__VA_ARGS__)

/*
 * TODO: change the cache options to reflect that we don't cache the top level (ie datasets),
 * but we cache the datasets content (ie files in datasets). Those won't change. Datasets might.
 */
static void usage(struct fuse_args *args)
{
	printf(
"usage: %s [user@]host mountpoint [options]\n"
"\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"    -f                     foreground operation\n"
"    -s                     disable multi-threaded operation\n"
"    -o opt,[opt...]        mount options\n"
"    -d, --debug            print some debugging information (implies -f)\n"
"        --debug=N          debug level <N>\n"
"    -o dir_cache=BOOL      enable caching of directory names and attributes {yes,no} (default: yes)\n"
"    -o direct_io           enable direct i/o\n"
"    -o base_path           Base path of the SFTP remote lookups\n"
"\n"
"Fuse options:",
args->argv[0]);
    sshfs_print_options();
    cache_print_options();
    c4ghfs_print_options();
}


#define EGA_OPT(t, p, v) { t, offsetof(struct ega_config, p), v }

static struct fuse_opt ega_opts[] = {

	EGA_OPT("-h",		show_help, 1),
	EGA_OPT("--help",	show_help, 1),
	EGA_OPT("-V",		show_version, 1),
	EGA_OPT("--version",	show_version, 1),
	EGA_OPT("-v",		verbose, 1),
	EGA_OPT("verbose",	verbose, 1),
	EGA_OPT("-f",		foreground, 1),

	EGA_OPT("-d",		debug, 1),
	EGA_OPT("debug",	debug, 1),
	EGA_OPT("debug=%u",     debug, 0),

	EGA_OPT("direct_io",    direct_io, 1),
	EGA_OPT("base_path=%s", base_path, 0),

	EGA_OPT("disable_dir_cache", dir_cache, 0),
	EGA_OPT("file_cache", file_cache , 1),
	EGA_OPT("disable_c4gh", c4gh_decrypt , 0),

	/* if multithreaded */
	EGA_OPT("-s"              , singlethread    , 1),
	EGA_OPT("clone_fd"        , clone_fd        , 1),
	//EGA_OPT("max_idle_threads=%u", max_idle_threads, 0),


	/* Ignore these options.
	 * These may come in from /etc/fstab
	 */
	FUSE_OPT_KEY("writeback_cache=no", FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("auto",               FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("noauto",             FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("user",               FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("nouser",             FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("users",              FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("_netdev",            FUSE_OPT_KEY_DISCARD),

	FUSE_OPT_END
};

struct ega_config config;

static int
ega_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	(void) outargs; (void) data;
	char *tmp;

	switch (key) {
	case FUSE_OPT_KEY_OPT:
	  /* Pass through */
	  return 1;

	case FUSE_OPT_KEY_NONOPT:
	  /* first one: host
	   * second one: mountpoint
	   */
	  if (!config.host) {
	    config.host = strdup(arg);
	    return 0;
	  }
	  else if (!config.mountpoint) {
	    config.mountpoint = realpath(arg, NULL);
	    
	    if (!config.mountpoint) {
	      fprintf(stderr, "ega-qv: bad mount point `%s': %s\n",
		      arg, strerror(errno));
	      return -1;
	    }
	    return 0;
	  }
	  
	  fprintf(stderr, "ega-qv: invalid argument `%s'\n", arg);
	  return -1;


	default:
	  fprintf(stderr, "internal error\n");
	  abort();
	}
}


static char program_path[PATH_MAX] = { 0 };

int main(int argc, char *argv[], __unused char *envp[], char **exec_path)
{
  int res;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  struct fuse *fuse;
  struct fuse_chan *ch;
  struct fuse_operations *operations;

  int libver = fuse_version();
  assert(libver >= 27);

  if (!realpath(*exec_path, program_path)) {
    memset(program_path, 0, PATH_MAX);
  }

  memset(&config, 0, sizeof(struct ega_config));

  config.progname = argv[0];
  config.show_help = 0;
  config.show_version = 0;
  config.singlethread = 0;
  config.foreground = 0;
  config.dir_cache = 1; /* enabled by default */
  config.c4gh_decrypt = 1; /* enabled by default */
  config.uid = getuid();
  config.gid = getgid();
  config.mounted_at = time(NULL);
  config.mnt_mode = S_IFDIR | 0755;
  //config.max_idle_threads = DEFAULT_MAX_THREADS;


  /* General options */
  if (fuse_opt_parse(&args, &config, ega_opts, ega_opt_proc) == -1)
    exit(1);

  if (config.show_version) {
    printf("EGAQV version %s\n", PACKAGE_VERSION);
    printf("FUSE library version %d\n", fuse_version());
    exit(0);
  }
  if (config.show_help) {
    usage(&args);
    exit(0);
  }

  if (!config.host) {
    fprintf(stderr, "missing host\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  } 
  if (!config.mountpoint) {
    fprintf(stderr, "error: no mountpoint specified\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  }

  /*
   * Make sure $PATH does not contain anything pointing inside the mountpoint,
   * (cuz it would deadlock).
   */
  char *path_env = getenv("PATH");
  char *path = (path_env)?strdup(path_env):NULL;
  char *token = NULL, *p = path;
  if(!path){
    perror("The PATH environment variable is not set or empty");
    exit(1);
  }
  while ((token = strsep(&path, ":"))){
    if(!strcmp(token, config.mountpoint)){ /* todo use realpath */
      fprintf(stderr, "The mountpoint is contained in $PATH\n");
      free(p);
      exit(1);
    }
  }
  free(p);

  /* Parse each sub file system options */
  if( sshfs_parse_options(&args) || /* SSH options */
      cache_parse_options(&args) || /* Cache options */
      c4ghfs_parse_options(&args)   /* C4GH options */
      ){
    E("Parsing options");
    res = 1;
    goto bailout;
  }

  if(config.debug)
    config.foreground = 1;

  fuse_opt_insert_arg(&args, 1, "-osubtype=egafs,fsname=EGAQV");
  if (fuse_is_lib_option("ac_attr_timeout="))
    fuse_opt_insert_arg(&args, 1, "-oauto_cache,ac_attr_timeout=0");

  D1("EGAQV version %s", PACKAGE_VERSION);

  if(!config.base_path)
    config.base_path = DEFAULT_BASE_PATH;

  D1("EGAQV base path: %s", config.base_path);

  /* eventually correct the base path */
  size_t base_path_len = strlen(config.base_path);
  if(base_path_len > 0){
    char* last = config.base_path + base_path_len - 1;
    if(*last == '/')
      *last = '\0';
  }

  /* Stack up the file systems */
  operations = &sshfs_oper;
  if(config.dir_cache)
    operations = cache_wrap(operations);
  if(config.c4gh_decrypt)
    operations = c4gh_wrap(operations);

  config.op = operations;

  D2("fuse_mount: %s\n", config.mountpoint);
  ch = fuse_mount(config.mountpoint, &args);
  if (!ch){
    res = 1;
    goto bailout;
  }

  res = fcntl(fuse_chan_fd(ch), F_SETFD, FD_CLOEXEC);
  if (res == -1)
    perror("WARNING: failed to set FD_CLOEXEC on fuse device");

  D2("fuse_new\n");
  fuse = fuse_new(ch, &args, operations, sizeof(struct fuse_operations), NULL);
  if(fuse == NULL){
    res = 2;
    goto bailout_unmount;
  }

  D3("SSH connect");
  if (ssh_connect() == -1) { /* $PATH =/= mountpoint: no deadlock */
    res = 6;
    goto bailout_unmount;
  }

  D3("SSH deamonize: %d", config.foreground);
  if (fuse_daemonize(config.foreground) == -1) {
    res = 6;
    goto bailout_unmount;
  }
    
  D3("Setting up signal handlers");
  if (fuse_set_signal_handlers(fuse_get_session(fuse)) != 0) {
    res = 4;
    goto bailout_unmount;
  }


  D1("Mode: %s-threaded\n", (config.singlethread)?"single":"multi");

  if (config.singlethread)
    res = fuse_loop(fuse);
  else
    res = fuse_loop_mt(fuse);

  if (res != 0)
    res = 8;

bailout_signal:
  D3("Removing signal handlers");
  fuse_remove_signal_handlers(fuse_get_session(fuse));

bailout_unmount:
  D3("Unmounting");
  fuse_unmount(config.mountpoint, ch);

bailout_destroy:
  D3("Destroying");
  fuse_destroy(fuse);

bailout:
  D1("Exiting with status %d", res);

  fuse_opt_free_args(&args);

  if(config.debug)
    sshfs_print_stats();

  if(config.host) free(config.host);
  if(config.mountpoint) free(config.mountpoint);

  return res;
}

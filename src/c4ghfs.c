/*
  Read-only Crypt4GH file system
  Copyright (C) 2021  Frédéric Haziza <frederic.haziza@crg.eu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "includes.h"

#define DEFAULT_SECKEY       "~/.c4gh/seckey"
#define MAX_PASSPHRASE       1024

/* Debug color: Magenta */
#define D1(format, ...) if(c4gh.debug > 0) DEBUG_FUNC("\x1b[35m", "[C4GH]", format, ##__VA_ARGS__)
#define D2(format, ...) if(c4gh.debug > 1) DEBUG_FUNC("\x1b[35m", "[C4GH]", "     " format, ##__VA_ARGS__)
#define D3(format, ...) if(c4gh.debug > 2) DEBUG_FUNC("\x1b[35m", "[C4GH]", "          " format, ##__VA_ARGS__)
#define E(fmt, ...) ERROR_FUNC("[C4GH]", fmt, ##__VA_ARGS__)

struct c4gh {
  unsigned int debug;

  struct fuse_operations *next_oper;
  pthread_mutex_t lock;

  char* seckeypath;
  char* passphrase;
  char* passphrase_from_env;
  uint8_t seckey[crypto_kx_SECRETKEYBYTES]; /* unlocked secret key. TODO: better protect it */
  uint8_t pubkey[crypto_kx_PUBLICKEYBYTES];
};

static struct c4gh c4gh;

struct c4gh_file {

  int no_extension;

  /* underlying file handle */
  struct fuse_file_info fi;
  int fh;

  /* header */
  uint8_t *header;
  unsigned int header_size;
  size_t filesize;

  /* parsed header */
  uint8_t *session_keys;
  unsigned int nkeys;
  uint64_t *edit_list;
  unsigned int edit_list_len;

  /* decryption cache and pre-allocation.
   * We pull one segment at a time, even if the requested buffer size 
   * is more. We'll loop until we pulled all the necessary segments.
   *
   * TODO? add an option `readahead` that pull n segments at a time.
   * For the moment, n = 1;
   */
  uint8_t segment[CRYPT4GH_SEGMENT_SIZE];
  size_t  segment_len;
  size_t last_segment;
  int has_data;
  
  uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE];
  size_t  ciphersegment_len;
  unsigned char nonce[CRYPT4GH_NONCE_SIZE];

  pthread_mutex_t lock;
};

static inline void
c4gh_file_handle_free(struct c4gh_file *node)
{
  if(!node)
    return;
  if(node->header)
    free(node->header);
  if(node->session_keys)
    free(node->session_keys);
  if(node->edit_list)
    free(node->edit_list);
  free(node);
}


static void *
c4gh_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
  D1("INIT");
  void *res = NULL;

  /* Create the inode->path hash table */
  pthread_mutex_init(&c4gh.lock, NULL);

  if(c4gh.next_oper->init)
    res = c4gh.next_oper->init(conn, cfg);

  cfg->nullpath_ok = 0; // c4gh requires a path for each request

  return res;
}

static void
c4gh_destroy(void *userdata)
{
  D1("DESTROY");

  if(c4gh.next_oper->destroy)
    c4gh.next_oper->destroy(userdata);

  sodium_memzero(c4gh.seckey, crypto_kx_SECRETKEYBYTES);
  sodium_memzero(c4gh.pubkey, crypto_kx_PUBLICKEYBYTES);
}

static inline int c4gh_fetch_header(const char* path, uint8_t **h, unsigned int *hlen, struct fuse_file_info *fi);

#if 0
static int
is_dotted(const char *p)
//__attribute__((nonnull))
{
  while(1){
    while(*p && *p++ != '/'); /* find / */
    D2("     is_dotted %s\n", p);
    if(*p == '\0')
      return 0;
    if(*p == '.')
      return 1;
    p++;
  }
}
#endif

static int
c4gh_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{

#if 0
  if(path && is_dotted(path)){
    D2("NOPE ---------------- %s\n", path);
    return -ENOENT;
  }
#endif

  D1("GETATTR %s", path);

  /* fi will always be NULL if the file is not currently open, but may also be NULL if the file is open.
   *
   * Therefore, we do the following dance and put back the underlying fi as it should be
   */

  struct fuse_file_info fi_copy;
  struct fuse_file_info *fi2 = NULL;
  struct c4gh_file *cfi = NULL;
  if(fi){
    fi_copy = *fi;
    fi2 = &fi_copy;
    cfi = (struct c4gh_file *)fi->fh;
  }

  if(cfi)
    fi_copy.fh = cfi->fi.fh;

  /* This is a bit ugly. Someone please help.
   * We don't know when we should add the .c4gh extension.
   * We, so far, hard-code that EGA datasets are the top level directories
   * and that we have .c4gh files, and only files, in them.
   * Therefore, if the path length is greater than "/EGADxxxxxxxxxxx/"
   * we don't add the extension. Otherwise, we always do.
   */

  int err = 0;
  size_t plen = strlen(path);

  if(plen < sizeof("/EGADxxxxxxxxxxx")){ /* works for the desktop icon too */
    D3("passing through");
    err = c4gh.next_oper->getattr(path, stbuf, fi2);
  } else {
    D3("adding %s extension", CRYPTGH_EXT);
    char c4gh_path[plen+CRYPTGH_EXT_LEN+1];
    memcpy(c4gh_path, path, plen);
    memcpy(c4gh_path+plen, CRYPTGH_EXT, CRYPTGH_EXT_LEN);
    c4gh_path[plen+CRYPTGH_EXT_LEN] = '\0';
    err = c4gh.next_oper->getattr(c4gh_path, stbuf, fi2);
  }

  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();

  return err;
}

static int
c4gh_open(const char *path, struct fuse_file_info *fi)
{
  D1("OPEN %s", path);

  struct c4gh_file *cfi = calloc(1, sizeof(struct c4gh_file));
  if(!cfi)
    return -ENOMEM;

  cfi->fi = *fi; /* shallow copy */

  int err = 0;
  if(strcmp(path, "/.desktop") == 0){
    err = c4gh.next_oper->open(path, &cfi->fi);
    cfi->no_extension = 1;
  } else {
    size_t plen = strlen(path);
    char c4gh_path[plen+CRYPTGH_EXT_LEN+1];
    memcpy(c4gh_path, path, plen);
    memcpy(c4gh_path+plen, CRYPTGH_EXT, CRYPTGH_EXT_LEN);
    c4gh_path[plen+CRYPTGH_EXT_LEN] = '\0';
    err = c4gh.next_oper->open(c4gh_path, &cfi->fi);
  }

  if(err){
    E("Open failed: %d", err);
    c4gh_file_handle_free(cfi);
    return err;
  }

  struct sshfs_file *sshfh = (struct sshfs_file*)cfi->fi.fh;
  cfi->filesize = sshfh->filesize;

  D2("filesize: %zu", cfi->filesize);

  if(!config.singlethread)
    pthread_mutex_init(&cfi->lock, NULL);

  /* success */
  cfi->segment_len = -1;
  fi->fh = (uint64_t)cfi;

  if (config.file_cache)
    fi->keep_cache = 1; /* don't flush the kernel cache */

  if (config.direct_io)
    fi->direct_io = 1;

  return 0;
}

static int
c4gh_release(const char *path, struct fuse_file_info *fi)
{
  D1("RELEASE %s", path);

  struct c4gh_file *cfi = (struct c4gh_file *)fi->fh;

  int err = 0;

  if(cfi->no_extension){
    err = c4gh.next_oper->release(path, &cfi->fi);
  } else {
    size_t plen = strlen(path);
    char c4gh_path[plen+CRYPTGH_EXT_LEN+1];
    memcpy(c4gh_path, path, plen);
    memcpy(c4gh_path+plen, CRYPTGH_EXT, CRYPTGH_EXT_LEN);
    c4gh_path[plen+CRYPTGH_EXT_LEN] = '\0';
    err = c4gh.next_oper->release(c4gh_path, &cfi->fi);
  }

  c4gh_file_handle_free(cfi);

  return err;
}

static int
c4gh_fetch_header(const char *path,
		  uint8_t **h, unsigned int *hlen,
		  struct fuse_file_info *fi)
{
  int err = -EPERM;
  D2("Fetch header of %s", path);

  /*
   * TODO: Fetch c4gh.header_size bytes if it's already set.
   * For the moment, we fetch the bytes little at a time.
   */

  char *header = NULL, *p = NULL;
  unsigned int header_size = 0;

  header = calloc(16, sizeof(uint8_t));
  header_size = 16;
  if(!header)
    return -ENOMEM;

  D3("Reading [0-16]");
  if(c4gh.next_oper->read(path, header, 16, 0, fi) != 16){
    E("can't read preamble");
    err = -EIO;
    goto error;
  }

  D3("Checking magic number and version");
  if (memcmp(header, MAGIC_NUMBER, 8) != 0){
    E("Not a CRYPT4GH formatted file");
    err = -EIO;
    goto error;
  }

  if (PEEK_U32_LE(header + 8) != VERSION){
    E("Unsupported CRYPT4GH version");
    err = -EIO;
    goto error;
  }

  unsigned int npackets = PEEK_U32_LE(header + 12);
  D2("Header contains %d packets", npackets);
  if (npackets == 0){
    E("Empty Crypt4GH header");
    err = -EPERM;
    goto error;
  }

  /* now read all the packets */
  int i = 0;
  uint32_t packet_len = 0;
  char pbuf[4];
  while(npackets--){

    /* get the packet length */
    if (c4gh.next_oper->read(path, pbuf, 4, header_size, fi) != 4){
      E("can't read 4 bytes for packet length");
      err = -EIO;
      goto error;
    }

    /* extend header */
    packet_len = PEEK_U32_LE(pbuf);
    header = realloc(header, sizeof(uint8_t) * (header_size + packet_len));
    if(!header)
      return -ENOMEM;

    /* copy the packet length */
    memcpy(header+header_size, pbuf, 4);
    header_size += 4;
    packet_len -= 4;

    /* get the encrypted packet data */
    if (c4gh.next_oper->read(path, header + header_size, packet_len, header_size, fi) != packet_len){
      E("can't read %d bytes for packet", packet_len);
      err = -EIO;
      goto error;
    }
    header_size += packet_len;
  }

  /* Success */
  D2("Crypt4GH header size: %d", header_size);

  //H("header", header, header_size);
  err = 0;

error:

  if(err){ /* cleanup */
    E("Error fetching header of %s: %d", path, err);
    if(header) free(header);
    return err;
  }

  /* save the results */
  if(h)
    *h = (uint8_t*)header;
  else
    free(header); /* we were not interested in keeping it, we only wanted its size */

  if(hlen)
    *hlen = header_size;
  
  return err;
}


static inline int
c4gh_open_header(const char* path, struct c4gh_file *cfi)
{
  D2("Open header of %s", path);
  return (c4gh_fetch_header(path, &cfi->header, &cfi->header_size, &cfi->fi) ||
	  c4gh_header_parse(cfi->header, cfi->header_size,
			    c4gh.seckey, c4gh.pubkey,
			    &cfi->session_keys, &cfi->nkeys,
			    &cfi->edit_list, &cfi->edit_list_len)
	  );
}


/*
 * get the cipher segment from the underlying file system
 *
 * TODO: add a variable readahead=<n> and pre-allocate n cipher buffers
 * We then don't pull one segments, but n, if possible.
 * Alternatively, we use the size passed to crypt4gh_read() and allocate that amount (in cipher segments)
 * If size gets bigger, we reallocate. We then don't need the readahead variable, cuz the call will adapt
 * to the largest requested buffer.
 */
static int
c4gh_pull_segment(const char* path, off_t idx, struct c4gh_file* cfi)
__attribute__((nonnull))
{

  /* reverting the file handle */
  unsigned int requested = CRYPT4GH_CIPHERSEGMENT_SIZE;
  unsigned int received = 0;
  int len;

  off_t offset = idx * CRYPT4GH_CIPHERSEGMENT_SIZE + cfi->header_size;

  D2("Pulling segment " OFF_FMT " at position: " OFF_FMT, idx, offset);

  /* We loop until we pulled a full segment.
   * In case we pull less, we pull again and stop if we receive a zero-byte response.
   */
  while(requested > 0){
    len = c4gh.next_oper->read(path,
			       (char*)(cfi->ciphersegment + received),  /* where to put the data */
			       requested,                      /* requested amount      */
			       offset + received,              /* shift                 */
			       &cfi->fi);
    if(len < 0) /* error */
      return len;
    
    D3("received %d bytes | left: %u", len, requested);
    if(len == 0) /* done */
      break;
    received += len;
    requested -= len;
  }

  if(received < CIPHER_DIFF)
    return -EIO;

  cfi->ciphersegment_len = received;

  D3("Pulling segment " OFF_FMT " received %u bytes", idx, received);
  return received;
}


/* get the cipher segment from sshfs and decrypt */
static int
c4gh_decrypt_segment(struct c4gh_file* cfi)
__attribute__((nonnull))
{

  unsigned int key_idx = 0;
  uint8_t* session_key = NULL;
  unsigned long long segment_len = 0;

  D3("Decrypting latest segment | nkeys: %d", cfi->nkeys);

  /* nonce at the beginning of the ciphersegment */
  memcpy(cfi->nonce, cfi->ciphersegment, CRYPT4GH_NONCE_SIZE); /* CRYPT4GH_NONCE_SIZE * sizeof(char) */
  //H("\tBlock nonce", cfi->nonce, CRYPT4GH_NONCE_SIZE);

  /* Loop through all the session keys */
  session_key = cfi->session_keys;
  for(key_idx = 0; key_idx < cfi->nkeys; key_idx++)
    {
      if(crypto_aead_chacha20poly1305_ietf_decrypt(cfi->segment, &segment_len,
						   NULL,
						   cfi->ciphersegment + CRYPT4GH_NONCE_SIZE,
						   cfi->ciphersegment_len - CRYPT4GH_NONCE_SIZE,
						   NULL, 0, /* no authenticated data */
						   cfi->nonce, session_key)
	 ){
	D3("Session key %d failed", key_idx + 1);
	/* try next session key */
	session_key += CRYPT4GH_SESSION_KEY_SIZE;
	continue;
      }
      D3("Session key %d worked | segment length: %llu", key_idx+1, segment_len);
      cfi->segment_len = segment_len;
      cfi->has_data = 1;
      return 0; /* success */
    }
  /* we tried all the keys, none worked */
  return -EPERM;
}

static int
c4gh_read_and_decrypt(const char *c4gh_path, char *buf, size_t size, off_t offset, struct c4gh_file *cfi)
{

  D1("READ (encrypted) offset: " OFF_FMT " | size: %zu | %s", offset, size, c4gh_path);

  int err = -EIO;

  /* Check if we already have the header */
  if(cfi->header == NULL && c4gh_open_header(c4gh_path, cfi)){
    E("Opening header failed");
    return -EPERM;
  }

  if(!cfi->nkeys){
    E("No session keys found: decryption failed");
    return -EPERM;
  }
  D3("Number of keys: %d", cfi->nkeys);

  /* Determine the number of segments spanning the request */
  size_t start_segment = offset / CRYPT4GH_SEGMENT_SIZE;
  unsigned int off = offset % CRYPT4GH_SEGMENT_SIZE;
  size_t _size = off + size;
  size_t nsegments = _size / CRYPT4GH_SEGMENT_SIZE + (_size % CRYPT4GH_SEGMENT_SIZE != 0);

  D2("READ | spanning %lu segment%c | offset within first ciphersegment: %u",
     nsegments, (nsegments>1)?'s':' ', off);

#if DEBUG
  if( (size+off) <= (nsegments * CRYPT4GH_SEGMENT_SIZE)){
    E("READ | invalid sizes");
    free(buf);
    return -EINVAL;
  }
#endif

  /* get and decrypt all the relevant segments */
  unsigned int segment_idx = start_segment;
  size_t len;
  unsigned int segment_offset = off; /* for the first one and then reset */
  size_t leftover = size;
  size_t received = 0;
  char *b = buf;


  if(!config.singlethread)
    pthread_mutex_lock(&cfi->lock);

  while(leftover > 0){

    /* pull segment */
    if( cfi->has_data == 1 && cfi->last_segment == segment_idx ){
      D3("Skipping pulling segment %u", segment_idx);
    } else {
      len = c4gh_pull_segment(c4gh_path, segment_idx, cfi);
      D2("pulling segment got %zu", len);
      
      if(len < 0){ err = len; goto done; }
      if(len == 0) goto done;
      /* decrypt segment */
      D2("Decrypting");
      err = c4gh_decrypt_segment(cfi);
      D2("Decrypting error: %d", err);
      if(err)
	goto done;
      cfi->last_segment = segment_idx;
    }

    len = cfi->segment_len - segment_offset;
    if(len < 0){ err = -EIO; goto done; }

    if(leftover < len) /* minimum */
      len = leftover;

    D3("Copying %zu bytes | segment %u | offset: %u | size: %zu", len, segment_idx, segment_offset, size);
    memcpy(b, cfi->segment + segment_offset, len);
    leftover -= len;
    b += len;
    segment_idx++;
    segment_offset = 0; /* reset */
  }
  err = 0;

done:

  if(!config.singlethread)
    pthread_mutex_unlock(&cfi->lock);

  /* if(leftover > 0) */
  /*   E("===> READ missing: %zu of %zu | err %d", requested, size, err); */

  if(err < 0)
    return err;

  /* all good */
  D3("Answering %zu bytes", size - leftover);

  return size - leftover;
}


static int
c4gh_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{

  D1("READ offset: " OFF_FMT " | size: %zu | %s", offset, size, path);

  struct c4gh_file *cfi = (struct c4gh_file*) fi->fh;

  /* Check if the offset and requested size are within the file boundaries */
  /* filesize is calculated _after_ opening the header */
  ssize_t end = cfi->filesize - offset;

  if(end <= 0){ /* Reading passed the end */
    D2("Reading passed the end: offset " OFF_FMT " > filesize: %zu", offset, cfi->filesize);
    return 0;
  }

  if(size > end){ /* reset */
    D2("Reading too many bytes passed the end | scaling down %zu to %zu", size, (size_t)end);
    size = end;
  }

  if(cfi->no_extension)
    return c4gh.next_oper->read(path, buf, size, offset, &cfi->fi);

  size_t plen = strlen(path);
  char c4gh_path[plen+CRYPTGH_EXT_LEN+1];
  memcpy(c4gh_path, path, plen);
  memcpy(c4gh_path+plen, CRYPTGH_EXT, CRYPTGH_EXT_LEN);
  c4gh_path[plen+CRYPTGH_EXT_LEN] = '\0';
  return c4gh_read_and_decrypt(c4gh_path, buf, size, offset, cfi);
}



/*********************************************
 *
 * Directories
 * 
 *********************************************/

struct c4gh_readdir_handle {
  //const char *path;
  void *buf;
  fuse_fill_dir_t filler;
};

/*
 * Removes the .c4gh extension.
 * Caller must free the result.
 */
static inline char*
remove_extension(const char *name)
{
  if(!name) return NULL;
  char *n = strdup(name);
  if(!n)
    return NULL;
  size_t slen = strlen(n);

  if(slen < CRYPTGH_EXT_LEN)
    return n;
    
  slen -= CRYPTGH_EXT_LEN;
  char *dot_pos = n + slen;
  if(strncmp(dot_pos, CRYPTGH_EXT, CRYPTGH_EXT_LEN)) /* not the C4GH extension */
    return n;
  
  /* remove the extension */
  *dot_pos = '\0';
  return n;
}

static int
c4gh_filler(void *buf, const char *name, const struct stat *stbuf, off_t off, enum fuse_fill_dir_flags flags)
{
  D2("FILLER %s", name);

  int err = 0;
  struct c4gh_readdir_handle *h = (struct c4gh_readdir_handle*) buf;

  if(!stbuf){
    char *dname = remove_extension(name);
    if(dname){
      err = h->filler(h->buf, dname, stbuf, off, flags);
      free(dname);
    }
    return err;
  }

  D2("FILLER | checking file type | %p", stbuf);

  if(!S_ISREG(stbuf->st_mode)){ /* not a reg file */
    D2("FILLER | not a regular file");
    return h->filler(h->buf, name, stbuf, off, flags);
  }
	
  /* It's a file: adjust name and size */
  D2("FILLER | regular file: %s | encrypted size: " OFF_FMT, name, stbuf->st_size);
  char *dname = remove_extension(name);
  if(dname){
    err = h->filler(h->buf, dname, stbuf, off, flags);
    free(dname);
  }
  return err;
}

static int
c4gh_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	     off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
  D1("READDIR %s | offset: " OFF_FMT, path, offset);
  struct c4gh_readdir_handle h;
  //h.path = path,
  h.buf = buf;
  h.filler = filler;
  return c4gh.next_oper->readdir(path, &h, c4gh_filler, offset, fi, flags);
}

static int c4gh_statfs(const char *path, struct statvfs *buf)
{
  D1("STATFS %s", path);
  int err = c4gh.next_oper->statfs(path, buf);

  /* todo: correct the sizes */
  return err;
}

static int
c4gh_getxattr(const char *path, const char* name, char *value, size_t size)
{

  /* We get lots of:
     - "security.selinux"
     - "system.posix_acl_access"
     - "system.posix_acl_default"
     so we only answer to "user.decrypted_filesize".
     Alternatively, we could only allow the user.* extended attributes
  */
  if(strcmp(name, "user.decrypted_filesize"))
    return -ENODATA;

  D1("GETXATTR %s | name: %s | size: %zu", path, name, size);

  /* This is a bit ugly. Someone please help.
   * We don't know when we should add the .c4gh extension.
   * We, so far, hard-code that EGA datasets are the top level directories
   * and that we have .c4gh files, and only files, in them.
   * Therefore, if the path length is greater than "/EGADxxxxxxxxxxx/"
   * we don't add the extension. Otherwise, we always do.
   */

  int err = 0;
  size_t plen = strlen(path);

  if(plen < sizeof("/EGADxxxxxxxxxxx")){
    D3("passing through");
    err = c4gh.next_oper->getxattr(path, name, value, size);
  } else {
    D3("adding %s extension", CRYPTGH_EXT);
    char c4gh_path[plen+CRYPTGH_EXT_LEN+1];
    memcpy(c4gh_path, path, plen);
    memcpy(c4gh_path+plen, CRYPTGH_EXT, CRYPTGH_EXT_LEN);
    c4gh_path[plen+CRYPTGH_EXT_LEN] = '\0';
    err = c4gh.next_oper->getxattr(c4gh_path, name, value, size);
  }

  return err;
}

static int
c4gh_listxattr(const char *path, char* names, size_t size)
{

  D1("LISTXATTR %s | size: %zu", path, size);

  /* This is a bit ugly. Someone please help.
   * We don't know when we should add the .c4gh extension.
   * We, so far, hard-code that EGA datasets are the top level directories
   * and that we have .c4gh files, and only files, in them.
   * Therefore, if the path length is greater than "/EGADxxxxxxxxxxx/"
   * we don't add the extension. Otherwise, we always do.
   */

  int err = 0;
  size_t plen = strlen(path);

  if(plen < sizeof("/EGADxxxxxxxxxxx")){
    D3("passing through");
    err = c4gh.next_oper->listxattr(path, names, size);
  } else {
    D3("adding %s extension", CRYPTGH_EXT);
    char c4gh_path[plen+CRYPTGH_EXT_LEN+1];
    memcpy(c4gh_path, path, plen);
    memcpy(c4gh_path+plen, CRYPTGH_EXT, CRYPTGH_EXT_LEN);
    c4gh_path[plen+CRYPTGH_EXT_LEN] = '\0';
    err = c4gh.next_oper->listxattr(c4gh_path, names, size);
  }

  return err;
}


struct fuse_operations *
c4gh_wrap(struct fuse_operations *oper)
{
  c4gh.next_oper = oper;

  static struct fuse_operations c4gh_oper;
  memset(&c4gh_oper, 0, sizeof(struct fuse_operations));

  c4gh_oper.init       = c4gh_init;
  c4gh_oper.destroy    = c4gh_destroy;
  c4gh_oper.getattr    = c4gh_getattr;
  c4gh_oper.listxattr  = c4gh_listxattr;
  c4gh_oper.getxattr   = c4gh_getxattr;

  c4gh_oper.opendir    = oper->opendir;
  c4gh_oper.readdir    = oper->readdir ? c4gh_readdir : NULL;
  c4gh_oper.releasedir = oper->releasedir;

  c4gh_oper.open       = c4gh_open;
  c4gh_oper.read       = c4gh_read;
  c4gh_oper.release    = c4gh_release;

  //c4gh_oper.statfs     = oper->statfs ? c4gh_statfs : NULL;

  return &c4gh_oper;
}

static int
read_passphrase(const char* prompt)
{
  D1("Reading passphrase from TTY");
  int err = 0;
  int size = getpagesize();
  int max_passphrase = MIN(MAX_PASSPHRASE, size - 1);
  int n, rppflags, ttyfd;

  c4gh.passphrase = mmap(NULL, size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
			 -1, 0);
  if (c4gh.passphrase == MAP_FAILED) {
    perror("Failed to allocate locked page for passphrase");
    return -1;
  }
  if (mlock(c4gh.passphrase, size) == -1) {
    perror("Failed to lock the page for passphrase");
    err = 1;
    goto error;
  }

  /* require a TTY */
  rppflags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;
  ttyfd = open(_PATH_TTY, O_RDWR);
  if (ttyfd < 0){
    perror("can't open " _PATH_TTY);
    err = 2;
    goto error;
  }
  /*
   * If we're on a tty, ensure that show the prompt at
   * the beginning of the line. This will hopefully
   * clobber any passphrase characters the user has
   * optimistically typed before echo is disabled.
   */
  const char cr = '\r';
  (void) write(ttyfd, &cr, 1);
  close(ttyfd);

  /* read the passphrase */
  if(readpassphrase(prompt, c4gh.passphrase, max_passphrase, rppflags) == NULL) {
    perror("can't read the passphrase");
    err = 3;
    goto error;
  }

  c4gh.passphrase[strcspn(c4gh.passphrase, "\r\n")] = '\0'; /* replace the CRLF */
  
  return 0;

error:
  memset(c4gh.passphrase, 0, size);
  munmap(c4gh.passphrase, size);
  c4gh.passphrase = NULL;
  return err;
}


static int
tilde_expand(const char *s, char **d)
__nonnull__()
{
  char *dst;
  D3("Expanding %s", s);
  if (*s != '~') {
    D3("Nothing to expand");
    dst = strdup(s);
    if(!dst) errno = ENOMEM;
    *d = dst;
    return !dst;
  }

  s++;
  if(*s != '/' && *s != '\0'){
    errno = EINVAL; /* not a ~/... */
    return 1;
  }

  const char *homedir;
  
#ifdef HAVE_PWD_H
  D3("Getting home directory from getpwuid");
  struct passwd *pw;
  if ((pw = getpwuid(getuid())) == NULL) {
    perror("Error fetching the home directory for the current user");
    return -1;
  }
  homedir = pw->pw_dir;
#else
  D3("Getting home directory from HOME envvar");
  homedir = getenv("HOME");
#endif

  /* Make sure directory has a trailing '/' */
  size_t len = strlen(homedir);
  const char *sep = (len == 0 || homedir[len - 1] != '/')? "/": "";

  /* Skip leading '/' from specified path */
  if (s != NULL) s++;

  if (asprintf(&dst, "%s%s%s", homedir, sep, s) >= PATH_MAX) {
    perror("Path too long");
    if(dst) free(dst);
    return -1;
  }

  *d = dst;
  return 0;
}

void c4ghfs_print_options(void)
{
	printf("\n"
"Crypt4GH Options:\n"
"    -o c4gh_debug=N        debug level N\n"
"    -o seckey=<path>       path to the Crypt4GH secret key\n"
"    -o passphrase_from_env=<ENVVAR>\n"
"                           read passphrase from environment variable <ENVVAR>\n"
);
}

#define C4GH_OPT(t, p, v) { t, offsetof(struct c4gh, p), v }

static struct fuse_opt c4gh_opts[] = {

    C4GH_OPT("c4gh_debug",    debug, 1),
    C4GH_OPT("c4gh_debug=%u", debug, 0),

    C4GH_OPT("seckey=%s"             , seckeypath         , 0),
    C4GH_OPT("passphrase_from_env=%s", passphrase_from_env, 0),

    FUSE_OPT_END
};

int
c4ghfs_parse_options(struct fuse_args *args)
{
  char *seckeypath = NULL;
  int res = 0;

  memset(&c4gh, 0, sizeof(struct c4gh));

  if(fuse_opt_parse(args, &c4gh, c4gh_opts, NULL))
    return 1;

  if(!c4gh.seckeypath)
    c4gh.seckeypath = DEFAULT_SECKEY;

  /* Get the passphrase to unlock the Crypt4GH secret key */
  if (c4gh.passphrase_from_env) {
    D1("Getting the passphrase from envvar %s", c4gh.passphrase_from_env);
    c4gh.passphrase = getenv(c4gh.passphrase_from_env);
  } else {
    char prompt[PATH_MAX + sizeof("Enter the passphrase for the Crypt4GH key '': ")];
    sprintf(prompt, "Enter the passphrase for the Crypt4GH key '%s': ", c4gh.seckeypath);
    if (read_passphrase(prompt) != 0){
      res ++;
      goto bailout;
    }
  }

  if(!c4gh.passphrase){
    E("Missing passphrase");
    res ++;
    goto bailout;
  }

  /* Initialize libsodium */
  if (sodium_init() == -1) {
    E("Could not initialize libsodium: disabling Crypt4GH decryption");
    res ++;
    goto bailout;
  }

  /* Load the private key */
  D2("Loading secret key from %s", c4gh.seckeypath);
  if( tilde_expand(c4gh.seckeypath, &seckeypath) ||
      crypt4gh_private_key_from_file(seckeypath, c4gh.passphrase,
				     c4gh.seckey, c4gh.pubkey) ){
    E("Can't load the secret key from %s", (seckeypath)? seckeypath : "[unexpanded]");
    res ++;
    goto bailout;
  }

  D3("Crypt4GH key loaded from '%s'", seckeypath);

  if(c4gh.debug)
    config.foreground = 1;

bailout:
  if(seckeypath) free(seckeypath);
  return res;
}

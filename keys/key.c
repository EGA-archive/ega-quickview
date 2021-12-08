#include <ctype.h> /* isspace */
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sodium.h>

#include "includes.h"
#include "crypt4gh/key.h"
#include "crypt4gh/keys/ssh.h"
#include "crypt4gh/keys/c4gh.h"
#include "openbsd-compat/openbsd-compat.h" /* for freezero */

#define BUF_SIZE 4096 /* Laaaaarge enough */

int
crypt4gh_private_key_from_file(const char* filename,
			       char* passphrase,
			       uint8_t seckey[crypto_kx_SECRETKEYBYTES],
			       uint8_t pubkey[crypto_kx_PUBLICKEYBYTES])
{
  int rc = 1;
  char* buf = NULL;
  char *start = NULL, *end = NULL;
  size_t len = 0, buflen = BUF_SIZE - 2; /* for the trailing \n and \0 */
  int fd = -1;

  /* Read file into the buffer */
  D1("Opening file: %s", filename);
  if ((fd = open(filename, O_RDONLY)) == -1)
    return 1;

  if((buf = calloc(BUF_SIZE, sizeof(char))) == NULL){
    D1("Error allocating a buffer of size %d", BUF_SIZE);
    rc = 1;
    goto bailout;
  }

  start = buf;
  while (buflen > 0) {
    D2("Reading %lu bytes", buflen);
    rc = read(fd, start, buflen);
    D3("Read: %d", rc);
    if (rc == -1) { /* error */
      D1("Error reading file: %s", strerror(errno));
      rc = 2;
      goto bailout;
    }
    if (rc == 0) /* no more to read */
      break;

    /* otherwise */
    start += rc;
    buflen -= rc;
    len += rc;
  }

  start = buf; /* reset */
  while(isspace(*start)){ start++; len--; }; /* skip leading white-space (or newline) */

  end = start + len - 1; /* point at the end */
  while(isspace(*end)){ end--; len--; }; /* Discount trailing white-space or newline */

  /* Make sure we end with a newline character */
  D3("Last char: '%c'", *end);
  end++;
  *end = '\n';
  *(end+1) = '\0'; /* null-terminated. Don't worry, we left some space. */
  len++;

  /* We now stripped the file content from white-spaces */
  D1("Content from %s\%s", filename, start);
  D1("Content len: %lu | %lu", strlen(start), len);

  /* Try an SSH key first */
  rc = crypt4gh_ssh_private_key_from_blob(start, len, passphrase, seckey, pubkey);
  if(rc == 0) /* success: it's an ssh key */
    goto bailout;

  /* Try a Crypt4GH key */
  rc = crypt4gh_c4gh_private_key_from_blob(start, len, passphrase, seckey, pubkey);

bailout:
  if(fd > 0) close(fd);
  freezero(buf, BUF_SIZE);
  if(rc){ D1("Failed parsing %s: Error %d", filename, rc); }
  return rc;
}

int
crypt4gh_public_key_from_blob(const char* line,
			      size_t len,
			      uint8_t pk[crypto_kx_PUBLICKEYBYTES])
{
  /* Try an ssh key */
  if(!strncmp(line, "ssh-ed25519 ", 12)){
    D1("This is an ssh key");
    return crypt4gh_ssh_public_key_from_blob(line, len, pk);
  }

  /* Try a Crypt4GH key */
  D1("Trying Crypt4GH key");
  return crypt4gh_c4gh_public_key_from_blob(line, len, pk);
}

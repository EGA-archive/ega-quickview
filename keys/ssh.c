#include <sys/types.h>
#include <ctype.h> /* isspace */
#include <string.h>
#include <unistd.h>
#include <sodium.h>

#include "openssh/ssherr.h"
#include "openssh/sshbuf.h"
#include "openssh/sshkey.h"

#include "includes.h"
#include "crypt4gh/keys/ssh.h"

int
crypt4gh_ssh_private_key_from_blob(const char* line, size_t len,
				   char* passphrase,
				   uint8_t seckey[crypto_kx_SECRETKEYBYTES],
				   uint8_t pubkey[crypto_kx_PUBLICKEYBYTES])
{
  int rc = 1;
  struct sshbuf* blob = NULL;
  struct sshkey *key = NULL;
  char *comment = NULL;

  D1("Parsing an sshkey blob");

  /* Dump the blob into a buffer */
  if ((blob = sshbuf_new()) == NULL ||
      (rc = sshbuf_put(blob, line, len)) ||
      sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
    D1("Can't dump blob into buffer");
    rc = 1;
    goto bailout;
  }
  
  rc = sshkey_parse_private_from_blob(blob, passphrase, &key, &comment);
  if (rc || key == NULL){
    D1("Can't parse ssh buffer into sshkey: %s", ssh_err(rc));
    goto bailout;
  }

  if((rc = crypto_sign_ed25519_pk_to_curve25519(pubkey, key->pk)) ||
     (rc = crypto_sign_ed25519_sk_to_curve25519(seckey, key->sk))
     ){
    D1("Can't convert sshkey to x25519 keys");
    rc = 1;
    goto bailout;
  }
  /* success */
  D1("ED25519 key for \"%s\"", comment);
  rc = 0; 

bailout:
  if(blob) sshbuf_free(blob);
  if(key) sshkey_free(key);
  if(comment) free(comment);
  return rc;
}


/*
 * Retrieve public key portion from a blob
 */
int
crypt4gh_ssh_public_key_from_blob(const char* line,
				  size_t len,
				  uint8_t pk[crypto_kx_PUBLICKEYBYTES])
{

  int rc = 1;
  struct sshbuf *blob = NULL;
  char *tmp = NULL, *end = NULL, *ktype = NULL, *res = NULL;
  size_t reslen = 0;

  /* Check key type and skip it */
  if(strncmp(line, "ssh-ed25519 ", 12)){ D1("Not an ed25519 ssh key"); rc = 1; goto bailout; }
  line += 12;

  /* skip whitespace */
  while(isspace(*line)) line++;

  /* find the first white-space */
  tmp = strndup(line, len);
  end = strchr(tmp, ' ');
  if(end) *end = '\0'; /* Change it to \0 */
  D2("pk part: %s", tmp);

  /* base64 decode */
  blob = sshbuf_new();
  if(blob == NULL){ D1("Can't allocate ssh buffer"); rc = 2; goto bailout; }
  rc = sshbuf_b64tod(blob, tmp); /* see https://github.com/openssh/openssh-portable/blob/master/sshbuf-misc.c#L148 */
  if(rc){ D1("Can't decode the base64 string"); rc = 3; goto bailout; }

  /* consume key type */
  sshbuf_get_cstring(blob, &ktype, NULL);
  if(strcmp(ktype, "ssh-ed25519")){ D1("Not an ed25519 ssh key: Got %s instead", ktype); rc = 4; goto bailout; }

  /* consume public key */
  sshbuf_get_cstring(blob, &res, &reslen);

  if( reslen != crypto_kx_PUBLICKEYBYTES ){
    D1("public key is of incorrect size: %lu (instead of %d)", reslen, crypto_kx_PUBLICKEYBYTES);
    rc = 5;
    goto bailout;
  }

  /* convert it to x25519 and store it into pk */
  rc = crypto_sign_ed25519_pk_to_curve25519(pk, (u_char*)res);

bailout:
  sshbuf_free(blob);
  if(ktype) free(ktype);
  if(tmp) free(tmp);
  return rc;
}

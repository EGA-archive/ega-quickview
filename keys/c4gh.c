#include <ctype.h> /* isspace */
#include <unistd.h>
#include <string.h>
#include <sodium.h>

#include "includes.h"
#include "crypt4gh/keys/kdf.h"
#include "crypt4gh/keys/c4gh.h"

/* ==================================================================
 *
 *  Public key
 *
 * ================================================================== */

#define MARK_PUBLIC_BEGIN	"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
#define MARK_PUBLIC_END         "-----END CRYPT4GH PUBLIC KEY-----"
#define MARK_PUBLIC_BEGIN_LEN	(sizeof(MARK_PUBLIC_BEGIN) - 1)
#define MARK_PUBLIC_END_LEN	(sizeof(MARK_PUBLIC_END) - 1)

/*
 * The line should start with MARK_PUBLIC_BEGIN and end with MARK_PUBLIC_END
 */
int
crypt4gh_c4gh_public_key_from_blob(const char* line,
				   size_t len,
				   uint8_t pk[crypto_kx_PUBLICKEYBYTES])
{
  int rc = 1;
  char* end = (char*)line + len - 1; /* point at the end */
  D1("Length: %lu", len);
  D1("Last char: %c", *end);

  while(isspace(*line)){ line++; len--; }; /* skip leading white-space (or newline) */
  while(isspace(*end)){ end--; len--; }; /* Discount trailing white-space or newline */

  D1("Real length: %lu", len);

  if(/* large enough */
     len <= MARK_PUBLIC_BEGIN_LEN + MARK_PUBLIC_END_LEN 
     || /* starts with MARK_PUBLIC_BEGIN */
     memcmp(line, MARK_PUBLIC_BEGIN, MARK_PUBLIC_BEGIN_LEN) 
     || /* ends with MARK_PUBLIC_END */
     memcmp(line + len - MARK_PUBLIC_END_LEN, MARK_PUBLIC_END, MARK_PUBLIC_END_LEN)
     )
    {
      D1("Not a C4GH-v1 key");
      return 1;
    }

  /* Skip the MARK_PUBLIC_BEGIN and any white-space and newline */
  line += MARK_PUBLIC_BEGIN_LEN;
  len -= MARK_PUBLIC_BEGIN_LEN;
  while(isspace(*line)){ line++; len--; }; /* skip leading white-space or newline */

  /* Discount the MARK_PUBLIC_END and any white-space and newline */
  len -= MARK_PUBLIC_END_LEN;
  end = (char*)line + len - 1; /* point at the end */
  while(isspace(*end)){ end--; len--; }; /* Discount trailing white-space or newline */

  /* Copy the base64 part and add a NULL-terminating character (cuz we can't change "line") */
  char tmp[len+1];
  memcpy(tmp, line, len);
  tmp[len] = '\0';
  D1("base64 string: %s", tmp);

  /* Decoded string will be NULL-terminated too */
  u_char tmp2[crypto_kx_PUBLICKEYBYTES+1];
  int nlen = b64_pton(tmp, tmp2, crypto_kx_PUBLICKEYBYTES+1);
  D1("base64 decoding: %d", nlen);
  if(nlen < 0 || nlen < crypto_kx_PUBLICKEYBYTES){
    D1("Error with base64 decoding");
    rc = 2;
  } else {
    /* Success: copy over without the NULL-terminating char */
    memcpy(pk, tmp2, crypto_kx_PUBLICKEYBYTES);
    rc = 0;
  }

  /* Public information: no need to zero it */
  return rc;
}


/* ==================================================================
 *
 *  Private key, locked or not
 *
 * ================================================================== */

#define MAGIC_WORD      "c4gh-v1"

#define MARK_PRIVATE_BEGIN	"-----BEGIN CRYPT4GH PRIVATE KEY-----\n"
#define MARK_PRIVATE_END         "-----END CRYPT4GH PRIVATE KEY-----\n"
#define MARK_PRIVATE_BEGIN_LEN	(sizeof(MARK_PRIVATE_BEGIN) - 1)
#define MARK_PRIVATE_END_LEN	(sizeof(MARK_PRIVATE_END) - 1)

/*
 * Read 4 bytes from p and 
 * get its integer representation in little-endian format
 */
#define PEEK_U32_BE(p) \
	(((uint32_t)(((const uint8_t *)(p))[0]) << 24) | \
	 ((uint32_t)(((const uint8_t *)(p))[1]) << 16) | \
	 ((uint32_t)(((const uint8_t *)(p))[2]) << 8 ) | \
	 ((uint32_t)(((const uint8_t *)(p))[3])      ))


/** Consumes a string. 
 *  The string length is encoded in the 2 first bytes, as big-endian
 *  Advances the pointer bufp
 */
static int
decode_string(u_char** bufp, u_char **valp, uint16_t *lenp)
{
  if(bufp == NULL) return 1;
  u_char* buf = *bufp;

  /* string length is encoded in the 2 first bytes, as big-endian */
  uint16_t slen = ((uint8_t)(buf[0]) << 8) | (uint8_t)(buf[1]);
  if(valp) *valp = buf + 2;  /* save the start */
  if(lenp) *lenp = slen;   /* save the length */

  *bufp += slen + 2; /* make it consumed */
  return 0;
}


/*
 * The line should start with MARK_PRIVATE_BEGIN and end with MARK_PRIVATE_END
 */
int
crypt4gh_c4gh_private_key_from_blob(char* line, size_t len,
				    char* passphrase,
				    uint8_t seckey[crypto_kx_SECRETKEYBYTES],
				    uint8_t pubkey[crypto_kx_PUBLICKEYBYTES])
{
  int rc = 1;
  char *end = line + len; /* point at the end */
  u_char *tmp = NULL, *p = NULL;
  uint8_t* shared_key = NULL;

  if(/* large enough */
     len <= MARK_PRIVATE_BEGIN_LEN + MARK_PRIVATE_END_LEN 
     || /* starts with MARK_PRIVATE_BEGIN */
     memcmp(line, MARK_PRIVATE_BEGIN, MARK_PRIVATE_BEGIN_LEN) 
     || /* ends with MARK_PRIVATE_END */
     memcmp(end - MARK_PRIVATE_END_LEN, MARK_PRIVATE_END, MARK_PRIVATE_END_LEN)
     )
    {
      D1("Not a Crypt4GH private key");
      rc = 1;
      goto bailout;
    }

  /* Skip the MARK_PUBLIC_BEGIN and any white-space and newline */
  line += MARK_PRIVATE_BEGIN_LEN;
  len -= MARK_PRIVATE_BEGIN_LEN;
  while(isspace(*line)){ line++; len--; }; /* skip leading white-space or newline */

  /* Discount the MARK_PUBLIC_END and any white-space and newline */
  len -= MARK_PRIVATE_END_LEN;
  end = line + len - 1; /* point at the end */
  while(isspace(*end)){ end--; len--; }; /* Discount trailing white-space or newline */

  /* we _can_ change "line" */
  *(end+1) = '\0';

  D1("base64 string: %s", line);

  /* Decoded string will be NULL-terminated too */
  tmp = (u_char*)malloc((len+1) * sizeof(char));
  int nlen = b64_pton(line, tmp, len+1);
  D1("base64 decoding: %d", nlen);
  if(nlen < 0){
    D1("Error with base64 decoding");
    rc = 4;
    goto bailout;
  }

  if(memcmp(tmp, MAGIC_WORD, sizeof(MAGIC_WORD) - 1)){
    D1("Invalid magic word");
    rc = 5;
    goto bailout;
  }

  /* record start */
  p = tmp + sizeof(MAGIC_WORD) - 1;

  char* kdfname = NULL;
  uint16_t kdfname_len = 0;
  decode_string(&p, (u_char**)&kdfname, &kdfname_len);

  D1("KDF name: %.*s", (int)kdfname_len, kdfname);
  u_char* salt = NULL;
  uint16_t salt_len = 0;
  uint32_t rounds = 0;

  if(strncmp(kdfname, "none", kdfname_len))
    { /* not none... so get the saltsize and rounds */

      /* get KDF options */
      u_char* kdfoptions = NULL;
      uint16_t kdfoptions_len = 0;
      decode_string(&p, &kdfoptions, &kdfoptions_len);

      /* get rounds as 4 big-endian bytes */
      if( kdfoptions_len < 4){ rc = 2; goto bailout; }
      rounds = (((uint32_t)(kdfoptions[0]) << 24) | 
		((uint32_t)(kdfoptions[1]) << 16) |
		((uint32_t)(kdfoptions[2]) <<  8) |
		((uint32_t)(kdfoptions[3])      ) );
      D1("Rounds: %d", rounds);
      /* get the salt */
      salt_len = kdfoptions_len-4;
      salt = kdfoptions+4;
      H1("Salt", salt, salt_len);
    }
  else
    {
      D1("Not encrypted");
    }

  char* ciphername = NULL;
  uint16_t ciphername_len = 0;
  decode_string(&p, (u_char**)&ciphername, &ciphername_len);
  D1("Ciphername: %.*s", (int)ciphername_len, ciphername);

  u_char* private_data = NULL;
  uint16_t private_data_len = 0;
  decode_string(&p, &private_data, &private_data_len);

  H1("Private data", private_data, private_data_len);

  if(strncmp(ciphername, "none", ciphername_len) == 0)
    {
      /* No encryption: the private data is the secret key */
      memcpy(seckey, private_data,
	     /* use the min */
	     (private_data_len < crypto_kx_SECRETKEYBYTES)?private_data_len:crypto_kx_SECRETKEYBYTES);
      goto pubkey;
    }

  /* We have encrypted data, start libsodium */
  if (sodium_init() == -1) {
    D1("Unable to initialize libsodium");
    rc = 127;
    goto bailout;
  }

  shared_key = (uint8_t*)sodium_malloc(crypto_kx_SESSIONKEYBYTES /* 32 */);
  if( (rc = crypt4gh_kdf_derive_key(kdfname,
				    shared_key, crypto_kx_SESSIONKEYBYTES /* 32 */,
				    passphrase, strlen(passphrase), salt, salt_len, rounds)) != 0)
    {
      D1("Error deriving the shared key: %d", rc);
      goto bailout;
    }
  sodium_mprotect_readonly(shared_key);
  H1("Shared key", shared_key, crypto_kx_SESSIONKEYBYTES);

  u_char nonce[12];
  memcpy(nonce, private_data, 12);
  H1("Nonce", nonce, 12);
  D1("Encrypted data length: %d", (private_data_len - 12));

  unsigned long long decrypted_len;
  if( (rc = crypto_aead_chacha20poly1305_ietf_decrypt(seckey, &decrypted_len,
						 NULL,
						 private_data + 12, private_data_len - 12,
						 NULL, 0, /* no authenticated data */
						 nonce, shared_key)) != 0)
    {
      D1("Error decrypting the private data: %d", rc);
      D2("outlen: %llu", decrypted_len);
      goto bailout;
    }

  D2("outlen: %llu", decrypted_len);

pubkey:
  /* derive the public key */
  rc = crypto_scalarmult_base(pubkey, seckey);

bailout:
  if(tmp) free(tmp);
  if(shared_key) sodium_free(shared_key);
  return rc;
}

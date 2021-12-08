#include <sys/types.h>
#include <stdint.h>
#include <sodium.h>
#include <openssl/evp.h>

#include "includes.h"
#include "openbsd-compat/openbsd-compat.h" /* for bcrypt_pbkdf */
#include "crypt4gh/keys/kdf.h"

/* Supported key types */
static const struct kdftype kdfs[] = {
  {              "scrypt", 16, 0      },
  {              "bcrypt", 16, 100    },
  { "pbkdf2_hmac_sha256'", 16, 100000 },
  { NULL, 0, 0 }
};

const struct kdftype *
crypt4gh_kdf_from_name(const char* name, size_t name_len)
{
  const struct kdftype *kt;
  for (kt = kdfs; kt->name != NULL; kt++) {
    if (!strncmp(kt->name, name, name_len))
      return kt; /* points to static allocation */
  }
  return NULL;
}


int
crypt4gh_kdf_derive_key(char* alg,
		    uint8_t *key, size_t key_len,
		    const char* passphrase, size_t passphrase_len,
		    uint8_t* salt, size_t salt_len,
		    int rounds)
{
  /* See https://www.rfc-editor.org/rfc/rfc7914.txt
     and https://doc.libsodium.org/advanced/scrypt#notes */
  if (!strncmp(alg, "scrypt", 6)){
    D1("Deriving a shared key using scrypt");
    return crypto_pwhash_scryptsalsa208sha256_ll((const uint8_t*)passphrase, passphrase_len,
						 salt, salt_len,
						 1<<14, 8, 1,
						 key, key_len);
  }

  /* See keys/bcrypt
     and https://github.com/pyca/bcrypt/tree/master/src/_csrc */
  if (!strncmp(alg, "bcrypt", 6)){
    D1("Deriving a shared key using scrypt");
    return bcrypt_pbkdf(passphrase, passphrase_len,
			salt, salt_len,
			key, key_len,
			rounds);
  }

  /* See https://www.openssl.org/docs/man1.1.0/man3/PKCS5_PBKDF2_HMAC.html */
  if (!strncmp(alg, "pbkdf2_hmac_sha256", 18)){
    const EVP_MD *digest = EVP_sha256();
    if(digest == NULL) return 3;
    int rc = PKCS5_PBKDF2_HMAC(passphrase, passphrase_len,
			       salt, salt_len,
			       rounds,
			       digest,
			       key_len,
			       key)?0:1; /* ah bravo openssl: 1 on success, 0 on error ! */
    /* shouldn't we free the digest? Or is it done by openssl? */
    return rc;
  }

  D1("Unsupported KDF: %s", alg);
  return -1;
}

#ifndef __CRYPT4GH_KEYS_H_INCLUDED__
#define __CRYPT4GH_KEYS_H_INCLUDED__

#include <sodium.h>

int crypt4gh_private_key_from_file(const char* filename, char* passphrase,
				   unsigned char seckey[crypto_kx_SECRETKEYBYTES],
				   unsigned char pubkey[crypto_kx_PUBLICKEYBYTES]);

int crypt4gh_public_key_from_blob(const char* line,
				  size_t len,
				  unsigned char pk[crypto_kx_PUBLICKEYBYTES]);


#endif /* !__CRYPT4GH_KEYS_H_INCLUDED__ */

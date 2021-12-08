/* $OpenBSD: sshkey.c,v 1.111 2020/08/27 01:06:19 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
 * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UTIL_H
#include <util.h>
#endif /* HAVE_UTIL_H */

#include "ssherr.h"
#include "sshbuf.h"
#include "cipher.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#include "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----"
#define MARK_BEGIN_LEN		(sizeof(MARK_BEGIN) - 1)
#define MARK_END_LEN		(sizeof(MARK_END) - 1)

#define AUTH_MAGIC		"openssh-key-v1"


static inline int
valid_key_type(const char* name){
  return !strncmp(name, "ssh-ed25519", 11);
}

struct sshkey *
sshkey_new(void)
{
  struct sshkey *k;
  if ((k = calloc(1, sizeof(*k))) == NULL)
    return NULL;
  k->sk = NULL;
  k->pk = NULL;
  return k;
}

void
sshkey_free(struct sshkey *k)
{
  if (k == NULL)
    return;
  freezero(k->pk, ED25519_PK_SZ);
  k->pk = NULL;
  freezero(k->sk, ED25519_SK_SZ);
  k->sk = NULL;
  freezero(k, sizeof(*k));
}

static int
sshkey_froms(struct sshbuf *buf, struct sshkey **keyp)
{
  struct sshbuf *b;
  int ret = SSH_ERR_INTERNAL_ERROR;
  char *ktype = NULL;
  struct sshkey *key = NULL;
  size_t len;
  u_char *pk = NULL;
  
  if ((ret = sshbuf_froms(buf, &b)) != 0)
    return ret;
  
#ifdef DEBUG_PK /* XXX */
  sshbuf_dump(b, stderr);
#endif

  if (keyp != NULL)
    *keyp = NULL;

  if (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
    ret = SSH_ERR_INVALID_FORMAT;
    goto out;
  }
  
  if(!valid_key_type(ktype)){
    ret = SSH_ERR_KEY_TYPE_UNKNOWN;
    goto out;
  }
  
  if ((ret = sshbuf_get_string(b, &pk, &len)) != 0)
    goto out;
  if (len != ED25519_PK_SZ) {
    ret = SSH_ERR_INVALID_FORMAT;
    goto out;
  }
  if ((key = sshkey_new()) == NULL) {
    ret = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  key->pk = pk;
  pk = NULL;
  
  if (key != NULL && sshbuf_len(b) != 0) {
    ret = SSH_ERR_INVALID_FORMAT;
    goto out;
  }
  ret = 0;
  if (keyp != NULL) {
    *keyp = key;
    key = NULL;
  }
 out:
  sshkey_free(key);
  free(ktype);
  free(pk);
  sshbuf_free(b);
  return ret;
}

static int
sshkey_private_deserialize(struct sshbuf *buf, struct sshkey **kp)
{
	char *tname = NULL;
	struct sshkey *k = NULL;
	size_t pklen = 0, sklen = 0;
	int r = SSH_ERR_INTERNAL_ERROR;
	u_char *ed25519_pk = NULL, *ed25519_sk = NULL;

	if (kp != NULL)
		*kp = NULL;
	if ((r = sshbuf_get_cstring(buf, &tname, NULL)) != 0)
		goto out;

	if ((k = sshkey_new()) == NULL) {
	  r = SSH_ERR_ALLOC_FAIL;
	  goto out;
	}

	if ((r = sshbuf_get_string(buf, &ed25519_pk, &pklen)) != 0 ||
	    (r = sshbuf_get_string(buf, &ed25519_sk, &sklen)) != 0)
	  goto out;
	if (pklen != ED25519_PK_SZ || sklen != ED25519_SK_SZ) {
	  r = SSH_ERR_INVALID_FORMAT;
	  goto out;
	}
	k->pk = ed25519_pk;
	k->sk = ed25519_sk;
	ed25519_pk = ed25519_sk = NULL; /* transferred */

	/* success */
	r = 0;
	if (kp != NULL) {
		*kp = k;
		k = NULL;
	}
 out:
	free(tname);
	sshkey_free(k);
	freezero(ed25519_pk, pklen);
	freezero(ed25519_sk, sklen);
	return r;
}


static int
private2_uudecode(struct sshbuf *blob, struct sshbuf **decodedp)
{
	const u_char *cp;
	size_t encoded_len;
	int r;
	u_char last;
	struct sshbuf *encoded = NULL, *decoded = NULL;

	if (blob == NULL || decodedp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	*decodedp = NULL;

	if ((encoded = sshbuf_new()) == NULL ||
	    (decoded = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	if (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	while (encoded_len > 0) {
		if (*cp != '\n' && *cp != '\r') {
			if ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				goto out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		if (last == '\n') {
			if (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				if ((r = sshbuf_put_u8(encoded, 0)) != 0)
					goto out;
				break;
			}
		}
	}
	if (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decode base64 */
	if ((r = sshbuf_b64tod(decoded, (char *)sshbuf_ptr(encoded))) != 0)
		goto out;

	/* check magic */
	if (sshbuf_len(decoded) < sizeof(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, sizeof(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	*decodedp = decoded;
	decoded = NULL;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	return r;
}

static int
private2_decrypt(struct sshbuf *decoded, const char *passphrase,
    struct sshbuf **decryptedp, struct sshkey **pubkeyp)
{
	char *ciphername = NULL, *kdfname = NULL;
	const struct sshcipher *cipher = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	struct sshbuf *kdf = NULL, *decrypted = NULL;
	struct sshcipher_ctx *ciphercontext = NULL;
	struct sshkey *pubkey = NULL;
	u_char *key = NULL, *salt = NULL, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	if (decoded == NULL || decryptedp == NULL || pubkeyp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = NULL;
	*pubkeyp = NULL;

	if ((decrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* parse public portion of key */
	if ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, NULL)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	if (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		goto out;

	if ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((passphrase == NULL || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	if (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	if ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (strcmp(kdfname, "bcrypt") == 0) {
		if ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			goto out;
		if (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	if (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decrypt private portion of key */
	if ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 0)) != 0)
		goto out;
	if ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		if (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	if ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		goto out;
	/* there should be no trailing data */
	if (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* check check bytes */
	if ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		goto out;
	if (check1 != check2) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = NULL;
	*pubkeyp = pubkey;
	pubkey = NULL;
	r = 0;
 out:
	cipher_free(ciphercontext);
	free(ciphername);
	free(kdfname);
	sshkey_free(pubkey);
	if (salt != NULL) {
		explicit_bzero(salt, slen);
		free(salt);
	}
	if (key != NULL) {
		explicit_bzero(key, keylen + ivlen);
		free(key);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	return r;
}

/* Check deterministic padding after private key */
static int
private2_check_padding(struct sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	int r = SSH_ERR_INTERNAL_ERROR;

	i = 0;
	while (sshbuf_len(decrypted)) {
		if ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			goto out;
		if (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, sizeof(pad));
	explicit_bzero(&i, sizeof(i));
	return r;
}

static int
sshkey_parse_private2(struct sshbuf *blob, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	char *comment = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL, *decrypted = NULL;
	struct sshkey *k = NULL, *pubkey = NULL;

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	/* Undo base64 encoding and decrypt the private section */
	if ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		goto out;

	/* Load the private key and comment */
	if ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, NULL)) != 0)
		goto out;

	/* Check deterministic padding after private section */
	if ((r = private2_check_padding(decrypted)) != 0)
		goto out;

	/* Check that the public key in the envelope matches the private key */
	if(!pubkey || !k || !(pubkey->pk) || !(k->pk) ||
	   memcmp(pubkey->pk, k->pk, ED25519_PK_SZ)){
	  r = SSH_ERR_INVALID_FORMAT;
	  goto out;
	}

	/* success */
	r = 0;
	if (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}
	if (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
 out:
	free(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	return r;
}

int
sshkey_parse_private_from_blob(struct sshbuf *blob,
			       const char *passphrase,
			       struct sshkey **keyp, char **commentp)
{
  if (keyp != NULL)
    *keyp = NULL;
  if (commentp != NULL)
    *commentp = NULL;
  
  return sshkey_parse_private2(blob, passphrase, keyp, commentp);
}


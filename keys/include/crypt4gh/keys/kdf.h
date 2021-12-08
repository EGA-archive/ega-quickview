#ifndef __CRYPT4GH_KEYS_KDF_H_INCLUDED__
#define __CRYPT4GH_KEYS_KDF_H_INCLUDED__

/* Supported key types */
struct kdftype {
	const char *name;
	int saltsize;
	int rounds;
};

const struct kdftype*
crypt4gh_kdf_from_name(const char* name, size_t name_len);

int
crypt4gh_kdf_derive_key(char* alg,
			unsigned char *key, size_t key_len,
			const char* passphrase, size_t passphrase_len,
			unsigned char *salt, size_t salt_len,
			int rounds);

#endif /* !__CRYPT4GH_KEYS_KDF_H_INCLUDED__ */

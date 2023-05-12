#include "includes.h"

static unsigned int header_debug = 3;

/* Debug color: Green */
#define D1(format, ...) if(header_debug > 0) DEBUG_FUNC("\x1b[32m", "[HEADER]", format, ##__VA_ARGS__)
#define D2(format, ...) if(header_debug > 1) DEBUG_FUNC("\x1b[32m", "[HEADER]", "     " format, ##__VA_ARGS__)
#define D3(format, ...) if(header_debug > 2) DEBUG_FUNC("\x1b[32m", "[HEADER]", "          " format, ##__VA_ARGS__)
#define E(fmt, ...) ERROR_FUNC("[HEADER]", fmt, ##__VA_ARGS__)

#define H(leading, v,len)
/* #define H(leading, v,len) do {					\ */
/*     fprintf(stderr, "[HEADER] %s: ", (leading));		\ */
/*     int _i = 0;							\ */
/*     uint8_t* _p = (uint8_t*)(v);				\ */
/*     for(;_i<(len);_i++){ fprintf(stderr, "%02x", _p[_i] ); }	\ */
/*     fprintf(stderr, "\n");					\ */
/*   } while(0) */


static int
packet_parse(uint8_t* data, unsigned int data_len,
		      uint8_t** session_keys, unsigned int* nkeys,
		      uint64_t** edit_list, unsigned int* edit_list_len)
__nonnull__()
;
static int
header_decrypt_X25519_Chacha20_Poly1305(const uint8_t seckey[crypto_box_SECRETKEYBYTES],
					const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
					uint8_t* data, unsigned int data_len,
					uint8_t* output, unsigned int* output_len)
__nonnull__()
;

int
c4gh_header_parse(uint8_t* header, unsigned int header_size,
		  const uint8_t seckey[crypto_box_SECRETKEYBYTES],
		  const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
		  uint8_t** session_keys, unsigned int* nkeys,
		  uint64_t** edit_list, unsigned int* edit_list_len)
__nonnull__()
{

  D1("Parsing header of size %u", header_size);

  if(session_keys == NULL || header_size < 16)
    {
      E("Invalid interface for session keys");
      return 1;
    }

  if (memcmp(header, MAGIC_NUMBER, 8) != 0)
    {
      E("Not a CRYPT4GH formatted file");
      return 2;
    }

  if (PEEK_U32_LE(header + 8) != VERSION)
    {
      E("Unsupported CRYPT4GH version");
      return 3;
    }

  int npackets = PEEK_U32_LE(header + 12);
  D1("Header contains %d packets", npackets);
  if (npackets == 0)
    {
      E("Empty Crypt4GH header");
      return 4;
    }

  int packet = 0, rc = 0;
  uint32_t packet_len = 0;

  /* Preallocate the sodium region (maybe one too much) */
  //uint8_t* session_keys2 = (uint8_t*)sodium_malloc(CRYPT4GH_SESSION_KEY_SIZE * sizeof(uint8_t) * npackets);
  uint8_t* session_keys2 = (uint8_t*)calloc(npackets, CRYPT4GH_SESSION_KEY_SIZE * sizeof(uint8_t));

  if(session_keys2 == NULL || errno == ENOMEM){
    D1("Could not allocate the buffer for the session keys");
    rc = 1;
    goto bail;
  }

  *session_keys = session_keys2;
  header += 16;
  header_size -= 16;

  for (; packet < npackets; packet++)
    {
      D2("Packet %d", packet);

      if (header_size < 4){
	E("Packet too small: %u", header_size);
	rc = 5;
	goto bail;
      }

      packet_len = PEEK_U32_LE(header) - 4;
      header += 4;
      header_size -= 4;

      if(packet_len > header_size) /* already >= 0 */
	{
	  E("Invalid packet length %d", packet_len);
	  rc = 6;
	  goto bail;
	}

      D3("packet length: %d", packet_len);
      unsigned int decrypted_len = packet_len - 4U - crypto_box_PUBLICKEYBYTES - CRYPT4GH_NONCE_SIZE;
      uint8_t decrypted[decrypted_len];
      memset(decrypted, '\0', decrypted_len);
      D3("decrypted packet length: %d", decrypted_len);

      if(header_decrypt_X25519_Chacha20_Poly1305(seckey, pubkey,
						 header, packet_len,
						 (uint8_t*)decrypted, &decrypted_len))
	{
	  E("Cannot decrypt packet %d", packet);
	  header += packet_len;
	  continue;
	}

      /* valid session key or edit list */
      D3("Packet %d decrypted [%u bytes]", packet, decrypted_len);
      H("Packet", decrypted, decrypted_len);

      /* Parse the packet */
      rc = packet_parse(decrypted, decrypted_len, &session_keys2, nkeys, edit_list, edit_list_len);
      //sodium_memzero(decrypted, decrypted_len);
      memset(decrypted, '\0', decrypted_len); /* might be compiled away */


      header += packet_len;

      if(rc){ D1("Invalid packet %d", packet); }
    }

bail:
  //sodium_mprotect_readonly(session_keys);
  if(rc){ D1("Header Error %d", rc); }
  return rc;
}



static int
parse_packet_data_enc(uint8_t* data, uint8_t data_len,
		      uint8_t** session_keys, unsigned int* nkeys)
{
  D2("Data encryption packet");
  
  if(data == NULL || data_len < 4U + CRYPT4GH_SESSION_KEY_SIZE){
    D1("Not enough data to read");
    return 1;
  }
  
  uint32_t encryption_method = PEEK_U32_LE(data);
  if(encryption_method != chacha20_ietf_poly1305)
    {
      D1("Unsupported data encryption method: %u", encryption_method);
      return 2;
    }

  if(session_keys != NULL){
    memcpy(*session_keys, data+4, CRYPT4GH_SESSION_KEY_SIZE);
    *session_keys += CRYPT4GH_SESSION_KEY_SIZE;
    *nkeys += 1;
  }
  return 0;
}

static int
parse_packet_edit_list(uint8_t* data, unsigned int data_len,
		       uint64_t** edit_list, unsigned int* edit_list_len)
{
  D2("Edit list packet");

  if(edit_list == NULL)
    {
      E("Invalid interface");
      return 1;
    }

  if(*edit_list != NULL)
    {
      E("Only one edit list allowed per header");
      /* Reject header ?*/
      return 1;
    }

  if(data_len < 4)
    {
      D1("Invalid edit list of size %u", data_len);
      return 2;
    }

  uint32_t nlengths = PEEK_U32_LE(data);
  data += 4;
  data_len -= 4;

  if (data_len < 8ULL * nlengths)
    {
      D1("Edit list too small: %u, but expecting %llu", data_len, 8ULL * nlengths);
      return 3;
    }

  *edit_list = (uint64_t*)malloc(sizeof(uint64_t) * nlengths);
  if(*edit_list == NULL || errno == ENOMEM){
    D1("Could not allocate memory");
    return 4;
  }
  
  uint64_t* e = *edit_list;
  while(nlengths-- > 0)
    {
      *e = PEEK_U64_LE(data);
      data += sizeof(uint64_t);
      e++;
    }
  
  return 0;
}

static int
packet_parse(uint8_t* data, unsigned int data_len,
	     uint8_t** session_keys, unsigned int* nkeys,
	     uint64_t** edit_list, unsigned int* edit_list_len)
__nonnull__()
{
  int rc = 1;
  if(data_len < 4) { D1("Packet too small"); return rc; }

  uint32_t packet_type = PEEK_U32_LE(data);

  switch(packet_type){
  case data_encryption_parameters:
    rc = parse_packet_data_enc(data+4, data_len-4, session_keys, nkeys);
    break;
  case data_edit_list:
    rc = parse_packet_edit_list(data+4, data_len-4, edit_list, edit_list_len);
    break;
  default:
    D1("Unsupported packet type: %d", packet_type);
    break;
  }
  return rc;
}


static int
header_decrypt_X25519_Chacha20_Poly1305(const uint8_t seckey[crypto_box_SECRETKEYBYTES],
					const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
					uint8_t* data, unsigned int data_len,
					uint8_t* output, unsigned int* output_len)
__nonnull__()
{
  int rc = 0;

  if(output == NULL ||
     data_len < 4U + crypto_box_PUBLICKEYBYTES + CRYPT4GH_NONCE_SIZE + crypto_box_MACBYTES)
    {
      D1("Invalid input parameters");
      return 1;
    }

  /* encryption method */
  uint8_t* p = data;
  if(PEEK_U32_LE(p) != X25519_chacha20_ietf_poly1305)
    {
      E("Invalid encryption method");
      return 1;
    }
  p += 4;
  data_len -= 4;

  /* sender's pubkey */
  uint8_t sender_pubkey[crypto_box_PUBLICKEYBYTES];
  memcpy(sender_pubkey, p, crypto_box_PUBLICKEYBYTES);
  H("Sender's pubkey", sender_pubkey, crypto_box_PUBLICKEYBYTES);
  p += crypto_box_PUBLICKEYBYTES;
  data_len -= crypto_box_PUBLICKEYBYTES;
  
  /* nonce */
  uint8_t nonce[CRYPT4GH_NONCE_SIZE];
  memcpy(nonce, p, CRYPT4GH_NONCE_SIZE);
  H("nonce", p, CRYPT4GH_NONCE_SIZE);
  p += CRYPT4GH_NONCE_SIZE;
  data_len -= CRYPT4GH_NONCE_SIZE;

  /* X25519 shared key */
  //uint8_t* shared_key = (uint8_t*)sodium_malloc(crypto_kx_SESSIONKEYBYTES);
  uint8_t* shared_key = (uint8_t*)calloc(crypto_kx_SESSIONKEYBYTES, sizeof(uint8_t));
  if(!shared_key || errno == ENOMEM){
    D1("Unable to allocated memory for the shared key");
    return 1;
  }
  
  uint8_t ignored[crypto_kx_SESSIONKEYBYTES];
  rc = crypto_kx_client_session_keys(shared_key, ignored, pubkey, seckey, sender_pubkey);
  //sodium_memzero(ignored, crypto_kx_SESSIONKEYBYTES);
  //sodium_mprotect_readonly(shared_key);
  memset(ignored, '\0', crypto_kx_SESSIONKEYBYTES); /* might be compiled away */

  if(rc){
    E("Unable to derive the shared key: %d", rc);
    goto bailout;
  }

  H("Shared key", shared_key, crypto_kx_SESSIONKEYBYTES);

  /* decrypted packet (and mac) */
  D3("Encrypted Packet length %d", data_len);
  H("Encrypted Data", p, data_len);
  unsigned long long decrypted_len;
  rc = crypto_aead_chacha20poly1305_ietf_decrypt(output, &decrypted_len,
						 NULL,
						 p, data_len,
						 NULL, 0, /* no authenticated data */
						 nonce, shared_key);
  if(rc){
    D1("Error decrypting the packet");
    goto bailout;
  }
  
  D3("Decrypted Packet length %llu", decrypted_len);
  if(output_len) *output_len = (unsigned int)decrypted_len; /* small enough, won't drop anything */

  rc = 0; /* success */

bailout:
  //sodium_free(shared_key);
  free(shared_key);
  return rc;
}

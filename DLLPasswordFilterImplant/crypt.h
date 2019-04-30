#pragma once

#include <bcrypt.h>

typedef struct buffer_ {
	BYTE* data;
	size_t len;
} buffer_t;

typedef struct crypt_ctx_ {
	BCRYPT_ALG_HANDLE hAlg;
	BCRYPT_KEY_HANDLE hKey;
	BCRYPT_AUTH_TAG_LENGTHS_STRUCT auth_tag_lens;
	size_t block_len;
} crypt_ctx_t;

buffer_t* buffer_new(size_t len);
void buffer_free(buffer_t* buffer);

crypt_ctx_t* crypt_new(buffer_t* key);
void crypt_free(crypt_ctx_t* ctx);
buffer_t* crypt_rsa(crypt_ctx_t* ctx, buffer_t* plain);

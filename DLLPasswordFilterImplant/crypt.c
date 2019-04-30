#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <assert.h>

#include "crypt.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

crypt_ctx_t* crypt_new(buffer_t* key)
{
	DWORD res = 0, len = 0;
	CERT_PUBLIC_KEY_INFO* ki;

	res = CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
		key->data, key->len,
		CRYPT_ENCODE_ALLOC_FLAG, // Windows will allocate the buffer.
		NULL,
		&ki, &len);

	crypt_ctx_t* ctx = HeapAlloc(GetProcessHeap(), 0, sizeof(crypt_ctx_t));
	res = BCryptOpenAlgorithmProvider(&ctx->hAlg, BCRYPT_RSA_ALGORITHM, 0, 0);
	assert(BCRYPT_SUCCESS(res) || !"BCryptOpenAlgorithmProvider");

	// Import public key into CNG.
	res = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, ki, 0, NULL, &ctx->hKey);
	LocalFree(ki);

	return ctx;
}

void crypt_free(crypt_ctx_t* ctx)
{
	assert(ctx != NULL);

	if (ctx->hAlg) BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
	if (ctx->hKey) BCryptDestroyKey(ctx->hKey);
	HeapFree(GetProcessHeap(), 0, ctx);
}

buffer_t* buffer_new(size_t len)
{
	assert(len > 0);
	HANDLE h = GetProcessHeap();
	buffer_t* b = HeapAlloc(h, 0, sizeof(buffer_t));
	b->data = HeapAlloc(h, 0, len);
	b->len = len;
	return b;
}

void buffer_free(buffer_t* buffer)
{
	assert(buffer && buffer->data);
	HANDLE h = GetProcessHeap();
	HeapFree(h, 0, buffer->data);
	HeapFree(h, 0, buffer);
}

buffer_t* crypt_rsa(crypt_ctx_t* ctx, buffer_t* plain)
{
	DWORD res = 0, len = 0;
	BCRYPT_OAEP_PADDING_INFO padding;
	
	ZeroMemory(&padding, sizeof(padding));
	padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;

	// Get required buffer size.
	res = BCryptEncrypt(ctx->hKey,
		plain->data, plain->len,
		&padding, NULL, 0, NULL, 0,
		&len, BCRYPT_PAD_OAEP);

	// Allocated encrypted buffer.
	buffer_t* encrypted = buffer_new(len);
	res = BCryptEncrypt(ctx->hKey,
		plain->data, plain->len,
		&padding, NULL, 0,
		encrypted->data, encrypted->len,
		&len, BCRYPT_PAD_OAEP);

	return encrypted;
}
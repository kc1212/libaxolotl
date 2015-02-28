
#ifndef _hkdf_h
#define _hkdf_h

int hkdf_create_for(int message_version);

int hkdf_derive_secrets_zerosalt(const unsigned char* in, const size_t inlen,
		const unsigned char* info, const size_t infolen,
		const int outlen, unsigned char* out);

int hkdf_derive_secrets(const unsigned char* in, const size_t inlen,
		const unsigned char* salt, const size_t saltlen,
		const unsigned char* info, const size_t infolen,
		const int outlen, unsigned char* out);

#endif

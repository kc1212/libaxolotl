
#ifndef _hkdf_h
#define _hkdf_h

enum hkdf_msg_ver_t {
	HKDF_MESSAGE_V2 = 0,
	HKDF_MESSAGE_V3 = 1
};

int hkdf_derive_secrets_zerosalt(enum hkdf_msg_ver_t offset,
		const unsigned char* in, const size_t inlen,
		const unsigned char* info, const size_t infolen,
		const int outlen, unsigned char* out);

int hkdf_derive_secrets(enum hkdf_msg_ver_t offset,
		const unsigned char* in, const size_t inlen,
		const unsigned char* salt, const size_t saltlen,
		const unsigned char* info, const size_t infolen,
		const int outlen, unsigned char* out);

#endif
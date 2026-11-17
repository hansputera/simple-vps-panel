#ifndef _CRYPT_H
#define _CRYPT_H
#ifdef __cplusplus
extern "C" {
#endif
struct crypt_data {
	int initialized;
	char output[384];
	char setting[64];
	char input[512];
	char misc[256];
	void *internal[32];
};
extern char *crypt(const char *, const char *);
extern char *crypt_r(const char *, const char *, struct crypt_data *);
char *__crypt_r(const char *, const char *, struct crypt_data *);
#ifdef __cplusplus
}
#endif
#endif

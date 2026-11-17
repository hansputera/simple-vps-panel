#include <crypt.h>
char *crypt_r(const char *k, const char *s, struct crypt_data *d){
    return __crypt_r(k, s, d);
}

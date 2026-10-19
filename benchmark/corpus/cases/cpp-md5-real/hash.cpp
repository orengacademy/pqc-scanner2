#include <openssl/md5.h>
void f(const unsigned char* d, size_t n, unsigned char* o) { MD5(d, n, o); }

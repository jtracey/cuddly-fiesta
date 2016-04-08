#ifndef BASE64
#define BASE64 1
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#define SIGLEN 56
#define B64SIZE 64
#define BINSIZE 48
#define TOKENSIZE 162

void base64encode(char out[], const BIGNUM* bn1, BIGNUM* bn2);
void base64decode(BIGNUM* bn1, BIGNUM* bn2, char* in);
void dump_mem(const unsigned char* buf, int n);

#endif

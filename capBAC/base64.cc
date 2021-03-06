#include "base64.h"
#include "string.h"
#include <stdio.h>

#include "cencode.h"
#include "cdecode.h"

void dump_mem(const unsigned char* buf, int n) {
  printf("MEMDUMP: ");
  for(int i=0; i<n; i++)
    printf("%02X",buf[i]);
  printf("\n");
}

void encode(char out[B64SIZE], const unsigned char* input) {
  char* c = out;
  int cnt = 0;
  base64_encodestate s;

  base64_init_encodestate(&s);
  cnt = base64_encode_block((char *) input, BINSIZE, c, &s);
  c += cnt;
  cnt = base64_encode_blockend(c, &s);

  return;
}

void decode(unsigned char out[BINSIZE], const char* input) {
  char* c =  (char*) out;
  base64_decodestate s;

  base64_init_decodestate(&s);
  base64_decode_block(input, B64SIZE, c, &s);

  return;
}


void base64encode(char out[B64SIZE], const BIGNUM* bn1, BIGNUM* bn2) {
  unsigned char buf[BINSIZE];
  unsigned char *bi1, *bi2;
  int r1, r2;

  bi1 = buf;
  bi2 = buf + BINSIZE/2;

  r1 = BN_bn2bin(bn1, bi1);
  r2 = BN_bn2bin(bn2, bi2);

  if((r1 == 0) || (r2 == 0)) {
    printf("error writing bn to binary\n");
    exit(1);
  }

  if(r1 < BINSIZE/2) {
    memset(bi1, 0, BINSIZE/2);
    r1 = BN_bn2bin(bn1, bi1+(BINSIZE/2 - r1));
  }
  if(r2 < BINSIZE/2) {
    memset(bi2, 0, BINSIZE/2);
    r2 = BN_bn2bin(bn2, bi2+(BINSIZE/2 - r2));
  }

  if((r1 == 0) || (r2 == 0)) {
    printf("error writing bn to binary\n");
    exit(1);
  }

  encode(out, buf);
  return;
}

// takes in 56 bytes of base 64 representing two 24 byte EC points,
// puts the values into bn1/2
void base64decode(BIGNUM* bn1, BIGNUM* bn2, char* in) {
  unsigned char buf[B64SIZE];
  unsigned char *bi1, *bi2;

  decode(buf, in);

  bi1 = buf;
  bi2 = buf + 24;
  BN_bin2bn(bi1, 24, bn1);
  BN_bin2bn(bi2, 24, bn2);

  return;
}

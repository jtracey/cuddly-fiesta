#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "base64.h"

#define MACHINE_IP inet_addr("127.0.0.1")
#define PORT 49152

using namespace rapidjson;

int test_net(const char* message, const unsigned char* sig){
  int soc;
  uint16_t port = PORT;

  soc = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in connectAddress;
  memset(&connectAddress, 0, sizeof(connectAddress));
  connectAddress.sin_family = AF_INET;
  connectAddress.sin_addr.s_addr = MACHINE_IP;
  connectAddress.sin_port = htons(port);

  if(connect(soc, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) < 0) {
    printf("failed to connect: %s\n", strerror(errno));
    return 1;
  }

  if(write(soc, message, strlen(message)+1) < 0) {
      printf("failed to write to socket\n");
      return 1;
  }
  if(write(soc, sig, SIGLEN) < 0) {
      printf("failed to write to socket\n");
      return 1;
  }
  return 0;
}

int test_sigs() {
  Document d;
  EC_KEY *eckey;
  char su[B64SIZE];
  Value ii, nb, na, suv;
  unsigned int now;
  unsigned char *sig;
  EVP_MD_CTX* mdctx;
  const EVP_MD* md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len, buf_len;
  BIGNUM *x, *y, *x2, *y2;
  BN_CTX *ctx;

  eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime192v3);
  if (eckey == NULL) {
    printf("failed to initialize curve\n");
    return 1;
  }
  if (EC_KEY_generate_key(eckey) == 0) {
    printf("failed to generate key\n");
    return 1;
  }

  x  = BN_new();
  y  = BN_new();
  x2 = BN_new();
  y2 = BN_new();

  if(!x || !y || !x2 || !y2) {
    printf("base64decode: BN_new() failure\n");
    exit(1);
  }
  ctx = BN_CTX_new();
  if(!ctx) {
    printf("failed to create bn ctx\n");
    return 1;
  }
  EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(eckey),
				      EC_KEY_get0_public_key(eckey),
				      x, y, ctx);
  BN_CTX_free(ctx);
  base64encode(su, x, y);
  base64decode(x2, y2, su);
  //if(BN_cmp(x, x2) != 0 || BN_cmp(y, y2) != 0) {
  //  printf("values differ\n");
  printf("b64: %s\nx : %s\nx2: %s\ny : %s\ny2: %s\n", su,
	 BN_bn2hex(x), BN_bn2hex(x2), BN_bn2hex(y), BN_bn2hex(y2));
    //  return 1;
    //}

  d.Parse("{}");

  suv.SetString(su, B64SIZE, d.GetAllocator());

  now = time(NULL);
  ii.SetInt(now);
  nb.SetInt(now);
  na.SetInt(1600000000); // The future!


  d.AddMember("id", "fake identifier", d.GetAllocator());
  d.AddMember("ii", ii, d.GetAllocator());
  d.AddMember("is", "fake issuer", d.GetAllocator());
  d.AddMember("su", suv, d.GetAllocator());
  d.AddMember("de", "fake device URI", d.GetAllocator());
  d.AddMember("ar", "fake access rights", d.GetAllocator());
  d.AddMember("nb", nb, d.GetAllocator());
  d.AddMember("na", na, d.GetAllocator());
  d.AddMember("si", "fake inner sig........................................56", d.GetAllocator());

  
  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  d.Accept(writer);

  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname("sha256");
  if(md == 0) {
    printf("Unknown message digest\n");
    return 1;
  }
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, buffer.GetString(), buffer.GetSize());
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  buf_len = ECDSA_size(eckey);
  printf("key size: %d\n", buf_len);
  sig = (unsigned char*) OPENSSL_malloc(buf_len);

  if (ECDSA_sign(0, md_value, md_len, sig, &buf_len, eckey) == 0) {
    printf("Signing failed\n");
    return 1;
  }

  printf("digest: ");
  dump_mem(md_value, md_len);
  
  EC_KEY* key;
  key = EC_KEY_new_by_curve_name(NID_X9_62_prime192v3);
  if(!key) {
    printf("verify_outer_sig: Failed to create key\n");
    exit(1);
  }
  printf("DEBUG: verify_outer_sig: key created, parsing base64: %s\n",
	 su);
  printf("DEBUG: verify_outer_sig: base64 parsed:\nx : %s\ny : %s\nsetting coordinates...\n", BN_bn2hex(x2), BN_bn2hex(y2));
  EC_KEY_set_public_key_affine_coordinates(key, x2, y2);
  printf("DEBUG: verify_outer_sig: coordinates set...\n");

  int ret = ECDSA_verify(0, md_value, md_len, sig, SIGLEN, key);
  printf("internal verification ret: %d\n", ret);
  if(ret<0) {
    printf("%s\n", ERR_error_string(ERR_peek_last_error(), NULL));
    return 1;
  }
  
  return test_net(buffer.GetString(), sig);
}

int main(){
  return test_sigs();
}

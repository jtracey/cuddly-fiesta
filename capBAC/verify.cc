#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

using namespace rapidjson;

// takes in 56 bytes of base 64 representing two 40 bit EC points,
// puts the values into bn1/2
void base64decode(BIGNUM* bn1, BIGNUM* bn2, const char* in) {
  unsigned char *buf, *bi1, *bi2;
  BIO *bio, *b64;

  buf = (unsigned char*) malloc(40);
  if(!buf) {
    printf("base64decode: buff malloc(40) failed");
    exit(1);
  }
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf((void*) in, 56);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);
  BIO_read(bio, buf, 56);
  BIO_free_all(b64);

  bi1 = buf;
  bi2 = buf+20;
  bn1 = BN_bin2bn(bi1, 20, NULL);
  bn2 = BN_bin2bn(bi2, 20, NULL);
  free(buf);
  if(!bn1 || !bn2) {
    printf("base64decode: BN_new() failure");
    exit(1);
  }
  
  return;
}

bool verify_outer_sig(const char* json, const unsigned char* sig, const char* su) {
  EVP_MD_CTX* mdctx;
  const EVP_MD* md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  int ret;
  EC_KEY* key;
  BIGNUM *x, *y;

  md = EVP_get_digestbyname("sha256");
  if(!md) {
    printf("verify_outser_sig: Unknown message digest");
    exit(1);
  }

  // TODO: decide on a curve here
  key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(!key) {
    printf("verify_outser_sig: Failed to create key");
    exit(1);
  }
  base64decode(x, y, su);
  EC_KEY_set_public_key_affine_coordinates(key, x, y);

  
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, json, strlen(json));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  ret = ECDSA_verify(0, md_value, md_len, sig, 56, key);
  free(key);

  return ret == 1;
}

// TODO: get key
bool verify_inner_sig(Document* d) {
  EVP_MD_CTX* mdctx;
  const EVP_MD* md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  int ret;
  EC_KEY* key;
  char sig64[56];
  ECDSA_SIG *sig;
  
  
  sig = ECDSA_SIG_new();
  base64decode(sig->r, sig->s, (*d)["si"].GetString());
  
  d->EraseMember(d->FindMember("si"));

  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  d->Accept(writer);
  
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, buffer.GetString(), buffer.GetSize());
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  ret = ECDSA_do_verify(md_value, md_len, sig, key);

  ECDSA_SIG_free(sig);
  
  return ret == 1;
}

bool is_valid(Document* d) {
  if((*d)["ii"].GetInt() > (*d)["nb"].GetInt()) return false;
  unsigned int now = time(NULL);
  return now < (*d)["nb"].GetInt() && now > (*d)["na"].GetInt();
}

// TODO: make this return something meaningful
int process_request(const char* json, const unsigned char* sig) {
  Document d;
  d.Parse(json);

  if(! is_valid(&d)) return 1;
  if(! verify_outer_sig(json, sig, d["su"].GetString())) return 1;
  if(! verify_inner_sig(&d)) return 1;

}

int main(){
  return 0;
}

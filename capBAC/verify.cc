#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "verify.h"

// change this to INADDR_ANY if using Shadow or VMs
#define MACHINE_IP inet_addr("127.0.0.1")

using namespace rapidjson;

// takes in 56 bytes of base 64 representing two 40 bit EC points,
// puts the values into bn1/2
void base64decode(BIGNUM* bn1, BIGNUM* bn2, const char* in) {
  unsigned char *buf, *bi1, *bi2;
  BIO *bio, *b64;

  buf = (unsigned char*) malloc(40);
  if(!buf) {
    printf("base64decode: buff malloc(40) failed\n");
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
    printf("base64decode: BN_new() failure\n");
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
    printf("verify_outser_sig: Unknown message digest\n");
    exit(1);
  }

  // TODO: decide on a curve here
  key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(!key) {
    printf("verify_outser_sig: Failed to create key\n");
    exit(1);
  }
  base64decode(x, y, su);
  EC_KEY_set_public_key_affine_coordinates(key, x, y);


  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, json, strlen(json));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  ret = ECDSA_verify(0, md_value, md_len, sig, 40, key);
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

  return 0;
}

int get_json(char* json, int fd) {
  size_t size = 162; // 162 = minimum token size
  int offset;

  json = (char*) realloc(NULL, sizeof(char)*size);
  if(!json) {
    printf("get_json: Failure to realloc\n");
    exit(1);
  }

  offset = -1;
  do {
    offset++;
    if (offset == size) {
      json = (char*) realloc(json, sizeof(char)*(size += 16));
      if(!json) {
	printf("get_json: Failure to realloc\n");
	exit(1);
      }
    }
    if(!read(fd, json+offset, 1)) {
      printf("get_json: EOF encountered\n");
      return 1;
    }
  } while (json[offset] != 0);

  return 0;
}


int listen_nonblock(uint16_t port){
  int soc;

  soc = socket(AF_INET, (SOCK_STREAM | SOCK_NONBLOCK), 0);
  if(soc == -1) {
    printf("listen: Failed to open socket\n");
    exit(1);
  }

  struct sockaddr_in bindAddress;
  memset(&bindAddress, 0, sizeof(bindAddress));
  bindAddress.sin_family = AF_INET;
  bindAddress.sin_addr.s_addr = MACHINE_IP;
  bindAddress.sin_port = htons(port);

  if(bind(soc, (struct sockaddr *) &bindAddress, sizeof(bindAddress)) == -1) {
    printf("listen: Failed to bind\n");
    exit(1);
  }

  if(listen(soc, 100) == -1) {
    printf("listen: Failed to listen\n");
    exit(1);
  }

  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.fd = soc;
  if(epoll_ctl(epoll_create(1), EPOLL_CTL_ADD, soc, &ev)) {
    printf("listen: epoll failure\n");
    exit(1);
  }

  // TODO: do things with epoll events
}


int listen_block(const char* port_s){
  int soc, fd;
  socklen_t peer_addr_size;
  char* json;
  unsigned char sig[40];
  uint16_t port;

  port = strtol(port_s, NULL, 10);

  soc = socket(AF_INET, (SOCK_STREAM), 0);
  if(soc == -1) {
    printf("listen: Failed to open socket\n");
    exit(1);
  }

  struct sockaddr_in bindAddress;
  memset(&bindAddress, 0, sizeof(bindAddress));
  bindAddress.sin_family = AF_INET;
  bindAddress.sin_addr.s_addr = MACHINE_IP;
  bindAddress.sin_port = htons(port);

  if(bind(soc, (struct sockaddr *) &bindAddress, sizeof(bindAddress)) == -1) {
    printf("listen: Failed to bind\n");
    exit(1);
  }

  if(listen(soc, 5) == -1) {
    printf("listen: Failed to listen\n");
    exit(1);
  }

  struct sockaddr_in retAddress;
  peer_addr_size = sizeof(struct sockaddr_in);
  while(true) {
    fd = accept(soc, (struct sockaddr *) &retAddress, &peer_addr_size);
    if( fd == -1) {
      printf("listen: Failed to accept\n");
      exit(1);
    }

    // TODO: do something smart when these fail
    get_json(json, fd);

    if(read(fd, sig, 40) != 40) {
      printf("listen: EOF in sig encountered\n");
    }
    if(process_request(json, sig) == 0)
      printf("request processed");
    else printf("process request failure");
  }
}

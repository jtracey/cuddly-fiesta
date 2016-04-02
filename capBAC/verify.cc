#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include <string>
#include <unordered_map>
#include <utility>

#include <sys/epoll.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "verify.h"
#include "base64.h"

//#define DEBUG 1

// change this to INADDR_ANY if using Shadow or VMs
// although listen_nonblock needs to be finished first for Shadow
#define MACHINE_IP inet_addr("127.0.0.1")

using namespace rapidjson;

typedef std::unordered_map<std::string, std::string> token_store;

bool verify_outer_sig(const char* json, const unsigned char* sig, int sig_len, char* su) {
  EVP_MD_CTX* mdctx;
  const EVP_MD* md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  int ret;
  EC_KEY* key;
  BIGNUM *x, *y;

  // TODO: decide on a curve here
  key = EC_KEY_new_by_curve_name(NID_X9_62_prime192v3);
  if(!key) {
    printf("verify_outer_sig: Failed to create key\n");
    exit(1);
  }
#ifdef DEBUG
  printf("DEBUG: verify_outer_sig: key created, parsing base64...\n");
#endif
  x  = BN_new();
  y  = BN_new();
  if(!x || !y) {
    printf("base64decode: BN_new() failure\n");
    exit(1);
  }
  base64decode(x, y, su);
#ifdef DEBUG
  printf("DEBUG: verify_outer_sig: base64 parsed:\nx : %s\ny : %s\nsetting coordinates...\n", BN_bn2hex(x), BN_bn2hex(y));
#endif
  EC_KEY_set_public_key_affine_coordinates(key, x, y);
#ifdef DEBUG
  printf("DEBUG: verify_outer_sig: coordinates set, preparing digest...\n");
#endif

  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname("sha256");
  if(!md) {
    printf("verify_outer_sig: Unknown message digest\n");
    exit(1);
  }

  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, json, strlen(json));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

#ifdef DEBUG
  printf("DEBUG: verify_outer_sig: digest created, verifying sig...\n");
#endif

  ret = ECDSA_verify(0, md_value, md_len, sig, sig_len, key);

#ifdef DEBUG
  printf("DEBUG: verify_outer_sig: outer verification complete...\n");
  printf("digest: ");
  dump_mem(md_value, md_len);
  BN_CTX *ctx;
  ctx = BN_CTX_new();
  if(!ctx) {
    printf("failed to create bn ctx\n");
    return 1;
  }
  EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key),
				      EC_KEY_get0_public_key(key),
				      x, y, ctx);
  BN_CTX_free(ctx);
  printf("x : %s\ny : %s\n",
	 BN_bn2hex(x), BN_bn2hex(y));
#endif

  free(key);
  return ret == 1;
}


// TODO: get key
bool verify_inner_sig(Document* d, EC_KEY* keys[]) {
  EVP_MD_CTX* mdctx;
  const EVP_MD* md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  int ret;
  EC_KEY* key;
  char sig64[B64SIZE];
  ECDSA_SIG *sig;

  strncpy(sig64, (*d)["si"].GetString(), B64SIZE);

  sig = ECDSA_SIG_new();
  base64decode(sig->r, sig->s, sig64);

  d->EraseMember(d->FindMember("si"));

  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  d->Accept(writer);

  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname("sha256");
  if(!md) {
    printf("verify_inner_sig: Unknown message digest\n");
    exit(1);
  }
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, buffer.GetString(), buffer.GetSize());
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  ret = ECDSA_do_verify(md_value, md_len, sig, keys[0]);

#ifdef DEBUG
  printf("inner verify is verifying: %s\n", buffer.GetString());
  printf("inner digest: ");
  dump_mem(md_value, md_len);
  printf("inner sig: %s, %s\n", BN_bn2hex(sig->r), BN_bn2hex(sig->s));
#endif

  ECDSA_SIG_free(sig);
  return ret == 1;
}


bool is_valid(Document* d) {
  const char* fields[9] = {"id", "ii", "is", "su",
			   "de","si", "ar", "nb", "na"};
#ifdef DEBUG
  printf("checking validity\n");
  bool ret = false;
  for(int i=0; i < 9; i++) {
    if(!d->HasMember(fields[i])) {
      printf("missing \"%s\" field\n", fields[i]);
      ret = true;
    }
  }
  if(ret) return false;
#else
  for(int i=0; i < 9; i++) {
    if(!d->HasMember(fields[i])) {
      return false;
    }
  }
#endif

  if((*d)["ii"].GetInt() > (*d)["nb"].GetInt()) {
#ifdef DEBUG
    printf("DEBUG: invalid timing: ii > nb (%d > %d)\n",
	   (*d)["ii"].GetInt(), (*d)["nb"].GetInt());
#endif
    return false;
  }
  unsigned int now = time(NULL);
  if(now < (*d)["nb"].GetInt() || now > (*d)["na"].GetInt()) {
#ifdef DEBUG
    printf("DEBUG: invalid timing: %d, %d, %d (nb, na, now)\n",
	   (*d)["nb"].GetInt(), (*d)["na"].GetInt(), now);
#endif
    return false;
  }
  return true;
}


// TODO: make this return something meaningful
int process_request(const char* json, const unsigned char* sig, int sig_len, EC_KEY* authority_keys[]) {
#ifdef DEBUG
  printf("DEBUG: processing request...\n");
#endif
  Document d;
  if(d.Parse(json).HasParseError()){
    printf("invalid json: %s\n", json);
    return 1;
  }
#ifdef DEBUG
  printf("DEBUG: json parsed, checking validity...\n");
#endif
  if(! is_valid(&d)) return 1;
#ifdef DEBUG
  printf("DEBUG: valid token, verifying signatures...\n");
#endif
  char su[B64SIZE];
  strncpy(su, d["su"].GetString(), B64SIZE);
  if(! verify_outer_sig(json, sig, sig_len, su)) return 1;
#ifdef DEBUG
  printf("DEBUG: outer sig verified...\n");
#endif
  if(! verify_inner_sig(&d, authority_keys)) return 1;
#ifdef DEBUG
  printf("DEBUG: signatures verified.\n");
#endif

  return 0;
}

unsigned char mode2_process(char record[17], token_store* capabilities, EC_KEY* authority_keys[]){
  #ifdef DEBUG
  printf("DEBUG: processing request, parsing request...\n");
  #endif
  Document d;
  token_store::const_iterator it = capabilities->find(record);
  if(it == capabilities->end()) return 1;
  std::string record_s = capabilities->at(std::string(record));
  if(d.Parse(record_s.c_str()).HasParseError()){
    printf("invalid json: %s\n", record_s.c_str());
    return 1;
  }
  #ifdef DEBUG
  printf("DEBUG: json parsed, checking validity...\n");
  #endif
  if(!is_valid(&d)) {
    capabilities->erase(it);
    return 1;
  }
  #ifdef DEBUG
  printf("DEBUG: request valid\n");
  #endif
  return 0;
}


char* get_json(int fd) {
  char* json;
  size_t size = TOKENSIZE;
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
    if(read(fd, json+offset, 1) <= 0) {
      printf("get_json: EOF encountered\n");
#ifdef DEBUG
      char c = json[offset];
      json[offset] = 0;
      printf("story so far (%d): %s%c\n", offset, json, c);
#endif
      exit(1);
    }
  } while (json[offset] != 0);

#ifdef DEBUG
  printf("DEBUG: get_json: json at %p: %s\n", json, json);
#endif
  return json;
}

unsigned char store_token(char* json, token_store* capabilities, EC_KEY* authority_keys[]) {
  Document d;
  if(d.Parse(json).HasParseError()){
    printf("invalid json: %s\n", json);
    return 1;
  }

  std::pair <token_store::const_iterator, bool> result;
  std::string id;

  if(! is_valid(&d)) return 1;
  if(! verify_inner_sig(&d, authority_keys)) return 1;

  id = d["id"].GetString();

  result = capabilities->insert(std::make_pair(id, std::string(json)));
  if(!result.second) {
    capabilities->at(id) = std::string(json);
    printf("replacing capability %s\n", id.c_str());
  }

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


int listen_block1(int soc, EC_KEY* authority_keys[]){
  int fd, sig_len;
  socklen_t peer_addr_size = sizeof(struct sockaddr_in);
  char* json;
  unsigned char sig[SIGLEN];
  unsigned char response;
  struct sockaddr_in retAddress;

#ifdef DEBUG
  printf("DEBUG: entering network loop\n");
#endif
  while(true) {
#ifdef DEBUG
    printf("DEBUG: network loop: accepting connection...\n");
#endif
    fd = accept(soc, (struct sockaddr *) &retAddress, &peer_addr_size);
    if( fd == -1) {
      printf("listen: Failed to accept\n");
      exit(1);
    }

    // TODO: do something smart when these fail
#ifdef DEBUG
    printf("DEBUG: network loop: connection accepted, getting json...\n");
#endif
    json = get_json(fd);
#ifdef DEBUG
    printf("DEBUG: network loop: json recieved, getting sig...\n");
#endif
    sig_len = read(fd, sig, SIGLEN);

#ifdef DEBUG
    printf("DEBUG: sig recieved, readying process request: %p, %p\n", json, sig);
#endif
    response = process_request(json, sig, sig_len, authority_keys);
    if(response == 0) {
      printf("request processed\n");
    }
    else {
      printf("request denied\n");
    }
    if(write(fd, &response, 1) <= 0) {
      printf("network loop: failed to write to socket\n");
      exit(1);
    }
  }
}

int listen_block2(int soc, EC_KEY* authority_keys[]){
  int fd, sig_len;
  socklen_t peer_addr_size = sizeof(struct sockaddr_in);
  char record[17];
  char* json;
  token_store capabilities;
  unsigned char response;
  struct sockaddr_in retAddress;

#ifdef DEBUG
  printf("DEBUG: entering network loop\n");
#endif
  while(true) {
#ifdef DEBUG
    printf("DEBUG: network loop: accepting connection...\n");
#endif
    fd = accept(soc, (struct sockaddr *) &retAddress, &peer_addr_size);
    if( fd == -1) {
      printf("listen: Failed to accept\n");
      exit(1);
    }

    // TODO: do something smart when these fail
#ifdef DEBUG
    printf("DEBUG: network loop: connection accepted, getting record value...\n");
#endif
    if(read(fd, record, 17) <= 0) {
      printf("network loop: failed to read record value\n");
      exit(1);
    }
    record[16] = (char) 0;
#ifdef DEBUG
    printf("DEBUG: network loop: record value recieved\n");
#endif
    if(!strcmp(record, "")) {
#ifdef DEBUG
      printf("DEBUG: network loop: record is null, getting json...\n");
#endif
      json = get_json(fd);
      #ifdef DEBUG
      printf("DEBUG: network loop: json recieved, readying token store...\n");
      #endif
      response = store_token(json, &capabilities, authority_keys);
      if(response == 0) {
	printf("capability stored\n");
      }
      else {
	printf("capability invalid\n");
      }
      if(write(fd, &response, 1) <= 0) {
	printf("network loop: failed to write to socket\n");
	exit(1);
      }
    }
    else {
      response = mode2_process(record, &capabilities, authority_keys);
      if(response == 0) {
	printf("request processed\n");
      }
      else {
	printf("request denied\n");
      }
      if(write(fd, &response, 1) <= 0) {
	printf("network loop: failed to write to socket\n");
	exit(1);
      }
    }
  }
}

int bootstrap_network(const char* port_s) {
  int soc, fd;
  uint16_t port;
  struct sockaddr_in bindAddress;

  port = strtol(port_s, NULL, 10);
  soc = socket(AF_INET, SOCK_STREAM, 0);
  if(soc == -1) {
    printf("bootstrap: Failed to open socket\n");
    exit(1);
  }


  memset(&bindAddress, 0, sizeof(bindAddress));
  bindAddress.sin_family = AF_INET;
  bindAddress.sin_addr.s_addr = MACHINE_IP;
  bindAddress.sin_port = htons(port);

  if(bind(soc, (struct sockaddr *) &bindAddress, sizeof(bindAddress)) == -1) {
    printf("bootstrap: Failed to bind\n");
    exit(1);
  }

  if(listen(soc, 5) == -1) {
    printf("bootstrap: Failed to listen\n");
    exit(1);
  }

  return soc;
}

EC_KEY** get_auth_keys() {
  int auth_key_count = 1;
  EC_KEY** authority_keys;
  EC_POINT* point_buffer;
  BN_CTX *ctx;

  ctx = BN_CTX_new();
  if(!ctx) {
    printf("bootstrap: failed to create bn ctx\n");
    exit(1);
  }

  authority_keys = (EC_KEY**) malloc(auth_key_count * sizeof(EC_KEY*));
  for(int i = 0; i < auth_key_count; i++) {
    authority_keys[i]= EC_KEY_new_by_curve_name(NID_X9_62_prime192v3);
    if (authority_keys[i] == NULL) {
      printf("bootstrap: failed to initialize curve %d\n", i);
      exit(1);
    }
  }

  //const char private_key[] = "F2506E09D4153EED5ACBE1D620C93CA0D5580EF41AC0A401";
  const char public_key[] = "027134EE605CB10FAE017BDD9FD88C96C8C080F08271637BB1";
  EC_KEY_set_public_key(authority_keys[0],
			EC_POINT_hex2point(EC_KEY_get0_group(authority_keys[0]),
					   public_key, NULL, ctx));
  BN_CTX_free(ctx);

  return authority_keys;
}

void verify_run_mode(const char* argv[]) {
  EC_KEY** auth_keys = get_auth_keys();
  int soc = bootstrap_network(argv[3]);

  if(!strcmp(argv[2], "1"))
    listen_block1(soc, auth_keys);
  else if(!strcmp(argv[2], "2"))
    listen_block2(soc, auth_keys);
  else {
    printf("Invalid mode: %s", argv[2]);
    exit(1);
  }
}

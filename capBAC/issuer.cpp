#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <sstream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "base64.h"
#define B64SIZE 64
using namespace std;
using namespace rapidjson;

#define MACHINE_IP  inet_addr("127.0.0.1")
#define PORT_SUBJECT  52933 

vector<string> split(string str, char delimiter) {
  vector<string> internal;
  stringstream ss(str); 
  string tok;
  
  while(getline(ss, tok, delimiter)) {
    internal.push_back(tok);
  }
  
  return internal;
}

int create_connection(){
    
    int soc,response_length,n;
	char *response;
	uint16_t port = PORT_SUBJECT;

	soc = socket(AF_INET, SOCK_STREAM, 0);
	if (soc == -1)	{
		printf("Socket Failed\n");
		return 1;
	}

	struct sockaddr_in connectAddress;
	memset(&connectAddress, 0, sizeof(connectAddress));
	connectAddress.sin_family = AF_INET;
	connectAddress.sin_addr.s_addr = MACHINE_IP;
	connectAddress.sin_port = htons(port);
    
   /* if(connect(soc, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) < 0) {
    printf("failed to connect: %s\n", strerror(errno));
    return 1;
    }

         
    if(read(soc, &response, 1) < 0) {
    printf("failed to read from socket\n");
    return 1;
    }*/ //once socket connects

    printf("response: %s\n", response);
}


//////////////////////////
int sign(Document* d) {
      const char private_key[] = "F2506E09D4153EED5ACBE1D620C93CA0D5580EF41AC0A401";
      const char public_key[] = "027134EE605CB10FAE017BDD9FD88C96C8C080F08271637BB1";
      ECDSA_SIG *sig;
      char sig_str[B64SIZE];
      BN_CTX *ctx;
      BIGNUM *a;
      EVP_MD_CTX* mdctx;
      const EVP_MD* md;
      unsigned char md_value[EVP_MAX_MD_SIZE];
      unsigned int md_len, buf_len;
      EC_KEY* auth_key;
      Value si;

      ctx = BN_CTX_new();
      if(!ctx) {
        printf("failed to create bn ctx\n");
        return 1;
      }

      auth_key = EC_KEY_new_by_curve_name(NID_X9_62_prime192v3);
      if (auth_key == NULL) {
          printf("failed to initialize curve\n");
          return 1;
      }

      EC_KEY_set_public_key(auth_key,
			    EC_POINT_hex2point(EC_KEY_get0_group(auth_key),
					       public_key, NULL, ctx));
      a = BN_new();
      BN_hex2bn(&a, private_key);
      EC_KEY_set_private_key(auth_key, a);
      BN_CTX_free(ctx);

      StringBuffer buffer;
      Writer<StringBuffer> writer(buffer);
      d->Accept(writer);

      printf("sig is signing: %s\n", buffer.GetString());

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

      printf("digest: ");
      dump_mem(md_value, md_len);

      buf_len = ECDSA_size(auth_key);

      sig = ECDSA_do_sign(md_value, md_len, auth_key);

      if (sig == NULL) {
        printf("Signing failed\n");
        return 1;
      }

      base64encode(sig_str, sig->r, sig->s);
      si.SetString(sig_str, B64SIZE, d->GetAllocator());
      d->AddMember("si", si, d->GetAllocator());


      printf("sig: %s, %s\n", BN_bn2hex(sig->r), BN_bn2hex(sig->s));

      return 0;
}
/////////////////////////


int process_request(){


	//get public key, resource address from create_connection() response
    
    //vector<string> sep = split(response, '\n');       //once socket connects
	
    string message = "key\nadd";
    vector<string> sep = split(message, '\n');
	const char * pub_key = sep[0].c_str();
    const char * res_add = sep[1].c_str();

    cout << "public key (hex): " << pub_key << "\n";
    cout << "resource address: " << res_add << "\n";
    
    
    //hex to bn for public key
    pub_key = "027134EE605CB10FAE017BDD9FD88C96C8C080F08271637BB1"; //dummy value
    
    BIGNUM *bn1 = BN_new();
    BN_hex2bn(&bn1,pub_key);
    cout << &bn1 << "BN new\n";
    
    
    //add data to json
   // const char* fields[9] = {"id", "ii", "is", "su",
    //			   "de","si", "ar", "nb", "na"};
	
	Document d;
	Value ii, nb, na, suv;
   // d.Parse(json);
		   
    d.Parse("{}");

    suv.SetString(bn1, B64SIZE, d.GetAllocator());

    ii.SetInt(now);
    nb.SetInt(now);
    na.SetInt(1600000000); 


    d.AddMember("id", "fake identifier", d.GetAllocator());
    d.AddMember("ii", ii, d.GetAllocator());
    d.AddMember("is", "fake issuer", d.GetAllocator());
    d.AddMember("su", bn1, d.GetAllocator());
    d.AddMember("de", res_add, d.GetAllocator());
    d.AddMember("ar", "fake access rights", d.GetAllocator());
    d.AddMember("nb", nb, d.GetAllocator());
    d.AddMember("na", na, d.GetAllocator());
   
    sign(&d);
    
        
}

int main(int argc, char *argv[])
{
    //create_connection();
    process_request();
    
    
}

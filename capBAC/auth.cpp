#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <vector>
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



using namespace std;
using namespace rapidjson;

#define MACHINE_IP  inet_addr("127.0.0.1")

vector<string> split(string str, char delimiter) {
	vector<string> internal;
	stringstream ss(str);
	string tok;

	while(getline(ss, tok, delimiter)) {
		internal.push_back(tok);
	}	

	return internal;
}

int sign(Document* d)
{

	const char private_key[] = "F2506E09D4153EED5ACBE1D620C93CA0D5580EF41AC0A401";
	const char pub_key[] = "027134EE605CB10FAE017BDD9FD88C96C8C080F08271637BB1";

	ECDSA_SIG *sig;
	char sig_str[B64SIZE];
	BN_CTX *ctx;
	BIGNUM *a;
	EVP_MD_CTX* mdctx;
	const EVP_MD* md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	EC_KEY* auth_key;
	Value si;


	auth_key = EC_KEY_new_by_curve_name(NID_X9_62_prime192v3);
	if (auth_key == NULL) {
		printf("failed to initialize curve\n");
		return 1;
  	}


	ctx = BN_CTX_new();
	if(!ctx) {
		printf("failed to create bn ctx\n");
		return 1;
  	}
	
	EC_KEY_set_public_key(auth_key,
	EC_POINT_hex2point(EC_KEY_get0_group(auth_key),pub_key, NULL, ctx));
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

//////////////////////////////////////////////////////////////////////////////////////

int get_request(int fd, int choice, const char* port_mode) {
 
          char* message;
          size_t size = TOKENSIZE;
          int offset;
         

          // step 1: read request from client, common for both mode1 and mode2
         
          message = (char*) realloc(NULL, sizeof(char)*size);
          if(!message) {
            printf("get_request: Failure to realloc\n");
            exit(1);
          }

          offset = -1;
          do {
                offset++;
                if (offset == size) {
                        
                        message = (char*) realloc(message, sizeof(char)*(size += 16)); 
                        if(!message) {
                            printf("get_request: Failure to realloc\n");
	                        exit(1);
                        }
                    }
            
                if(read(fd, message+offset, 1) <= 0) {
                        printf("get_request: EOF encountered\n");
                        char c = message[offset];
                        message[offset] = 0;
                        printf("story so far (%d): %s%c\n", offset, message, c);
                        exit(1);
                }
          } while (message[offset] != 0);


            printf("get_request: message at %p: %s\n", message, message);
          
	        vector<string> sep = split(message, '\n');
	        const char * pub_key = sep[0].c_str();
	        const char * res_add = sep[1].c_str();

	        cout << "public key (b64): " << pub_key << "\n";
	        cout << "resource address: " << res_add << "\n";

            // step 2: create token 'd', common for both mode1 and mode2 
	        Document d;
	        Value ii, nb, na, suv, dev,id;
            unsigned int now;

	        d.Parse("{}");

	        now = time(NULL);
	        ii.SetInt(now);
	        nb.SetInt(now);
	        na.SetInt(1600000000);

            //random 16 byte ID 
            char id_buffer[17] ;
            int j;
            srand(time(NULL));
            for (j = 0; j < 16; j++) {
//                itoa(rand()%10, id_buffer+j,10);
//                  snprintf(id_buffer+j, 1, "%d", rand()%10);

                   id_buffer[j] = 'A' + random()%24;

            }
             id_buffer[j] = '\0';
            
            cout << " id_buffer" <<  id_buffer << "\n";
            
            
            char const * id_buf2 = (char const *)id_buffer;
            
            id.SetString(id_buffer, strlen(id_buffer), d.GetAllocator());

	        suv.SetString(pub_key, strlen(pub_key), d.GetAllocator());
	        dev.SetString(res_add, strlen(res_add), d.GetAllocator());

	        d.AddMember("id", id, d.GetAllocator());
	        d.AddMember("ii", ii, d.GetAllocator());
	        d.AddMember("is", "fake issuer", d.GetAllocator());
	        d.AddMember("su", suv, d.GetAllocator());
	        d.AddMember("de", dev, d.GetAllocator());
	        d.AddMember("ar", "fake access rights", d.GetAllocator());
	        d.AddMember("nb", nb, d.GetAllocator());
	        d.AddMember("na", na, d.GetAllocator());

	        sign(&d);

	        // Step 3: Mode choice dependent
	        // (Mode 1, return token to client)
	        if (choice == 1) {
		        StringBuffer buffer;
		        Writer<StringBuffer> writer(buffer);
	            d.Accept(writer);

                cout << "buffer data : " << buffer.GetString();
		        cout << "\n buffer len:" << buffer.GetSize();

                if(write(fd, buffer.GetString(), buffer.GetSize()+1) < 0) {
                    printf("Failed to write to socket\n");
              	}
                return 1;	       
	        }
          
         
	        // (Mode 2, return token to resource, token ID to client)

	        else if(choice == 2 ){
          
		const char *res_port = sep[2].c_str();
                cout << "Mode 2\n";
		cout << "resource PORT:" << res_port << endl;
                int soc2;
                uint16_t port = strtol(res_port, NULL, 10);
                char null_string[17];

                soc2 = socket(AF_INET, SOCK_STREAM, 0);
                if(soc2 < 0) {
	                printf("failed to create socket: %s\n", strerror(errno));
                }

                struct sockaddr_in connectAddress;
                memset(&connectAddress, 0, sizeof(connectAddress));
                connectAddress.sin_family = AF_INET;
                connectAddress.sin_addr.s_addr = MACHINE_IP;
                connectAddress.sin_port = htons(port);

                if(connect(soc2, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) < 0) {
		                printf("send token to resource: failed to connect to resource: %s\n", strerror(errno));
                }


		        // insert code for null string here
               	int i;
                
		        // add 17 NULLS before sending the json to resource -- one socket
                for (i = 0; i <=17; i++){
                    null_string[i] = (char) 0;
                } 

                if(write(soc2, null_string, 17) < 0) {
                    printf("Failed to write null string to resource socket\n");
                }

                //send token to resource here
                StringBuffer buffer;
                Writer<StringBuffer> writer(buffer);
                d.Accept(writer);

                cout << "buffer data : "<< buffer.GetString() ;
                cout << "\n buffer len:" << buffer.GetSize() << "\n";

                if(write(soc2, buffer.GetString(), buffer.GetSize()+1) < 0) {
                     printf("Failed to write to token to resource socket\n");        
                }

                //send token ID to client

           

                char const *tokenID_str = d["id"].GetString();
                cout << "string token ID: " << tokenID_str << "\n";

                if(write(fd, tokenID_str, strlen(tokenID_str)+1) < 0) {
             
                     printf("Failed to write to socket\n");
                }

                return 1;
	      }// end of mode 2
}


int bootstrap_network(const char* port_sub){

	int soc;
	uint16_t port = strtol(port_sub, NULL, 10);   // from arguments

	soc = socket(AF_INET, SOCK_STREAM, 0);
	if (soc == -1)	{
		printf("Failed to open socket\n");
		return 1;
  	}

 	struct sockaddr_in connectAddress;
	memset(&connectAddress, 0, sizeof(connectAddress));
	connectAddress.sin_family = AF_INET;
	connectAddress.sin_addr.s_addr = MACHINE_IP;
	connectAddress.sin_port = htons(port);

	if(bind(soc, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) == -1) {
		printf("bootstrap: Failed to bind\n");
		exit(1);
  	}

	if(listen(soc, 5) == -1) {
		printf( "bootstrap: Failed to listen\n");
		exit(1);
  	}

	return soc;
}

int listen_block(int soc,int choice, const char* port_mode){

	int fd;
	socklen_t peer_addr_size = sizeof(struct sockaddr_in);
	struct sockaddr_in retAddress;
    int req1;

	printf("DEBUG: entering network loop\n");
	
	while(true) {
		printf("DEBUG: network loop: accepting connection...\n");
		fd = accept(soc, (struct sockaddr *) &retAddress, &peer_addr_size);
		printf("fd value: %d\n",fd);
		if( fd == -1) {
			printf("listen: Failed to accept: %s\n", strerror(errno));
			exit(1);
    		}
		
		printf( "DEBUG: network loop: connection accepted, getting request from subject...\n");
    
		req1 = get_request(fd,choice,port_mode);
		close(fd);
	}

}
  	
int main(int argc, char *argv[]){

	if(argc <= 3){
		printf("insufficient arguments\n");
		printf("sample argument: ./auth <mode> <port_client> <port_resource>\n {Enter dummy value for port_resource in Mode 1}");
		return 1;
  	}
  
	int fd1, soc1;
  	soc1 = bootstrap_network(argv[2]);
	
	const char* port_client = argv[2];
	const char* port_resource = argv[3];

  	if(!strcmp(argv[1], "1"))
		listen_block(soc1,1,port_resource);
  
    	else if(!strcmp(argv[1], "2"))
		listen_block(soc1,2,port_resource);
  
	else{
		printf("Invalid mode: %s", argv[1]);
		exit(1);
  	}

	return 1;
}

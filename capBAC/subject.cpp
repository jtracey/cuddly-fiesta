#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <sstream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "base64.h"

using namespace std;
using namespace rapidjson;


std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
	std::vector<std::string> elems;
	split(s, delim, elems);
	return elems;
}

int create_keypair(const char * client_name)
{
	
	EC_KEY *ec_key = EC_KEY_new();
	EC_GROUP* ec_group_new = EC_GROUP_new_by_curve_name(NID_X9_62_prime192v3);
	const EC_GROUP *ec_group = ec_group_new;
	if(!EC_KEY_set_group(ec_key,ec_group))	{
		printf("EC_KEY_set_group Error");
		return 1;
	}
	if(!EC_KEY_generate_key(ec_key)) {
		printf("Generatekey Error");
		return 1;
	}

	FILE *keys = fopen(client_name,"w"); 	
	

	//Save Private Key to File
	const BIGNUM *private_key = EC_KEY_get0_private_key(ec_key);
	char *priv_hex = BN_bn2hex(private_key);
	printf("%s\n",priv_hex);
	fwrite(priv_hex,sizeof(char),strlen(priv_hex),keys);
	fwrite("\n", sizeof(char) ,1,keys);	

	//Save Public Key to file
	const EC_POINT *public_key = EC_KEY_get0_public_key(ec_key);
	BIGNUM *pub_key;
	point_conversion_form_t form = EC_GROUP_get_point_conversion_form(ec_group);
	BN_CTX *ctx;
	ctx = BN_CTX_new();
	char *pub_hex = EC_POINT_point2hex(ec_group, public_key, form, ctx);
	printf("%s\n",pub_hex);		
	fwrite(pub_hex,sizeof(char),strlen(pub_hex),keys);

	// TO-DO FREE RELATED Contexts
	fclose(keys);
	return 0;
}

int read_keypair(const char* client_name, EC_KEY **ec_key)
{	
	*ec_key = EC_KEY_new();
	EC_GROUP* ec_group_new = EC_GROUP_new_by_curve_name(NID_X9_62_prime192v3);
	const EC_GROUP *ec_group = ec_group_new;
	if(!EC_KEY_set_group(*ec_key,ec_group))
		printf("EC_KEY_set_group Error");
	BIGNUM *private_key_bn;
	EC_POINT *public_key_point;
	BN_CTX *ctx;
	
	FILE *keys = fopen(client_name,"r"); 	
	size_t len_pub = 0, len_priv = 0;
	char *private_key = NULL;
	getline(&private_key, &len_priv, keys);
	
	char *public_key = NULL;
	getline(&public_key, &len_pub, keys);
	ctx = BN_CTX_new();
	private_key_bn = BN_new();
	if(!BN_hex2bn(&private_key_bn, private_key))
		printf("Hex2BN failed");
	EC_KEY_set_private_key(*ec_key,private_key_bn);

	EC_KEY_set_public_key(	*ec_key, 
				EC_POINT_hex2point(EC_KEY_get0_group(*ec_key),public_key, NULL,ctx));
	
	/* VIEW KEYS :
	cout << len_priv << " : " << private_key;
	cout << len_pub << " : " << public_key;	
	*/

	return 0;
}	

int sign_token(const char *token_file , EC_KEY **ec_key)
{
	unsigned char *sig;
	const EVP_MD* md;
	EVP_MD_CTX* mdctx;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, buf_len;

	FILE *sign_file = fopen(token_file, "r");
	fseek (sign_file, 0, SEEK_END);
	size_t srclen = ftell(sign_file);
	fseek(sign_file, 0, SEEK_SET);	
	
	char *source = (char*) malloc(srclen);
	fread(source, sizeof(char), srclen, sign_file);
	cout << source; 

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("sha256");
	if(md == 0) {
		printf("Unknown Message Digest\n");
		return 1;
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
  	EVP_DigestUpdate(mdctx, source, srclen);
 	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  	EVP_MD_CTX_destroy(mdctx);
		
	buf_len = ECDSA_size(*ec_key);
	sig = (unsigned char*) OPENSSL_malloc(buf_len);
	if(! ECDSA_sign(0, md_value, md_len, sig, &buf_len, *ec_key)) {
		printf("Signing Failed \n");
		return 1;
	}
	
	int ret = ECDSA_verify(0, md_value, md_len, sig, buf_len, *ec_key);
	printf("\n Ret : %d \n",ret);

	return 0;
}

int get_token( )
{
	// Network function to get token from Issuer
	return 0;
}

int send_token()
{
	// Network function to send token to Issuer
	return 0;
}
int access_resource( const char * resource_name, EC_KEY **ec_key)
{
	get_token();
	sign_token( resource_name , ec_key);
	send_token();
	return 0;
}

void parse(string buffer)
{
	std::vector<std::string> token_vector;
	token_vector = split(buffer,' ');
	std::vector<std::string>::iterator token_iterator = token_vector.begin();

	// NOTE : No robustness checks in parser, assuming worlkload generation file will ALWAYS be correct.
	while(token_iterator != token_vector.end())	{

		if((*token_iterator).compare("#")==0)
		{
			//Ignore comment line (Note : comment line must have space "# ")
		}
		else if((*token_iterator).compare("creater")==0)
		{
			string resource_name = *(++token_iterator);
			// Create Resource ?
		}
		else if((*token_iterator).compare("createc")==0)
		{
			string client_name = *(++token_iterator);
			create_keypair(client_name.c_str());
		}
		else if((*token_iterator).compare("removec")==0)
		{	
			string client_name = *(++token_iterator);
			//Remove client key files
		}	
		else if((*token_iterator).compare("remover")==0)
		{
			string resource_name = *(++token_iterator);
			//Remove Resource ?
		}
		else if((*token_iterator).compare("access")==0)
		{

			string client_name = *(++token_iterator);
			string resource_name = *(++token_iterator);
			EC_KEY *ec_key;
			read_keypair(client_name.c_str(), &ec_key);
			access_resource(resource_name.c_str(), &ec_key);
		}
		token_iterator++;
	}
}


int main(int argc, char *argv[])
{

	ifstream input_file(argv[1],std::ifstream::binary);
	string buffer;

	while(!input_file.eof())
	{
		getline(input_file, buffer);
		//cout<<buffer<<endl;
		parse(buffer);

	}	


	return 0;
}


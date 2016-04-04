//USAGE : ./name <filename_of_instructions> <PORT_NO_ISSUER> <MODE(1/2)>
//compile with -lcrypto 
//For dump_mem comparison of Digests (uncomment dump_mem and compile with base64.o,cencode.o,cdecode.o) 

/*
TO-DO's :
remove read_keypair
create_keypair
In Mode1_get_token from socket write json to json_message, and remove retrieveing json from file
Remove hard-coded keys 
*/

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
#include <unordered_map>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "base64.h"

using namespace std;
using namespace rapidjson;

#define MACHINE_IP  inet_addr("127.0.0.1")
#define PORT_ISSUER  49151
#define PORT_VERIFIER 49157
#define TOKEN_IDENTIFIER_SIZE 16 

int port_verifier;
int port_issuer;
int run_mode;
typedef unordered_map<string,string> map_tokens;
typedef std::pair<string,string> record;

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


int get_token(const char *resource_name, EC_KEY **ec_key)
{
	int soc,response_length;
	char *response;
	uint16_t port = PORT_ISSUER;

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


	EC_GROUP* ec_group_new = EC_GROUP_new_by_curve_name(NID_X9_62_prime192v3);
	const EC_GROUP *ec_group = ec_group_new;
	const EC_POINT *ec_point = EC_KEY_get0_public_key(*ec_key);
	BIGNUM *public_key;
	point_conversion_form_t form = EC_GROUP_get_point_conversion_form(ec_group);
	BN_CTX *ctx;
	ctx = BN_CTX_new();
	char *pub_hex = EC_POINT_point2hex(ec_group, ec_point, form, ctx);

	//Create Message <Public_Key_in_Hex\nResource_Name>
	char *message;
	message = (char *) malloc(strlen(pub_hex) + strlen(resource_name) + 2);
	strcat(message,pub_hex);
	strcat(message, "\n");
	strcat(message,resource_name);
	printf("MESSAGE: \n%s\n",message);


	if(connect(soc, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) < 0) {
		printf("get_token: failed to connect: %s\n", strerror(errno));
		//return 1;
	}
	/*

	if(write(soc, message, strlen(message)+1) < 0) {
		printf("Failed to write to socket\n");
		//return 1;
	}

	if(read(soc, &response_length, 1) < 0) {
		printf("Failed to read RESPONSE_LENGTH from socket\n");
		//return 1;
	}

	if(read(soc, &response, 1) < 0) {
		printf("Failed to read RESPONSE from socket\n");
		//return 1;
	}
	*/

	close(soc);
	return 0;

}


int send_token(unsigned char **sig, unsigned int *sig_len, char **json_message, size_t *json_length)
{

	int soc,response_length;
	char response;
	uint16_t port = port_verifier;

	soc = socket(AF_INET, SOCK_STREAM, 0);
	if(soc < 0) {
		printf("failed to create socket: %s\n", strerror(errno));
		//return 1;
	}

	struct sockaddr_in connectAddress;
	memset(&connectAddress, 0, sizeof(connectAddress));
	connectAddress.sin_family = AF_INET;
	connectAddress.sin_addr.s_addr = MACHINE_IP;
	connectAddress.sin_port = htons(port);


	//int ret = ECDSA_verify(0, md_value, md_len, *sig, *sig_len, *ec_key);
	//printf("\n Ret : %d \n",ret);

	if(connect(soc, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) < 0) {
		printf("send_token: failed to connect: %s\n", strerror(errno));
		//return 1;
	}

	printf("SEND_TOKEN : %s",*json_message);
	if(write(soc, *json_message, (*json_length)) < 0) {
		printf("Failed to write to socket\n");
		//return 1;
	}

	if(write(soc, *sig, (*sig_len)) < 0) {
		printf("Failed to write to socket\n");
		//return 1;
	}

	if(read(soc, &response, 1) < 0) {
		printf("Failed to read RESPONSE_LENGTH from socket\n");
		//return 1;
	}

	/*
	if(read(soc, &response, 1) < 0) {
		printf("Failed to read RESPONSE from socket\n");
		//return 1;
	}
	*/

	close(soc);
	printf("RESPONSE : %c",response);
	return 0;

}


int create_keypair(const char * client_name, EC_KEY **ec_key)
{

	*ec_key = EC_KEY_new();
	EC_GROUP* ec_group_new = EC_GROUP_new_by_curve_name(NID_X9_62_prime192v3);
	const EC_GROUP *ec_group = ec_group_new;
	if(!EC_KEY_set_group(*ec_key,ec_group))	{
		printf("EC_KEY_set_group Error\n");
		return 1;
	}
	if(!EC_KEY_generate_key(*ec_key)) {
		printf("Generatekey Error\n");
		return 1;
	}

	FILE *keys = fopen(client_name,"w");


	//Save Private Key to File
	const BIGNUM *private_key = EC_KEY_get0_private_key(*ec_key);
	char *priv_hex = BN_bn2hex(private_key);
	printf("%s\n",priv_hex);
	fwrite(priv_hex,sizeof(char),strlen(priv_hex),keys);
	fwrite("\n", sizeof(char) ,1,keys);

	//Save Public Key to file
	const EC_POINT *public_key = EC_KEY_get0_public_key(*ec_key);
	BIGNUM *pub_key;
	point_conversion_form_t form = EC_GROUP_get_point_conversion_form(ec_group);
	BN_CTX *ctx;
	ctx = BN_CTX_new();
	char *pub_hex = EC_POINT_point2hex(ec_group, public_key, POINT_CONVERSION_COMPRESSED, ctx);
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
		printf("EC_KEY_set_group Error\n");
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
		printf("Hex2BN failed\n");
	EC_KEY_set_private_key(*ec_key,private_key_bn);

	EC_KEY_set_public_key(	*ec_key,
			EC_POINT_hex2point(EC_KEY_get0_group(*ec_key),public_key, NULL,ctx));

	/* VIEW KEYS :
	   cout << len_priv << " : " << private_key;
	   cout << len_pub << " : " << public_key;
	 */

	fclose(keys);
	return 0;
}

int sign_token(const char *token_file , EC_KEY **ec_key, unsigned char **sig, unsigned int *sig_len, char **json_message, size_t *json_length)
{
	const EVP_MD* md;
	EVP_MD_CTX* mdctx;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	FILE *sign_file = fopen(token_file, "r");
	fseek (sign_file, 0, SEEK_END);
	*json_length= ftell(sign_file);
	fseek(sign_file, 0, SEEK_SET);

	*json_message = (char*) malloc(*json_length);
	fread(*json_message, sizeof(char), *json_length, sign_file);
	cout <<"Signing : " <<*json_message << endl;
	(*json_message)[*json_length-1] = '\0';

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("sha256");
	if(md == 0) {
		printf("Unknown Message Digest\n");
		return 1;
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, *json_message, (*json_length)-1);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	//dump_mem(md_value, md_len);

	*sig_len = ECDSA_size(*ec_key);
	*sig = (unsigned char*) OPENSSL_malloc(*sig_len);
	if(! ECDSA_sign(0, md_value, md_len, *sig, sig_len, *ec_key)) {
		printf("Signing Failed \n");
		return 1;
	}

	//int ret = ECDSA_verify(0, md_value, md_len, *sig, *sig_len, *ec_key);
	//printf("\n Ret : %d \n",ret);

	fclose(sign_file);
	return 0;
}

int mode1_access_resource( const char *resource_name, EC_KEY **ec_key)
{

	unsigned char *sig;
	unsigned int sig_len;
	char *json_message;
	size_t json_length;

	//Get token_file from get_token() to replace 'dummytoken'
	string token_file("dummytoken");
	get_token(resource_name, ec_key);
	sign_token(token_file.c_str(), ec_key, &sig, &sig_len, &json_message, &json_length);
	send_token(&sig, &sig_len, &json_message, &json_length);
	return 0;
}


int mode2_send_token_identifier(char *token_identifier)
{

	int soc,response_length;
	char response;
	uint16_t port = port_verifier;

	soc = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in connectAddress;
	memset(&connectAddress, 0, sizeof(connectAddress));
	connectAddress.sin_family = AF_INET;
	connectAddress.sin_addr.s_addr = MACHINE_IP;
	connectAddress.sin_port = htons(port);
		
	if(connect(soc, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) < 0) {
		printf("failed to connect: %s\n", strerror(errno));
		//return 1;
	}
	
	printf("SEND_TOKEN_IDENTIFIER: %s", token_identifier);
	if(write(soc, token_identifier, TOKEN_IDENTIFIER_SIZE) < 0) {
		printf("Failed to write to socket\n");
		//return 1;
	}
	
	if(read(soc, &response, 1) < 0) {
		printf("Failed to read RESPONSE_LENGTH from socket\n");
		//return 1;
	}	
	printf("RESPONSE : %c",response);
	return 0;	

}


int mode2_get_token_identifier(const char *resource_name, EC_KEY **ec_key, char *token_identifier )
{	
	int soc,response_length;
	char *response;
	uint16_t port = PORT_ISSUER;

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


	EC_GROUP* ec_group_new = EC_GROUP_new_by_curve_name(NID_X9_62_prime192v3);
	const EC_GROUP *ec_group = ec_group_new;
	const EC_POINT *ec_point = EC_KEY_get0_public_key(*ec_key);
	BIGNUM *public_key;
	point_conversion_form_t form = EC_GROUP_get_point_conversion_form(ec_group);
	BN_CTX *ctx;
	ctx = BN_CTX_new();
	char *pub_hex = EC_POINT_point2hex(ec_group, ec_point, form, ctx);

	//Create Message <Public_Key_in_Hex\nResource_Name>
	char *message;
	message = (char *) malloc(strlen(pub_hex) + strlen(resource_name) + 2);
	strcat(message,pub_hex);
	strcat(message, "\n");
	strcat(message,resource_name);
	printf("MESSAGE: \n%s\n",message);	

		
	if(connect(soc, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) < 0) {
		printf("failed to connect: %s\n", strerror(errno));
		//return 1;
	}
	/*
	if(write(soc, message, strlen(message)+1) < 0) {
		printf("Failed to write to socket\n");
		//return 1;
	}

	if(read(soc, token_identifier, TOKEN_IDENTIFIER_SIZE ) < 0) {
		printf("Failed to read RESPONSE_LENGTH from socket\n");
		//return 1;
	}
	
	record r1 = 
	map_table.insert()
	
	*/

	return 0;
	
}




int mode2_access_resource( const char *resource_name, EC_KEY **ec_key)
{

	char token_identifier[16];
	mode2_get_token_identifier(resource_name, ec_key, token_identifier);
	mode2_send_token_identifier(token_identifier);
	return 0;
}

void parse(string buffer, EC_KEY **ec_key)
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
			create_keypair(client_name.c_str(), ec_key);
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
			port_verifier = atoi(client_name.c_str());
			string resource_name = *(++token_iterator);
			printf("PORT : %d\n", port_verifier);
			read_keypair("FIX_KEY", ec_key);
			if(run_mode == 1)
				mode1_access_resource(resource_name.c_str(), ec_key);
			else if(run_mode == 2)
				mode2_access_resource(resource_name.c_str(), ec_key);
		}
		token_iterator++;
	}
}

int main(int argc, char *argv[])
{

	EC_KEY *ec_key;
	map_tokens token_table; 
	
	ifstream input_file(argv[1],std::ifstream::binary);
	string buffer;

	port_issuer = atoi(argv[2]);
	
	run_mode = atoi(argv[3]);
	

	while(!input_file.eof())
	{
		getline(input_file, buffer);
		//cout<<buffer<<endl;
		parse(buffer, &ec_key);

	}


	return 0;
}

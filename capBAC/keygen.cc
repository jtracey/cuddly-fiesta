#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdio.h>

main() {
  EC_KEY *eckey;
  BN_CTX *ctx;
  
  ctx = BN_CTX_new();
  if(!ctx) {
    printf("failed to create bn ctx\n");
    return 1;
  }
  
  eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime192v3);
  if (eckey == NULL) {
    printf("failed to initialize curve\n");
    return 1;
  }
  if (EC_KEY_generate_key(eckey) == 0) {
    printf("failed to generate key\n");
    return 1;
  }

  printf("private key: %s\n", BN_bn2hex(EC_KEY_get0_private_key(eckey)));
  printf("public key: %s\n",
	 EC_POINT_point2hex(EC_KEY_get0_group(eckey),
			    EC_KEY_get0_public_key(eckey),
			    POINT_CONVERSION_COMPRESSED, ctx));
  BN_CTX_free(ctx);
  return 0;
}

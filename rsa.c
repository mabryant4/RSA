#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

BIGNUM * generatePrivKey(BIGNUM * p, BIGNUM * q, BIGNUM * e, BN_CTX * ctx) {
  BIGNUM * phi = BN_new();
  BIGNUM * pDec = BN_new();
  BIGNUM * qDec = BN_new();
  BIGNUM * dec = BN_new();
  BIGNUM * d = BN_new();

  BN_dec2bn(&dec, "1");
  BN_sub(pDec, p, dec);
  BN_sub(qDec, q, dec);
  BN_mul(phi, pDec, qDec, ctx);

  BN_mod_inverse(d, e, phi, ctx);
  return d;
}

BIGNUM * encrypt(BIGNUM * n, BIGNUM * e, BIGNUM * m, BN_CTX * ctx) {
  BIGNUM * c = BN_new();

  BN_mod_exp(c, m, e, n, ctx);
  return c;
}

char * decrypt(BIGNUM * n, BIGNUM * d, BIGNUM * c, BN_CTX * ctx) {
  BIGNUM * m = BN_new();

  BN_mod_exp(m, c, d, n, ctx);
  char * hexM = BN_bn2hex(m);
  return hexM;
}

BIGNUM * generateSig(BIGNUM * m, BIGNUM * n, BIGNUM * d, BN_CTX * ctx) {
  BIGNUM * s = BN_new();

  BN_mod_exp(s, m, d, n, ctx);
  return s;
}

char * verifySig(BIGNUM * s, BIGNUM * e, BIGNUM * n, BN_CTX * ctx) {
  BIGNUM * m = BN_new();

  BN_mod_exp(m, s, e, n, ctx);
  char * hexM = BN_bn2hex(m);
  return hexM;
}

int verifyCert() {

}

int main() {

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *p = BN_new();
  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BIGNUM *q = BN_new();
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BIGNUM *e = BN_new();
  BN_hex2bn(&e, "0D88C3");

  BIGNUM *n = BN_new();
  BN_mul(n, p, q, ctx);

  BIGNUM *d = BN_new();
  d = generatePrivKey(p,q,e,ctx);
  char * privKey = BN_bn2hex(d);
  printf("Private Key: %s", privKey);

  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&e, "010001");

  BIGNUM *m = BN_new();
  BN_hex2bn(&m, "4D61726C6565427279616E742B3131373936303838");

  BIGNUM *cipher = BN_new();
  cipher = encrypt(n,e,m,ctx);
  char * ciphText = BN_bn2hex(cipher);
  printf("\nCipher Text: %s", ciphText);

  BIGNUM *c = BN_new();
  BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
  char * decMes = decrypt(n,d,c,ctx);
  printf("\nDecrypted Message: %s", decMes);

  BIGNUM *sigM1 = BN_new();
  BIGNUM *sigM2 = BN_new();
  char * sig1hex = "4D61726C6565206F77657320796F75202432303030";
  char * sig2hex = "4D61726C6565206F77657320796F75202433303030";
  BN_hex2bn(&sigM1, sig1hex);
  BN_hex2bn(&sigM2, sig2hex);

  BIGNUM *sig1 = BN_new();
  sig1 = generateSig(sigM1,n,d,ctx);
  BIGNUM *sig2 = BN_new();
  sig2 = generateSig(sigM2,n,d,ctx);
  char * sig1text = BN_bn2hex(sig1);
  printf("\n\nSignature 1: %s", sig1text);
  char * sig2text = BN_bn2hex(sig2);
  printf("\nSignature 2: %s", sig2text);

  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

  BIGNUM *sigTest = BN_new();
  BN_hex2bn(&sigTest, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
  BIGNUM *sigTest2 = BN_new();
  BN_hex2bn(&sigTest2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  char *origM = "4C61756E63682061206D697373696C652E";
  char *sigM = verifySig(sigTest,e,n,ctx);
  char *sigM0 = verifySig(sigTest2,e,n,ctx);

  printf("\n\nSent Message: %s", origM);
  printf("\nMessage from Signature 1: %s", sigM);
  if(strcmp(origM,sigM) == 0)
    printf("\nThis message was sent by Alice.");
  else
    printf("\nThis message was not sent by Alice.");
  printf("\nMessage from Signature 2: %s", sigM0);
  if(strcmp(origM,sigM0) == 0)
    printf("\nThis message was sent by Alice.\n");
  else
    printf("\nThis message was not sent by Alice.\n");

  BN_hex2bn(&n,"D753A40451F899A616484B6727AA9349D039ED0CB0B00087F1672886858C8E63DABCB14038E2D3F5ECA50518B83D3EC5991732EC188CFAF10CA6642185CB071034B052882B1F689BD2B18F12B0B3D2E7881F1FEF387754535F80793F2E1AAAA81E4B2B0DABB763B935B77D14BC594BDF514AD2A1E20CE29082876AAEEAD764D69855E8FDAF1A506C54BC11F2FD4AF29DBB7F0EF4D5BE8E16891255D8C07134EEF6DC2DECC48725868DD821E4B04D0C89DC392617DDF6D79485D80421709D6F6FFF5CBA19E145CB5657287E1C0D4157AAB7B827BBB1E4FA2AEF2123751AAD2D9B86358C9C77B573ADD8942DE4F30C9DEEC14E627E17C0719E2CDEF1F910281933");
  BN_hex2bn(&e, "10001");
  BN_hex2bn(&sigTest,"284a2a0d1c48cf004187df13a03f8aaa7c33fca82012694e990c91b13c4433b76b5b82de4e4f092729859cb166c2c9caef837d6e5740ac9902a53a2180d2f20c3f8461e973908ec9f7821b8d4a7a2118612ea70508c4018bbbdff902281c7a52e0942c6429aaf9c5d9aa12d8cdf89b90bb87c9cc2555aacb64e576fb7676ba112f142202a630c3b4928960abe22ec07a2b34b55755e1f49f12d0c4a94721efedc0777c77d8c977c592f83d950ef959ba27c20b09a8c3030299cc329063b4b03b1be3635cce6ebd6ef52b54a958d1c77e68c2ec7fa48925bdf3068f11cd8a5c2f01469860c579d6dccb41c708b1cce139b4858b8ed2e9e558b368e74c1d1d6111");

  char *webSig = verifySig(sigTest,e,n,ctx);
  printf("\nVerify Signature ouput: %s", webSig);
  char *hash = "abb7edf2d755f5472b63c161d2976c6e0e173dde1bdf442572d902a05f4542e3";
  printf("\nHash of Certificate body: %s", hash);
  if(strcmp(webSig,hash) == 0)
    printf("\nThis signature is valid.");
  else
    printf("\nThis signature is not valid.");
  //TASK 6

}

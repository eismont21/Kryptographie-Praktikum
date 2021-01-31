#include <praktikum.h>
#include "protocol.h"

static void prime(mpz_t p){
  unsigned char key[RSA_BITS/16];
  cs_rand_buf(key, sizeof(key));
  key[0] &= ~0x80;
  key[0] |=  0x40;
  mpz_import(p, RSA_BITS/16, 1, 1, 1, 0, key);
  mpz_nextprime(p, p);
}

void genkey(struct rsa_key *k){
  mpz_t p;
  mpz_init(p);
  mpz_t q;
  mpz_init(q);
  mpz_init(k->N);
  mpz_t pm1,qm1,phi;
  mpz_init(pm1);mpz_init(qm1);mpz_init(phi);mpz_init(k->e);mpz_init(k->d);

  while(1){
    prime(p);
    prime(q);
    mpz_mul(k->N, p, q);
    mpz_set_ui(k->e, 65537);
    mpz_sub_ui(pm1, p, 1);
    mpz_sub_ui(qm1, q, 1);
    mpz_mul(phi, pm1, qm1);
    if(mpz_invert(k->d, k->e, phi) == 0) {
    } else {
      break;
    }
  }
  mpz_clear(p);mpz_clear(q);mpz_clear(pm1);mpz_clear(qm1);mpz_clear(phi);
}

void pkcs1_1_5_pad(uint8_t *data, const char *msg){
  data[0] = 0;
  data[1] = 2;
  size_t len = strlen(msg);
  memcpy(data + RSA_BITS/8 - len, msg, len);
  data[RSA_BITS/8 - len-1] = 0;
  cs_rand_buf(data + 2, RSA_BITS/8 - len - 3);
  data[2] = 1;
  for(int i = 2; i < RSA_BITS/8 - len - 1; i++){
    while(data[i] == 0){
      data[i] = cs_rand_byte();
    }
  }
}
uint8_t *pkcs1_1_5_unpad(uint8_t *data){
  if(data[0] != 0 || data[1] != 2) return NULL;
  for(int i = 2; i < 10; i++){
    if(data[i] == 0) return NULL;
  }
  int i = 10;
  while(data[i] != 0 && i < RSA_BITS/8) i++;
  if(i >= RSA_BITS/8){
    return NULL;
  }
  return data + i + 1;
}

void pad_and_import(mpz_t m, const char *msg){
  uint8_t data[RSA_BITS/8 + 1];
  memset(data, 0, sizeof(data));
  pkcs1_1_5_pad(data, msg);
  mpz_import(m, sizeof(data)-1, 1,1,1,0, data);
}

uint8_t *calc_padding_oracle(mpz_t m, uint8_t *target){
  size_t sz = 0;
  uint8_t *out = mpz_export(NULL, &sz, 1, 1, 1, 0, m);
  if(sz > RSA_BITS/8){
    fprintf(stderr, "Too short\n");
    return NULL;
  }
  uint8_t data[RSA_BITS/8 + 1];
  if(target == NULL){
    target = data;
  }
  memset(target, 0, RSA_BITS/8+1);
  memcpy(target + RSA_BITS/8 - sz, out, sz);
  //if(target[0] == 0 && target[1] < 16)
  //  fprintf(stderr, " %s\n",  mpz_get_str(NULL, 16, m));
  uint8_t *unpadded = pkcs1_1_5_unpad(target);
  if(unpadded){
    // fprintf(stderr, "%s\n", unpadded);
    return unpadded;
  }else{
    // fprintf(stderr, "padding invalid\n");
    return NULL;
  }
}

#include "protocol.h"

int ecc_eq(ecc_point a, ecc_point b){
  if(a.inf == 1 && b.inf == 1) return 1;
  return mpz_cmp(a.x, b.x) == 0 && mpz_cmp(a.y, b.y) == 0 && a.inf == 0 && b.inf == 0;
}

void ecc_dbl(ecc_point *to, ecc_point p, mpz_t a, mpz_t mod){
  // Task: Implement double
}

void ecc_add(ecc_point *to, ecc_point p, ecc_point q, mpz_t a, mpz_t mod){
  if(ecc_eq(p, q)){
    ecc_dbl(to, p, a, mod);
    return;
  }
  // Task: Implement add of p and q
}

void ecc_init(ecc_point *p){
  mpz_init(p->x);
  mpz_init(p->y);
  p->inf=0;
}
void ecc_clear(ecc_point *p){
  mpz_clear(p->x);
  mpz_clear(p->y);
}
void ecc_set(ecc_point *p, ecc_point k){
  mpz_set(p->x, k.x);
  mpz_set(p->y, k.y);
  p->inf = k.inf;
}

void ec_print(ecc_point p){
  if(p.inf){
    fprintf(stderr, "p: Infinity\n");
    return;
  }
  fprintf(stderr, "p: x: %s\n", mpz_get_str(NULL, 16, p.x));
  fprintf(stderr, "   y: %s\n", mpz_get_str(NULL, 16, p.y));
}

aeskey aeskey_from_ec(ecc_point kpn){
  uint8_t data[VAL_SIZE];
  store_mpz(data, sizeof(data), kpn.x);
  if(kpn.inf != 0){
    memset(data, 0, sizeof(data));
  }
  for(int i = 0; i < 16; i++){
    data[VAL_SIZE-16 + i] ^= data[VAL_SIZE - 32 + i];
  }
  return aes_setup(data + VAL_SIZE - 16, 16);
}

void ecc_dbl_and_add(ecc_point *to, ecc_point p, mpz_t k, mpz_t a, mpz_t mod){
  // Task: Implement double-and-add to multiply p with scalar k
}

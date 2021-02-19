#include "protocol.h"

int ecc_eq(ecc_point a, ecc_point b){
  if(a.inf == 1 && b.inf == 1) return 1;
  return mpz_cmp(a.x, b.x) == 0 && mpz_cmp(a.y, b.y) == 0 && a.inf == 0 && b.inf == 0;
}
/**
void ecc_dbl(ecc_point *to, ecc_point p, mpz_t a, mpz_t mod){
    if (p.inf == 1 || mpz_cmp_ui(p.y, 0)) {
        to->inf = 1;
        return;
    }
    //calclulate s
    mpz_t s;
    mpz_t temp;
    mpz_t x;
    mpz_t y;
    mpz_init_set(s, p.x);
    mpz_powm_ui(s, s, 2, mod);
    mpz_mul_ui(s, s, 3);
    mpz_add(s, s, a);
    mpz_init_set(temp, p.y);
    mpz_mul_ui(temp, temp, 2);
    mpz_invert(temp, temp, mod);
    mpz_mul(s, s, temp);
    //calculate x
    mpz_init_set(x, s);
    mpz_mul(x, x, x);
    mpz_mul_ui(temp, p.x, 2);
    mpz_sub(x, x, temp);
    mpz_mod(x, x, mod);
    //calculate y
    mpz_init_set(y, p.x);
    mpz_sub(y, y, x);
    mpz_mul(y, y, s);
    mpz_sub(y, y, p.y);
    mpz_mod(y, y, mod);
    // set to
    mpz_set(to->x, x);
    mpz_set(to->y, y);
    to->inf = 0;
    mpz_clear(temp);
    // Task: Implement double
}

void ecc_add(ecc_point *to, ecc_point p, ecc_point q, mpz_t a, mpz_t mod){
    if(ecc_eq(p, q)){
        ecc_dbl(to, p, a, mod);
        return;
    }
    if (p.inf == 1) {
        ecc_set(to, q);
        return;
    }
    if (q.inf == 1) {
        ecc_set(to, p);
        return;
    }
    if (mpz_cmp(p.x, q.x) == 0) {
        to->inf = 1;
        return;
    }
    //calculate s
    mpz_t s;
    mpz_t temp;
    mpz_t x;
    mpz_t y;
    mpz_init(s);
    mpz_sub(s, p.y, q.y);
    mpz_init(temp);
    mpz_sub(temp, p.x, q.x);
    mpz_invert(temp, temp, mod);
    mpz_mul(s, s, temp);
    //calculate x
    mpz_init_set(x, s);
    mpz_powm_ui(x, x, 2, mod);
    mpz_sub(x, x, p.x);
    mpz_sub(x, x, q.x);
    mpz_mod(x, x, mod);
    //calculate y
    mpz_init(y);
    mpz_sub(y, p.x, x);
    mpz_mul(y, y, s);
    mpz_sub(y, y, p.y);
    mpz_mod(x, x, mod);
    // set to
    mpz_set(to->x, x);
    mpz_set(to->y, y);
    to->inf = 0;
    mpz_clear(temp);
    // Task: Implement add of p and q
}
**/

void ecc_dbl(ecc_point *to, ecc_point p, mpz_t a, mpz_t mod){
    if (p.inf == 1 || mpz_cmp_ui(p.y, 0)) {
        to->inf = 1;
        return;
    }
    //calclulate s
    mpz_t s;
    mpz_t temp;
    mpz_t x;
    mpz_t y;
    mpz_init_set(s, p.x);
    mpz_powm_ui(s, s, 2, mod);
    mpz_mul_ui(s, s, 3);
    mpz_mod(s, s, mod); //added
    mpz_mod(a, a, mod); //added
    mpz_add(s, s, a);
    mpz_mod(s, s, mod); // added
    mpz_init_set(temp, p.y);
    mpz_mul_ui(temp, temp, 2);
    mpz_mod(temp, temp, mod); //added
    mpz_invert(temp, temp, mod);
    mpz_mul(s, s, temp);
    mpz_mod(s, s, mod); // added
    //calculate x
    mpz_init_set(x, s);
    mpz_powm_ui(x, x, 2, mod);
    mpz_mul_ui(temp, p.x, 2);
    mpz_mod(temp, temp, mod); //added
    mpz_sub(x, x, temp);
    mpz_mod(x, x, mod);
    //calculate y
    mpz_init_set(y, p.x);
    mpz_sub(y, y, x);
    mpz_mod(y, y, mod); //added
    mpz_mod(s, s, mod); //added
    mpz_mul(y, y, s);
    mpz_mod(y, y, mod); //added
    mpz_mod(temp, p.y, mod); //added
    mpz_sub(y, y, p.y);
    mpz_mod(y, y, mod);

    // set to
    mpz_set(to->x, x);
    mpz_set(to->y, y);
    to->inf = 0;
    mpz_clear(temp);
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(s);
  // Task: Implement double
}

void ecc_add(ecc_point *to, ecc_point p, ecc_point q, mpz_t a, mpz_t mod){
    if (p.inf == 1) {
        ecc_set(to, q);
        return;
    }
    if (q.inf == 1) {
        ecc_set(to, p);
        return;
    }
    if (mpz_cmp(p.x, q.x) == 0) {
        to->inf = 1;
        return;
    }
    if (ecc_eq(p, q)) {
        ecc_dbl(to, p, a, mod);
        return;
    }
    //calculate s
    mpz_t s;
    mpz_t temp;
    mpz_t x;
    mpz_t y;
    mpz_init(s);
    mpz_sub(s, p.y, q.y);
    mpz_mod(s, s, mod);
    mpz_init(temp);
    mpz_sub(temp, p.x, q.x);
    mpz_mod(temp, temp, mod); //added
    mpz_invert(temp, temp, mod);
    mpz_mul(s, s, temp);
    mpz_mod(s, s, mod);

    //calculate x
    mpz_init_set(x, s);
    mpz_powm_ui(x, x, 2, mod);
    mpz_add(temp, p.x, q.x);
    mpz_mod(temp, temp, mod);
    mpz_sub(x, x, temp);
    mpz_mod(x, x, mod);
    //calculate y
    mpz_init(y);
    mpz_mod(temp, p.x, mod);
    mpz_sub(y, temp, x);
    mpz_mod(y, y, mod); //added
    mpz_mul(y, y, s);
    mpz_mod(y, y, mod); //added
    mpz_mod(temp, p.y, mod);
    mpz_sub(y, y, temp);
    mpz_mod(y, y, mod);

    // set to
    mpz_set(to->x, x);
    mpz_set(to->y, y);
    to->inf = 0;
    mpz_clear(temp);
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

/**
void ecc_dbl_and_add(ecc_point *to, ecc_point p, mpz_t k, mpz_t a, mpz_t mod){
    ecc_point temp;
    ecc_init(&temp);
    temp.inf = 1;
    //ecc_set(&t, p);
    int bits = (int) mpz_sizeinbase(k, 2) - 2;
    int bit = 0;
    //check if bits is -1, (case d=1). If yes, set the base point as solution
    if(bits < 0){
        ecc_set(to, p);
        return;
    }

    for(; bits >= 0; bits--){
        bit = mpz_tstbit(k, bits);
        if (temp.inf != 1) {
            ecc_dbl(&temp, temp, a, mod);
        }
        //point addition
        if(bit == 1){
            ecc_add(&temp, temp, p, a, mod);
        }
    }
    ecc_set(to, temp);

}

**/
/**
void ecc_dbl_and_add(ecc_point *to, ecc_point p, mpz_t k, mpz_t a, mpz_t mod){
    mpz_t r;
    mpz_init(r);
    mpz_t q;
    mpz_init(q);
    mpz_t two;
    mpz_init_set_ui(two, 2);
    if (mpz_cmp_ui(k, 1)==0){
        ecc_set(to, p);
        return;
    }
    mpz_tdiv_qr(q, r, k, two);

    ecc_point twice;
    ecc_init(&twice);
    ecc_dbl(&twice, p, a, mod);
    while (mpz_cmp_ui(q, 0) != 0) {
        ecc_add(to, *to, twice, a, mod);
        mpz_sub_ui(q, q, 1);
    }
    if (mpz_cmp_ui(r, 1) == 0) {
        ecc_add(to, *to, p, a, mod);
    }
    ecc_clear(&twice);
    // Task: Implement double-and-add to multiply p with scalar k
}
 **/

void ecc_dbl_and_add(ecc_point *to, ecc_point p, mpz_t k, mpz_t a, mpz_t mod){
    mpz_t i; mpz_init(i); mpz_set_ui(i, 1);
    ecc_point temp;
    ecc_init(&temp);

    if (mpz_cmp(i, k) == 0) {
        ecc_set(to, p);
        return;
    } else {
        ecc_dbl(&temp, p, a, mod);
        mpz_add_ui(i, i, 1);
    }

    while (mpz_cmp(i, k) != 0) {
        ecc_add(&temp, temp, p, a, mod);
        mpz_add_ui(i, i, 1);
    }
    ecc_set(to, temp);
}
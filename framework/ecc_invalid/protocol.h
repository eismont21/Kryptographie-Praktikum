#include <praktikum.h>

#define VAL_SIZE 224/8

typedef enum {
  MSG_CONN,
  MSG_SOL
} msg_type;

typedef struct {
  uint8_t x[VAL_SIZE];
  uint8_t y[VAL_SIZE];
  uint8_t inf;
} req;

typedef struct {
  uint8_t cipher[32];
} rep;

typedef struct {
  uint8_t key[VAL_SIZE];
} sol;

typedef struct {
  uint8_t state;
} sol_rep;


typedef struct {
  mpz_t x;
  mpz_t y;
  int inf;
} ecc_point;

// Return 1 if a and b are equal and 0 otherwise
int ecc_eq(ecc_point a, ecc_point b);
// Double the point p on the curve defined by a and mod and store the result in to
void ecc_dbl(ecc_point *to, ecc_point p, mpz_t a, mpz_t mod);
// Add two (possibly same) points p and q on the curve defined by a and mod and store the result in to
void ecc_add(ecc_point *to, ecc_point p, ecc_point q, mpz_t a, mpz_t mod);
// init the ecc_point struct pointed to by p
void ecc_init(ecc_point *p);
// free the ecc_point struct p
void ecc_clear(ecc_point *p);
// copy the values from k to p
void ecc_set(ecc_point *p, ecc_point k);
// print the ecc_point p
void ec_print(ecc_point p);
// derive an aeskey from the x coordanite of kpn. The result has to be passed to aes_free
aeskey aeskey_from_ec(ecc_point kpn);
// multiply a point with a scalar value (using the double and add algorithm)
void ecc_dbl_and_add(ecc_point *to, ecc_point p, mpz_t k, mpz_t a, mpz_t mod);

#define BLOCK_LENGTH 16

enum message_type {
  CHALLENGE,
  ORACLE_REQ,
  ORACLE_REP,
  SOLUTION,
  SOLUTION_REP};

#define RSA_BITS 2048
//1024

typedef struct {
  unsigned char N[RSA_BITS / 8];
  unsigned char e[RSA_BITS / 8];
  unsigned char c[RSA_BITS / 8];
} challenge;
typedef struct {
  unsigned char c[RSA_BITS / 8];
} oracle_req;
typedef struct {
  char rep;
} oracle_rep;
typedef struct {
  unsigned char m[RSA_BITS / 8];
} solution;
typedef struct {
  char state; // 1 = Solution is invalid, 0 = Solution is correct
} solution_rep;

struct rsa_key {
  mpz_t e;
  mpz_t d;
  mpz_t N;
};

void genkey(struct rsa_key *k);
void pkcs1_1_5_pad(uint8_t *data, const char *msg);
uint8_t *pkcs1_1_5_unpad(uint8_t *data);
void pad_and_import(mpz_t m, const char *msg);

uint8_t *calc_padding_oracle(mpz_t m, uint8_t *target);

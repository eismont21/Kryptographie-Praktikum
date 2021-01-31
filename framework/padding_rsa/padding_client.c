#include <praktikum.h>
#include <network.h>

#include <protocol.h>

Connection con;

const int local = 0;
struct rsa_key k;

// returns 1 if the padding is valid and 0 otherwise
int padding_oracle(mpz_t c){
  if(local) {
    mpz_t m;
    mpz_init(m);
    mpz_powm(m, c, k.d, k.N);
    int ret = calc_padding_oracle(m, NULL) != NULL;
    mpz_clear(m);
    return ret;
  }
  oracle_req req;
  enum message_type type = ORACLE_REQ;
  store_mpz(req.c, sizeof(req.c), c);
  Transmit(con, &type, sizeof(type));
  Transmit(con, &req, sizeof(req));
  oracle_rep m;
  ReceiveAll(con, &m, sizeof(m));
  return m.rep;
}

void submit_solution(mpz_t m){
  if(local){
    printf("Skipping submition, because running in offline mode.\n");
    return;
  } else {
    solution sol;
    store_mpz(sol.m, sizeof(sol.m), m);
    enum message_type type = SOLUTION;
    Transmit(con, &type, sizeof(type));
    Transmit(con, &sol, sizeof(sol));
    solution_rep m;
    ReceiveAll(con, &m, sizeof(m));
    if(m.state == 0){
      printf("Solution was accepted\n");
      const char *now = Now();
      printf("Solution submitted at %s\n", now);
    }else{
      printf("Solution was rejected\n");
    }
  }
}

int main (int argc, char *argv[]){
  mpz_t N, e, c;
  mpz_init(N); mpz_init(e); mpz_init(c);

  if(local){
    genkey(&k);
    mpz_t m;
    mpz_init(m);
    pad_and_import(m, "This is the secret test message");
    gmp_printf ("m: %Zd\n", m);
    mpz_set(N, k.N);
    mpz_set(e, k.e);
    mpz_powm(c, m, k.e, k.N);
    mpz_clear(m);
  } else {
    con = ConnectTo(MakeNetName(NULL), "RSA_Padding_Daemon");
    challenge chall;
    ReceiveAll(con, &chall, sizeof(chall));
    mpz_import(N, sizeof(chall.N), 1,1,1,0, chall.N);
    mpz_import(e, sizeof(chall.e), 1,1,1,0, chall.e);
    mpz_import(c, sizeof(chall.c), 1,1,1,0, chall.c);
  }
  fprintf(stderr, "N: %s\n",  mpz_get_str(NULL, 16, N));
  fprintf(stderr, "e: %s\n",  mpz_get_str(NULL, 16, e));
  fprintf(stderr, "c: %s\n",  mpz_get_str(NULL, 16, c));

  // Task: Obtain the plaintext of c
  // Use padding_oracle(c_2);
  //   to check (returns 1) if the decryption of c_2 has valid padding

  mpz_t B;
  mpz_init_set_ui(B, 2);
  mpz_pow_ui(B, B, 256 - 16);

  mpz_t m1;
  mpz_init_set_ui(m1, 2);
  mpz_mul(m1, m1, B);

  mpz_t m2;
  mpz_init_set_ui(m2, 3);
  mpz_mul(m2, m2, B);
  mpz_sub_ui(m2, m2, 1);

  mpz_t c_0;
  mpz_init_set(c_0, c);

  mpz_t s_i;
  mpz_init_set_ui(s_i, 1);

  mpz_t count;
  mpz_init_set_ui(count, 1);

  char flag = 1;
  printf("Step 1 copmlete \n");
  while (flag){
      mpz_t siPrev;
      mpz_init_set(siPrev, s_i);

      mpz_t m1Prev;
      mpz_init_set(m1Prev, m1);

      mpz_t m2Prev;
      mpz_init_set(m2Prev, m2);

      mpz_t a;
      mpz_t b;

      if (mpz_cmp_ui(count, 1) == 0){
          mpz_t tmp;
          mpz_init_set_ui(tmp, 3);
          mpz_mul(tmp, tmp, B);
          mpz_div(s_i, N, tmp);
          /*mpz_t tmp2;
          mpz_init_set_ui(tmp2, 0);
          mpz_mod(tmp2, N, tmp);
          if (mpz_cmp_ui(tmp2, 0) != 0){
              mpz_add_ui(s_i, s_i, 1);
          }
          mpz_clear(tmp2);*/
          mpz_clear(tmp);
          mpz_t c_2;
          mpz_init_set_ui(c_2, 0);
          mpz_powm(c_2, s_i, e, N);
          mpz_mul(c_2, c_0, c_2);
          while (!(padding_oracle(c_2))){
              mpz_add_ui(s_i, s_i, 1);
              mpz_powm(c_2, s_i, e, N);
              mpz_mul(c_2, c_0, c_2);
          }
          mpz_clear(c_2);
      } else {
          mpz_init_set(a, m1Prev);
          mpz_init_set(b, m2Prev);

          mpz_t ri;
          mpz_init_set_ui(ri, 0);
          mpz_mul_ui(ri, B, 2);
          mpz_t tmp;
          mpz_init_set_ui(tmp, 0);
          mpz_mul(tmp, b, siPrev);
          mpz_sub(ri, tmp, ri);
          mpz_div(ri, ri, N);
          mpz_t tmp2;
          mpz_init_set_ui(tmp2, 0);
          /*mpz_mod(tmp2, ri, N);
          if (mpz_cmp_ui(tmp2, 0) != 0){
              mpz_add_ui(ri, ri, 1);
          }*/
          mpz_mul_ui(ri, ri, 2);

          char flag2 = 1;

          while (flag2){
              mpz_mul(tmp, ri, N);
              mpz_mul_ui(tmp2, B, 2);
              mpz_add(s_i, tmp, tmp2);
              mpz_div(s_i, s_i, b);
              mpz_t tmp3;
              mpz_init_set_ui(tmp3, 0);
              /*mpz_mod(tmp3, s_i, b);
              if (mpz_cmp_ui(tmp3, 0) != 0){
                  mpz_add_ui(s_i, s_i, 1);
              }*/
              mpz_t maxSi;
              mpz_init_set_ui(maxSi, 0);
              mpz_mul_ui(tmp2, B, 3);
              mpz_add(maxSi, tmp, tmp2);
              mpz_sub_ui(maxSi, maxSi, 1);
              mpz_div(maxSi, maxSi, a);
              /*mpz_mod(tmp3, maxSi, a);
              if (mpz_cmp_ui(tmp3, 0) != 0){
                  mpz_add_ui(maxSi, maxSi, 1);
              }*/
              while (mpz_cmp(s_i, maxSi) <= 0){
                  mpz_t c_2;
                  mpz_init_set_ui(c_2, 0);
                  mpz_powm(c_2, s_i, e, N);
                  mpz_mul(c_2, c_0, c_2);
                  if (padding_oracle(c_2)){
                      flag2 = 0;
                      break;
                  }
                  mpz_add_ui(s_i, s_i, 1);
                  mpz_clear(c_2);
              }
              mpz_add_ui(ri, ri, 1);
              mpz_clear(tmp3);
              mpz_clear(maxSi);
          }
          mpz_clear(tmp);
          mpz_clear(tmp2);
          mpz_clear(ri);
      }
      printf("Step 2 copmlete \n");
      /*mpz_t r;
      mpz_init_set_ui(r, 0);
      mpz_t tmp3;
      mpz_init_set_ui(tmp3, 0);

      mpz_t tmp;
      mpz_init_set_ui(tmp, 0);
      mpz_mul(tmp, a, s_i);

      mpz_t tmp2;
      mpz_init_set_ui(tmp2, 0);
      mpz_mul_ui(tmp2, B, 3);
      mpz_add_ui(tmp, tmp, 1);
      mpz_sub(tmp, tmp, tmp2);
      mpz_div(r, tmp, N);
      mpz_mod(tmp3, tmp, N);
      if (mpz_cmp_ui(tmp3, 0) != 0){
          mpz_add_ui(r, r, 1);
      }

      mpz_t maxR;
      mpz_init_set_ui(maxR, 0);
      mpz_mul(tmp, b, s_i);
      mpz_mul_ui(tmp2, B, 2);
      mpz_sub(maxR, tmp, tmp2);
      mpz_div(maxR, maxR, N);
      mpz_mod(tmp, maxR, N);
      if (mpz_cmp_ui(tmp, 0) != 0){
          mpz_add_ui(maxR, maxR, 1);
      }
      while (mpz_cmp(r, maxR) <= 0){
          mpz_t bottom;
          mpz_init_set_ui(bottom, 0);

          mpz_mul(tmp2, r, N);
          mpz_mul_ui(tmp, B, 2);
          mpz_add(bottom, tmp, tmp2);
          mpz_div(bottom, bottom, s_i);
          mpz_mod(tmp3, bottom, s_i);
          if (mpz_cmp_ui(tmp3, 0) != 0){
              mpz_add_ui(bottom, bottom, 1);
          }
      }*/
      mpz_t rest;
      mpz_init_set_ui(rest, 0);
      mpz_sub(rest, a, b);
      gmp_printf ("a - b: %Zd\n", rest);
      mpz_clear(rest);
      if (mpz_cmp(a, b) == 0){
          gmp_printf ("my m: %Zd\n", a);
          submit_solution(a);
          flag = 0;
          break;
      }
      mpz_add_ui(count, count, 1);
      mpz_clear(siPrev);
      mpz_clear(m1Prev);
      mpz_clear(m2Prev);
      mpz_clear(a);
      mpz_clear(b);
  }

  mpz_clear(B);
  mpz_clear(m1);
  mpz_clear(m2);
  mpz_clear(c_0);
  mpz_clear(s_i);
  mpz_clear(count);

  if(!local) {
    DisConnect (con);
  }
  exit(0);

  return 0;
}

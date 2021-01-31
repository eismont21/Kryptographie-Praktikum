#include <praktikum.h>
#include <network.h>
#include "protocol.h"
#include "invalid_curves.h"

Connection con;

mpz_t p,a,b;

void validate_points(void){
  ecc_point pn;mpz_init(pn.x);mpz_init(pn.y);pn.inf=0;
  for(int pnt = 0; invalid_points[pnt].prime != 0; pnt++){
  
    mpz_set_str(pn.x, invalid_points[pnt].px, 16);
    mpz_set_str(pn.y, invalid_points[pnt].py, 16);

    ecc_point dbl;mpz_init(dbl.x);mpz_init(dbl.y);dbl.inf=0;
    mpz_set(dbl.x, pn.x);
    mpz_set(dbl.y, pn.y);
    dbl.inf = pn.inf;

    mpz_t k; mpz_init(k);
    mpz_set_ui(k, invalid_points[pnt].prime);
    //printf("flag before ecc_dbl_and_add");
    ecc_dbl_and_add(&dbl, dbl, k, a, p);
    //printf("flag after ecc_dbl_and_add");
    if (dbl.inf == 0) {
        printf("Iteration %d is NOT correct\n", pnt);
    }
    // Task: Implement point validation
  }
  printf("Validation DONE\n");
}

void submit_solution(mpz_t key){
  uint8_t type = MSG_SOL;
  Transmit(con, &type, sizeof(type));
  sol r;
  store_mpz(r.key, sizeof(r.key), key);
  Transmit(con, &r, sizeof(r));
  sol_rep rep;
  ReceiveAll(con, &rep, sizeof(rep));
  if(rep.state == 0){
    const char *date = Now();
    printf("Solution submitted at %s was correct.\n", date);
  }else{
    printf("Solution was incorrect.\n");
  }
}

void test_connection(uint8_t cipher[32], ecc_point p){
  uint8_t type = MSG_CONN;
  Transmit(con, &type, sizeof(type));
  req r;
  store_mpz(r.x, sizeof(r.x), p.x);
  store_mpz(r.y, sizeof(r.y), p.y);
  r.inf = p.inf != 0;
  Transmit(con, &r, sizeof(r));
  rep rep;
  ReceiveAll(con, &rep, sizeof(rep));
  memcpy(cipher, rep.cipher, 32);
}


int main(int argc, char *argv[]){
    //printf("start\n");
    mpz_init(p); mpz_set_str(p, curve_p, 16);
    mpz_init(a); mpz_set_str(a, curve_a, 16);
    mpz_init(b); mpz_set_str(b, curve_b, 16);

    validate_points();

    con = ConnectTo(MakeNetName(NULL), "ECC_invalid_Daemon");
    uint8_t cipher[32];
    uint8_t res[32];
    ecc_point pn;mpz_init(pn.x);mpz_init(pn.y);pn.inf=0;
    for(int pnt = 0; invalid_points[pnt].prime != 0; pnt++) {
        mpz_set_str(pn.x, invalid_points[pnt].px, 16);
        mpz_set_str(pn.y, invalid_points[pnt].py, 16);

        for (int i = 1; i <= invalid_points[pnt].prime; i++) {
            ecc_point dbl;mpz_init(dbl.x);mpz_init(dbl.y);dbl.inf=0;
            mpz_set(dbl.x, pn.x);
            mpz_set(dbl.y, pn.y);
            dbl.inf = pn.inf;

            mpz_t k; mpz_init(k);
            mpz_set_ui(k, i);
            ecc_dbl_and_add(&dbl, dbl, k, a, p);

            test_connection(cipher, dbl);
            aeskey key;
            key = aeskey_from_ec(dbl);
            aes_dec(res, cipher, key);
            //res = res ^ key;
            size_t key_size = sizeof(key.key) / sizeof(key.key[0]);
            int j_key = 0;
            for (int j = 0; j < 32; j++) {
                if (j_key == key_size) {
                    j_key = 0;
                }
                res[j] = res[j] ^ key.key[j_key];
                j_key++;
            }
            for (int j = 0; j < 32; j++) printf("%d", res[i]);


        }
    }
  // Task: Implement the attack to recover the daemon's private key
  // To simulate a connection attempt with curve point 'pn' use:
  // test_connection(cipher, pn);
  // the encrypted value is stored in 'cipher'
  // To submit the recovered key 'solution' use:
  // submit_solution(solution);
}

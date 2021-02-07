#include <praktikum.h>
#include <network.h>
#include "protocol.h"
#include "invalid_curves.h"

Connection con;

mpz_t p,a,b;

static void factorial (long n, mpz_t r)
{
    mpz_init_set_si (r, 1);
    for (; n > 1; n--) {
        mpz_mul_si (r, r, n);
    }
}
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
    exit(1);
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
    uint8_t cipher_text[16];
    uint8_t iv[16];
    uint8_t res[16];
    mpz_t solution;
    mpz_init(solution);
    char* solution_str;
    mpz_t two;
    mpz_init_set_ui(two, 2);
    mpz_t pi; mpz_init_set_ui(pi, 1);

    ecc_point pn;mpz_init(pn.x);mpz_init(pn.y);pn.inf=0;
    for(int pnt = 0; invalid_points[pnt].prime != 0; pnt++) {
        //if (invalid_points[pnt].prime < 50) continue;
        printf("\t\tPrime is %d\n", invalid_points[pnt].prime);
        mpz_set_str(pn.x, invalid_points[pnt].px, 16);
        mpz_set_str(pn.y, invalid_points[pnt].py, 16);
        mpz_mul_ui(pi, pi, invalid_points[pnt].prime);


        for (int i = 1; i <= invalid_points[pnt].prime; i++) {
            //mpz_set_ui(pi, i);
            //factorial(i, pi);
            ecc_point dbl;mpz_init(dbl.x);mpz_init(dbl.y);dbl.inf=0;
            mpz_set(dbl.x, pn.x);
            mpz_set(dbl.y, pn.y);
            dbl.inf = pn.inf;

            mpz_t k; mpz_init(k);
            mpz_set_ui(k, i);
            //k*dbl
            ecc_dbl_and_add(&dbl, dbl, k, a, p);

            test_connection(cipher, dbl);
            aeskey key;
            key = aeskey_from_ec(dbl);

            for (int i = 16; i < 32; i++) {
                cipher_text[i-16] = cipher[i];
            }
            for (int i = 0; i < 16; i++) {
                iv[i] = cipher[i];
            }
            //decryption AES
            aes_dec(cipher_text, res, key);

            //CBC Modus
            for (int i = 0; i < 16; i++) {
                res[i] = res[i] ^ iv[i];
            }


            //printf("cipher: \n");
            //for (int j = 0; j < 32; j++)  printf("%d", res[i]);
            int index = 0;
            for (int i=0; i<16; i++)
                index += sprintf(&solution_str[index], "%d", res[i]);

            if (solution_str[0] != '0' || solution_str[1] != '0' || solution_str[2] != '0') continue;
            printf("\ncipher_str: %s\n", solution_str);

            mpz_set_str(solution, solution_str, 16);
            mpz_powm(solution, solution, two, pi);
            mpz_sqrt(solution, solution);
            gmp_printf("Solution =  %Zd\n", solution);

            submit_solution(solution);
            con = ConnectTo(MakeNetName(NULL), "ECC_invalid_Daemon");
        }
    }
  // Task: Implement the attack to recover the daemon's private key
  // To simulate a connection attempt with curve point 'pn' use:
  // test_connection(cipher, pn);
  // the encrypted value is stored in 'cipher'
  // To submit the recovered key 'solution' use:
  // submit_solution(solution);
}

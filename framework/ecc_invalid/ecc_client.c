#include <praktikum.h>
#include <network.h>
#include "protocol.h"
#include "invalid_curves.h"
#include "string.h"
#include "math.h"
#include "stdint.h"
#include <limits.h>

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

      // Task: Implement point validation
    mpz_t k; mpz_init(k);
    mpz_set_ui(k, invalid_points[pnt].prime);

    ecc_dbl_and_add(&dbl, pn, k, a, p);

    if (dbl.inf == 0) {
        printf("Iteration %d is NOT correct\n", pnt);
    }

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

int numDigits (int n) {
    if (n < 0) return numDigits((n == INT_MIN) ? INT_MAX: -n);
    if (n < 10) return 1;
    return 1 + numDigits(n / 10);
}


int main(int argc, char *argv[]){
    //printf("start\n");
    mpz_init(p); mpz_set_str(p, curve_p, 16);
    mpz_init(a); mpz_set_str(a, curve_a, 16);
    mpz_init(b); mpz_set_str(b, curve_b, 16);

    validate_points();

    con = ConnectTo(MakeNetName(NULL), "ECC_invalid_Daemon");
    uint8_t cipher[32];
    // Task: Implement the attack to recover the daemon's private key
    // To simulate a connection attempt with curve point 'pn' use:
    // test_connection(cipher, pn);
    // the encrypted value is stored in 'cipher'
    // To submit the recovered key 'solution' use:
    // submit_solution(solution);
    uint8_t cipher_text[16];
    uint8_t iv[16];
    uint8_t res[16];

    char solution_str[16];
    mpz_t two;
    mpz_init_set_ui(two, 2);
    mpz_t pi; mpz_init_set_ui(pi, 1);

    size_t numPrimes = 65;
    mpz_t N[numPrimes]; // the squares of px
    mpz_t c[numPrimes]; // tthe corresponding j's
    for (int i = 0; i < numPrimes; i++) {
        mpz_init_set_ui(N[i], 0);
        mpz_init_set_ui(c[i], 0);
    }

    ecc_point pn;mpz_init(pn.x);mpz_init(pn.y);pn.inf=0;
    for(int pnt = 0; invalid_points[pnt].prime != 0; pnt++) {
        printf("\t\t%d: Prime is %d\n", pnt, invalid_points[pnt].prime);
        mpz_set_str(pn.x, invalid_points[pnt].px, 16);
        mpz_set_str(pn.y, invalid_points[pnt].py, 16);
        test_connection(cipher, pn);
        mpz_mul(N[pnt], pn.x, pn.x);


        for (int j = 1; j <= invalid_points[pnt].prime; j++) {

            ecc_point dbl;mpz_init(dbl.x);mpz_init(dbl.y);dbl.inf=0;
            mpz_set(dbl.x, pn.x);
            mpz_set(dbl.y, pn.y);
            dbl.inf = pn.inf;

            mpz_t k; mpz_init(k);
            mpz_set_ui(k, j);

            //k*pn
            ecc_dbl_and_add(&dbl, pn, k, a, p);

            aeskey key;
            key = aeskey_from_ec(dbl);

            //the 1st part is IV
            for (int i = 0; i < 16; i++) {
                iv[i] = cipher[i];
            }
            //the 2nd part is c
            for (int i = 16; i < 32; i++) {
                cipher_text[i-16] = cipher[i];
            }

            //decryption AES
            aes_dec(cipher_text, res, key);

            //CBC Modus
            for (int i = 0; i < 16; i++) {
                res[i] = res[i] ^ iv[i];
            }

            //res array to string
            int index = 0;
            for (int i=0; i<16; i++)
                index += sprintf(&solution_str[index], "%d", res[i]);

            //printf("\ncipher_str: %s\n", solution_str);
            if (solution_str[0] == '0' && solution_str[1] == '0' && solution_str[2] == '0') {
                printf("begins with 3 zeros\n");
                int j2 = j*j;
                mpz_set_ui(c[pnt], j2);
                break;
            }
        }
    }
    // Chinese remainder theorem from Versuch 4
    // Input: N and c
    // Output: solution
    mpz_t product;
    mpz_init(product);
    mpz_set_ui(product, 1);
    for (int i = 0; i < numPrimes; i++){
        mpz_mul(product, product, N[i]);
    }
    mpz_t s;
    mpz_init_set_ui(s, 0);
    mpz_t sum;
    mpz_init_set_ui(sum, 0);
    for (int i = 0; i < numPrimes; i++){
        mpz_div(s, product, N[i]);
        mpz_t a;
        mpz_init_set(a, s);
        mpz_t b;
        mpz_init_set(b, N[i]);
        mpz_t d;
        mpz_init_set(d, b);
        mpz_t f;
        mpz_init_set_ui(f, 0);
        mpz_t j;
        mpz_init_set_ui(j, 0);
        mpz_t h;
        mpz_init_set_ui(h, 0);
        mpz_t k;
        mpz_init_set_ui(k, 1);
        char flag = 0;
        if (mpz_cmp_ui(b, 1) == 0){
            flag = 1;
        }
        while ((mpz_cmp_ui(a, 1) > 0) && (flag == 0)){
            mpz_div(j, a, b);
            mpz_set(f, b);
            mpz_mod(b, a, b);
            mpz_set(a, f);
            mpz_set(f, h);
            mpz_t tmp;
            mpz_init_set_ui(tmp, 0);
            mpz_mul(tmp, j, h);
            mpz_sub(h, k, tmp);
            mpz_clear(tmp);
            mpz_set(k, f);
        }
        mpz_clear(a);
        mpz_clear(b);
        mpz_clear(f);
        mpz_clear(j);
        mpz_clear(h);
        if (mpz_cmp_ui(k, 0) < 0){
            mpz_add(k, k, d);
        }
        mpz_clear(d);
        mpz_t tmp;
        mpz_init_set_ui(tmp, 0);
        mpz_mul(tmp, k, s);
        mpz_mul(tmp, tmp, c[i]);
        mpz_add(sum, sum, tmp);
        mpz_clear(k);
        mpz_clear(tmp);
    }
    mpz_clear(s);
    mpz_t solution;
    mpz_init_set_ui(solution, 0);
    mpz_mod(solution, sum, product);
    mpz_clear(product);
    mpz_clear(sum);

    //end code: square root from solution
    //mpz_set_str(solution, x2, strlen(x2));
    //mpz_set_str(solution, solution_str, 16);
    mpz_sqrt(solution, solution);
    gmp_printf("Solution =  %Zd\n", solution);
    submit_solution(solution);
}

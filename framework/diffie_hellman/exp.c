/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 6: Langzahlarithmetik und Diffie-Hellmann         *
**            Key Exchange                                   *
**                                                           *
**************************************************************
**
** exp.c: Implementierung Modulo-Exponentation.
**/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>
#include <gmp.h>

#include "versuch.h"

#include <math.h>
/*
 * doexp(x,y,z,p) : Berechnet z := x^y mod p
 * 
 * Hinweise: mpz_init(mpz_t a)		Im Speicher wird der Platz für eine Ganzzahl a zur Verfügung gestellt
 * 					und diese wird mit dem Wert 0 initialisiert.
 * 
 * TODO
 */

long int fast_degree (int a, int b) {
    long int r = 1;
    int c = a;
    while (b > 0) {
        if ((b % 2 )!= 0) {
            r = r * c;
            b--;
        } else {
            c = c * c;
            b = b / 2;
        }
    }
    return r;
}

void doexp(mpz_t x, mpz_t y, mpz_t z, mpz_t p)
{
    // max. k-ary sliding window Exponentiation with reduced precomputation
    int n = 3;                           // when n >= 19, Segmentation fault
    int long SIZE = fast_degree(2, n);

// Initialasition and precomputaion for reduced lookup tale
    mpz_t table[SIZE];
    mpz_t temp;

    mpz_init_set_si(temp, 1);
    mpz_init(table[0]);
    mpz_set(table[0], temp);

    mpz_mod(temp, x, p); // x[1] <-- x mod p
    mpz_init(table[1]);
    mpz_set(table[1], temp);

    mpz_mul(temp, x, x); // x[2] <-- x^2 mod p
    mpz_init(table[2]);
    mpz_mod(table[2], temp, p);

    for (long int i = 1; i < SIZE / 2; i++) {
        mpz_init(table[2*i+1]);
        mpz_mul(temp, table[2*i-1], table[2]);    // x[2i+1] <-- x[2i-1]*x[2] mod p
        mpz_mod(table[2*i+1], temp, p);
    }


// modular exponentiation

    mpz_set_si(z, 1);

    int cursor = mpz_sizeinbase(y, 2) - 1; // 2 ^ cursor == y
    // pointer to start of current window
    
    while (cursor >= 0) {
        if(cursor < n) {                                                    // the max length of last window
            n = cursor + 1;
        }
        if (mpz_tstbit(y, cursor) == 0) {                                   // snip zero bits between windows
            mpz_mul(temp, z, z);
            mpz_mod(z, temp, p);
            cursor--;
        } else {
            int index = 0;
            int wnd = n;

            while (wnd > 1 && mpz_tstbit(y,cursor - wnd + 1) != 1) {          // find the max length of window
                wnd--;
            }
            for (size_t i = 0; i < wnd; i++) {
                mpz_mul(temp, z, z);                                               // z <-- z^2^wnd mod p
                mpz_mod(z, temp, p);
                index += fast_degree(2, wnd - i - 1) * mpz_tstbit(y, cursor - i);//find the index for lookup table
            }
            mpz_mul(temp, z, table[index]);                                // z <-- z*(x[2i+1])
            mpz_mod(z, temp, p);

            cursor -= wnd;
        }
    }
    mpz_clear(table);
    return;
  }

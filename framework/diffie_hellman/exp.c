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

/**
 * @param a base
 * @param b exponent
 * @return a^b
 */
long int fast_degree(int a, int b) {
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

/**
 * Calculate x^2 mod p
 * @param x
 * @param y
 * @param p
 */
void mpz_mul_mod(mpz_t x, mpz_t y, mpz_t p) {
    mpz_t temp;
    mpz_init(temp);
    mpz_mul(temp, x, y);
    mpz_mod(x, temp, p);
}
/**
 * Initialize the table for fast calculations
 * @param table to init
 * @param SIZE of the table
 * @param x base
 * @param p modulo
 */
void init_table(mpz_t table[], int SIZE, mpz_t x, mpz_t p) {
    mpz_init_set_si(table[0], 1);
    mpz_init_set(table[1], x);
    mpz_init_set(table[2], x);
    mpz_mul_mod(table[2], x, p);

    for (long int i = 1; i < SIZE / 2; i++) {
        mpz_init_set(table[2*i+1], table[2*i-1]);
        mpz_mul_mod(table[2*i+1], table[2], p);
    }
    return;
}
/**
 *
 * @param y exponent
 * @param cursor the current bit
 * @param n sliding window
 * @return the length of the window
 */
int wnd_length(mpz_t y, int cursor, int n) {
    int len = 0;
    for (int i = n; i > 1 && mpz_tstbit(y, cursor - i + 1) != 1; i--) {
        len++;
    }
    return n - len;
}

/*
 * doexp(x,y,z,p) : Berechnet z := x^y mod p
 *
 * Hinweise: mpz_init(mpz_t a)		Im Speicher wird der Platz für eine Ganzzahl a zur Verfügung gestellt
 * 					und diese wird mit dem Wert 0 initialisiert.
 *
 */
void doexp(mpz_t x, mpz_t y, mpz_t z, mpz_t p) {
    // define n bits sliding window
    int n;
    if (mpz_sizeinbase(y, 2) > 500) {
        n = 4;
    } else {
        n = 3;
    }
    int long SIZE = fast_degree(2, n);

    // Table with values 1, x, x^2, ... (mod p)
    mpz_t table[SIZE];
    init_table(table, SIZE, x, p);

// modular exponentiation
    mpz_set_si(z, 1);
    int cursor = mpz_sizeinbase(y, 2) - 1; // 2 ^ cursor == y , start point
    while (cursor >= 0) {
        if (mpz_tstbit(y, cursor) == 1) {
            //case 1, find the entry in the table
            int wnd = wnd_length(y, cursor, n);
            int table_index = 0;
            for (int i = 0; i < wnd; i++) {
                mpz_mul_mod(z, z, p);
                table_index += fast_degree(2, wnd - i - 1) * mpz_tstbit(y, cursor - i);
            }
            mpz_mul_mod(z, table[table_index], p);
            cursor -= wnd;
        } else {
            //case 2, zero bits will be just multiplied one by one
            mpz_mul_mod(z, z, p);
            cursor--;
        }
        // the last window
        if (cursor < n) {
            n = cursor + 1;
        }
    }
    mpz_clear(table);
    return;
}

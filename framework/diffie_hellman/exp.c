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
                        
/*
 * doexp(x,y,z,p) : Berechnet z := x^y mod p
 * 
 * Hinweise: mpz_init(mpz_t a)		Im Speicher wird der Platz für eine Ganzzahl a zur Verfügung gestellt
 * 					und diese wird mit dem Wert 0 initialisiert.
 * 
 * TODO
 */

void doexp(mpz_t x, mpz_t y, mpz_t z, mpz_t p)
{
    /*>>>>                                                   <<<<*
     *>>>> AUFGABE: Implementierung der Modulo-Exponentation <<<<*
     *>>>>                                                   <<<<*/
  }

/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 6: Langzahlarithmetik und Diffie-Hellmann         *
**            Key Exchange                                   *
**                                                           *
**************************************************************
**
** alicebob.c: Rahmenprogramm für das Abhören der Unterhaltung
**             zwischen Alice und Bob.
**/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>
#include <network.h>
#include <gmp.h>
#include <time.h>

#include "versuch.h"

#include "string.h"
#ifndef BYTE_LENGTH
#define BYTE_LENGTH 256
#endif

/**********************  Globale Konstanten  ********************/
const char *s_p  = PUBLIC_DATA_p;
const char *s_w  = PUBLIC_DATA_w;
const char *s_wa = PUBLIC_DATA_wa;
const char *s_wb = PUBLIC_DATA_wb;


/*
 * EnCryptStr und DeCryptStr ver- bzw. entschlüsseln jeweils einen
 *   String mit dem angegebenen Schlüssel. Man beachte, daß der
 *   Schlüssel (der IV-Teil) dabei verändert wird!
 */

static void EnCryptStr(CipherKey *ck, char *s, int len)
  {
    aes_do_ctr((uint8_t *)s, (uint8_t *)s, len, ck->state);
  }

static void DeCryptStr(CipherKey *ck, char *s, int len)
  {
    aes_do_ctr((uint8_t *)s, (uint8_t *)s, len, ck->state);
  }

void break_exp(mpz_t w, mpz_t a, mpz_t wa, mpz_t p) {
    mpz_t temp;
    mpz_init(temp);
    mpz_set_si(a, 0);
    //printf("\n w=%lld \n a=%lld \n wa=%lld \n p=%lld \n", w, a, wa, p);
    do {
        mpz_add_ui(a, a, 1); //a += 1
        doexp(w, a, temp, p); //temp = w^a mod p
    } while (mpz_cmp(temp, wa) != 0);
}
/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
  Packet pkt;
  Connection con;
  char *name1;
  /* die globalen Langzahlen in Langzahl-Form */
  mpz_t p;
  mpz_t w;
  mpz_t wa;
  mpz_t wb;


  /* Langzahlarithmetik initialisieren und Konstanten wandeln */
  mpz_init_set_str(p, s_p, 16);
  mpz_init_set_str(w, s_w, 16);
  mpz_init_set_str(wa, s_wa, 16);
  mpz_init_set_str(wb, s_wb, 16);
    

  /*----  Aufbau der Verbindung zum Alice/Bob-Daemon  ----*/
  name1 = MakeNetName("AliceBob");
  
  if (!(con = ConnectTo(name1,ABDAEMON_PORTNAME))) {
    fprintf(stderr,"ConnectTo(\"%s\",\"%s\") failed: %s\n",name1,ABDAEMON_PORTNAME,NET_ErrorText());
    exit(20);
  }

  /*
   * WICHTIGER HINWEIS: Auf der Netzwerkverbindung CON werden alle Pakete
   *    angeliefert, die Alice und Bob austauschen. Die Paketrichtung ist im
   *    direction-Feld angegeben. Das Paket muß explizit weiter transportiert
   *    werden. Außerdem ist zu beachten, daß die Kommunikation nur dann
   *    korrekt funktionier, wenn Alice und Bob immer abwechselnd senden.
   *    Das Unterschlagen eines Paketes führt also zu einem Hänger!
   *
   * Der folgende Programmrahmen zeigt alle abgefangenen Pakete an und
   * leitet sie anschließend korrekt weiter.
   */

  mpz_t k_ba, k_ab, a, b, pkt_number;
  mpz_init(k_ba); mpz_init(k_ab); mpz_init(a); mpz_init(b); mpz_init(pkt_number);
  //printf("\n w=%lld \n a=%lld \n wa=%lld \n p=%lld \n", w, a, wa, p);
  CipherKey ck_ba, ck_ab;
  break_exp(&w, &a, &wa, &p);
  break_exp(w, b, wb, p);
  //printf("\n w=%lld \n a=%lld \n wa=%lld \n p=%lld \n", w, a, wa, p);

  while(1) { /* Schleife über alle Nachrichten ... */
    ReceiveAll(con,&pkt,sizeof(pkt));
    // initialize number in packet
    printf("%s (%2d) ",pkt.direction == DIRECTION_AliceBob ? "Alice->Bob " : "Bob->Alice ",pkt.seqcount);

    if (pkt.tp==PACKETTYPE_Auth) {
      printf("AUTH %s\n",pkt.number);
      if (pkt.direction ==DIRECTION_BobAlice) {
          mpz_set_str(pkt_number, (char*) pkt.number, 16);
          doexp(pkt_number, a, k_ba, p); // k_ba = number^b mod p
          SetKey(k_ba, &ck_ba);
      } else if (pkt.direction ==DIRECTION_AliceBob) {
          mpz_set_str(pkt_number, (char*) pkt.number, 16);
          doexp(pkt_number, b, k_ab, p); // k_ab = number^b mod p
          SetKey(k_ab, &ck_ab);
      } else {
          printf("Error: Direction is incorrect");
      }
    }
    else {
      printf("DATA "); printstring_escaped(stdout, pkt.data,pkt.len); printf("\n");
      Data_Typ msg; //= pkt.data;
      //Data_Typ new_msg;
      //memcpy(msg, pkt.data, pkt.len);
      strcpy(msg, pkt.data);
      //Data_Typ key;
      if (pkt.direction == DIRECTION_BobAlice) {
          if (pkt.seqcount == 6) {
              Data_Typ new_msg;
              Data_Typ key;
              strcpy(new_msg, "ja");
              printf("\n Bob: %s \n", new_msg);
              EnCryptStr(&ck_ba, new_msg, pkt.len);
              strcpy(pkt.data, new_msg);

          } else if (pkt.seqcount == 8) {
              Data_Typ new_msg;
              Data_Typ key;
              strcpy(new_msg, "nein");
              printf("\n Bob: %s \n", new_msg);
              EnCryptStr(&ck_ba, new_msg, pkt.len);
              strcpy(pkt.data, new_msg);
          } else if (pkt.seqcount == 12) {
              Data_Typ new_msg;
              Data_Typ key;
              strcpy(new_msg, "nein");
              printf("\n Bob: %s \n", new_msg);
              EnCryptStr(&ck_ba, new_msg, pkt.len);
              strcpy(pkt.data, new_msg);
          } else {
                  DeCryptStr(&ck_ba, msg, pkt.len);
                  printf("\n Bob: %s \n", msg);
          }
      } else if (pkt.direction == DIRECTION_AliceBob) {
          DeCryptStr(&ck_ab, msg, pkt.len);
          printf("\n Alice: %s \n", msg);
      } else {
          printf("Error: Direction is incorrect");
      }
    }
    /* Paket weiterleiten */
    Transmit(con,&pkt,sizeof(pkt));
  }
  DisConnect(con);
  return 0;
}

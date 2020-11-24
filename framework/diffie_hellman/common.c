#include "versuch.h"

/*
 * SetKey(num,key) : Wandelt die Langzahl NUM in einen Schlüssel, der für die
 *    Funktionen EnCryptStr und DeCryptStr geeignet ist.
 */

void SetKey(mpz_t num, CipherKey *ck)
  {
    size_t len = (mpz_sizeinbase(num, 2) + 7)/8;
    uint8_t numHex[len];
    mpz_export(numHex, NULL, 1, 1, 1, 0, num);

    uint8_t data[2*16];
    memset(data, 0, sizeof(data));
    if(2*16 > len){
      memcpy(data, numHex, len);
    }else{
      memcpy(data, numHex, 2*16);
    }      
    printstring_escaped_unsigned(stdout, data, 32);

    
    ck->state = aes_init_ctr((uint8_t *) data, 16, ((uint8_t *) data) + 16);
  }

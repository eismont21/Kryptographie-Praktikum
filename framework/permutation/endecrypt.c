/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
**   Versuch 2: Permutations-Chiffre                         *
**                                                           *
**************************************************************
**
** endecrypt.c: Implementierung einer Permutations-Chiffre
**/

#include <stdlib.h>
#include "libperm.h"

#if defined (ENCRYPT)
#define fnname encrypt
#define ENCR 1
#elif defined (DECRYPT)
#define fnname decrypt
#define ENCR 0
#else
#error "Either ENCRYPT or DECRYPT must be defined"
#endif

void fnname(const char *source, char *dest, int len, int plen, const int *perm)
{
  int i;
  int j;
  int *tmpperm;
  int k;

  while (len >= plen) {
    for (i = 0; i < plen; i++) {
#if ENCR
      dest[perm[i]] = source[i];
#else
      dest[i] = source[perm[i]];
#endif
    }
    dest += plen;
    source += plen;
    len -= plen;
  }
  if (len) {
    /* encrypt last block handling */

    tmpperm = calloc (len+1, sizeof (int));
    for (i = 0; i < len; i++) tmpperm[i] = perm[i];
    tmpperm[len] = plen;
    for (i = 0; i < len; i++) {
      k = len;
      for (j = 0; j < len; j++) {
        if (tmpperm[j] >= i && tmpperm[j] < tmpperm[k]) k = j;
      }
      tmpperm[k] = i;
    }
    for (i = 0; i < len; i++) {
#if ENCR
      dest[tmpperm[i]] = source[i];
#else
      dest[i] = source[tmpperm[i]];
#endif
    }
#if 0
    /* decrypt last block handling */
    for (i = j = 0; i < len; i++, j++) {
      while (perm[j] >= len) j++;
      dest[perm[j]] = source[i];
      /*dest[i] = source[perm[j]];*/
    }
#endif
  }
}

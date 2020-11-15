/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
**   Versuch 2: Permutations-Chiffre                         *
**                                                           *
**************************************************************
**
** permio.c: Implementierung einer Permutations-Chiffre (IO-Routinen)
**/

#include <stdio.h>
#include <stdlib.h>

#include "libperm.h"

int * readperm (const char *filename, int *lenp)
{
  FILE *f;
  int *p;
  int len;
  int i;
  int d;

  f = fopen (filename, "r");
  if (! f) {
    return 0;
  }
  for (len = 0; fscanf (f, "%d", &d) == 1; len ++)
    ;
  rewind (f);
  p = calloc (len, sizeof (int));
  if (! p) {
    fclose (f); return 0;
  }
  for (i = 0; i < len; i++) {
    if (fscanf (f, "%d", p+i) != 1) {
      free (p);
      fclose (f);
      return 0;
    }
  }
  if (lenp) *lenp = len;
  return p;
}

int writeperm (const char *filename, int len, const int *perm)
{
  int i;
  FILE *f;

  f = fopen (filename, "w");
  if (!f) {
    return -1;
  }
  for (i = 0; i < len; i++) {
    if (i) fprintf (f, " ");
    fprintf (f, "%d", perm[i]);
  }
  fprintf (f, "\n");
  fclose (f);
  return 0;
}

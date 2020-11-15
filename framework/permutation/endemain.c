/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
**   Versuch 2: Permutations-Chiffre                         *
**                                                           *
**************************************************************
**
** endemain.c: Implementierung einer Permutations-Chiffre (Hauptprogramm)
**/

#include <stdio.h>
#include <stdlib.h>

#include "libperm.h"

#if defined (ENCRYPT)
#define fnname encrypt
#elif defined (DECRYPT)
#define fnname decrypt
#else
#error "Either ENCRYPT or DECRYPT must be defined"
#endif

int main (int argc, char **argv)
{
  char *infile, *outfile;
  FILE *f;
  int *perm, permlen;
  int filelen;

  if (argc != 4) {
    fprintf (stderr, "Usage: %s permutation infile outfile\n", argv[0]);
    exit (2);
  }
  perm = readperm (argv[1], &permlen);
  if (! perm) {
    fprintf (stderr, "Error reading permutation from file %s\n", argv[1]);
    exit (2);
  }
  f = fopen (argv[2], "r");
  if (!f) {
    fprintf (stderr, "Error opening input file %s\n", argv[2]);
    exit (2);
  }
  fseek (f, 0, SEEK_END);
  filelen = ftell (f);
  rewind (f);
  infile = (char *) malloc (filelen);
  outfile = (char *) malloc (filelen);
  if (! infile || ! outfile) {
    fprintf (stderr, "Error allocating memory\n");
    exit (2);
  }
  if (fread (infile, 1, filelen, f) != filelen) {
    fprintf (stderr, "Error reading input file %s\n", argv[2]);
    exit (2);
  }
  fclose (f);

  fnname (infile, outfile, filelen, permlen, perm);

  f = fopen (argv[3], "w");
  if (!f) {
    fprintf (stderr, "Error opening output file %s\n", argv[3]);
    exit (2);
  }
  if (fwrite (outfile, 1, filelen, f) != filelen) {
    fprintf (stderr, "Error writing output to file %s\n", argv[3]);
    exit (2);
  }
  exit (0);
}

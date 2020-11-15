/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
**   Versuch 2: Permutations-Chiffre                         *
**                                                           *
**************************************************************
**
** attacke.c: Implementierung einer Permutations-Chiffre
**            Rahmenprogramm zur Lösung
**/

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <ctype.h>

#include "libperm.h"

#define PERIODE 20
#define CHIFFRAT "chiffrat"
#define PERMUTATION "permutation"
#define LOESUNG "klartext"

int loesung[PERIODE];

int laenge;
char *chiffrat;

char *scratch1, *scratch2;

void attacke (void);

int main (void)
{
  FILE *f;

  f = fopen (CHIFFRAT, "r");
  if (! f) {
    perror ("fopen");
    fprintf (stderr, "Konnte Datei %s nicht oeffnen\n", CHIFFRAT);
    exit (2);
  }
  fseek (f, 0, SEEK_END);
  laenge = ftell (f);
  rewind (f);
  chiffrat = malloc (laenge);
  scratch1 = malloc (laenge);
  scratch2 = malloc (laenge);
  if (! chiffrat || ! scratch1 || ! scratch2) {
    fprintf (stderr, "Konnte Puffer nicht allozieren\n");
    exit (2);
  }
  if (fread (chiffrat, 1, laenge, f) != laenge) {
    fprintf (stderr, "Fehler beim einlesen der Datei %s\n", CHIFFRAT);
    exit (2);
  }
  fclose (f);

  {
    attacke ();
  }
  if (writeperm (PERMUTATION, PERIODE, loesung) < 0) {
    fprintf (stderr, "Fehler beim Schreiben der Loesung auf Datei %s\n",
             PERMUTATION);
    exit (2);
  }
  printf ("Nun kannst Du versuchen, die Datei mit dem Befehl:\n");
  printf ("  decrypt %s %s %s\n", PERMUTATION, CHIFFRAT, LOESUNG);
  printf ("zu entschluesseln, um zu sehen, ob die Loesung stimmt.\n");
  exit (0);
}



void attacke (void)
{
	/* *** Hier soll die Attacke implementiert werden *** */
	/* Globale Variablen:
	*   laenge         Laenge des Chiffrats
	*   chiffrat       Puffer, in dem das Chiffrat vorliegt
	*   scratch1  und
	*   scratch2       2 Puffer der Laenge 'laenge', die beliebig verwendet
	*                  werden koennen (char *)
	*   loesung        int loesung[PERIODE], dort sollte nach dem Ende
	*                  dieser Funktion die gesuchte Permutation stehen!
	*   PERIODE        In diesem #define steht die Periodenlaenge, die
	*                  in diesem Versuch benutzt wurde.
	*/

  /* Aufgabe */

}


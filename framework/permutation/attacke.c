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


int get_distribution(char u, char v) {
    if ((u == '.' || u == ',' || u == ')') && isspace(v)){
        return 1;
    }
    if (isspace(v) && ((v >= 'A' && v <='Z') || (v == '('))) {
        return 1;
    }
    return 0;
}

int find_max(int* a, int n) {
    int max = a[0];
    int max_index = 0;
    for (int i = 1; i < n; i++) {
        if (a[i] > max) {
            max = a[i];
            max_index = i;
        }
    }
    return max;
}

int find_index_min(int* a, int n) {
    int min = a[0];
    int min_index = 0;
    for (int i = 1; i < n; i++) {
        if (a[i] < min) {
            min = a[i];
            min_index = i;
        }
    }
    return min_index;
}
void quicksort(int *mas, int* permuts, int first, int last)
{
    int mid, count;
    int f=first, l=last;
    mid=mas[(f+l) / 2]; //вычисление опорного элемента
    do
    {
        while (mas[f]<mid) f++;
        while (mas[l]>mid) l--;
        if (f<=l) //перестановка элементов
        {
            count=mas[f];
            mas[f]=mas[l];
            mas[l]=count;

            count = permuts;
            permuts[f] = permuts[l];
            permuts[l] = count;

            f++;
            l--;
        }
    } while (f<l);
    if (first<l) quicksort(mas, permuts, first, l);
    if (f<last) quicksort(mas, permuts, f, last);
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
  int number_blocks = laenge / PERIODE;

  int A[PERIODE][PERIODE];
  for (int i = 0; i < PERIODE; i++) {
      for (int j = 0; j < PERIODE; j++) {
          A[i][j] = 0;
          //if not diagonal
          if (i != j) {
              for (int k = 0; k < number_blocks; k++)
                  A[i][j] += get_distribution(chiffrat[PERIODE*k + i], chiffrat[PERIODE*k + j]);
          }
      }
  }
  int b[PERIODE];
  //Suche Maximum in jeder Zeile
  for (int i = 0; i < PERIODE; i++) {
      b[i] = find_max(b[i], PERIODE);
  }
  for (int i = 1; i <= PERIODE; i++) loesung[i] = i;
  quicksort(b, loesung, 0, PERIODE-1);
}


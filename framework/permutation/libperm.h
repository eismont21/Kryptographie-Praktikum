extern int *readperm (const char *filename, int *lenp);
/* readperm liest eine Permutation aus der Datei namens filename.
 * Dateiformat:
 *   Beispiel: Die Permutation
 *        / 0 1 2 3 \
 *        \ 2 1 3 0 /
 * steht als eine Zeile mit dem Inhalt "2 1 3 0" in der Datei.
 * Return: *lenp wird die Groesse der Permutation zugewiesen.
 *         Returnwert zeigt auf einen ge'malloc'ten Block, der die
 *         Permutation enthaelt (im Beispiel: {2, 1, 3, 0}).
 */

extern int writeperm (const char *filename, int len, const int *perm);
/* writeperm schreibt die Permutation perm (Laenge len) im oben definierten
 * Format in eine Datei namens filename.
 * Return: 0: Kein Fehler aufgetreten. -1: Fehler aufgetreten.
 */

extern void encrypt (const char *source, char *dest, int len,
		     int plen, const int *perm);
/* Verschluesselt einen Datenblock der Laenge len von source nach dest,
 * mit der Permutation perm der Laenge plen
 */

extern void decrypt (const char *source, char *dest, int len,
		     int plen, const int *perm);
/* Entschluesselt einen Datenblock der Laenge len von source nach dest,
 * mit der Permutation perm der Laenge plen
 * (Die Permutation sollte die selbe sein wie bei encrypt(), sollte
 * also nicht invertiert sein)
 */

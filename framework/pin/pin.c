/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 3: Brechen von EC-Karten PINs                     *
**                                                           *
**************************************************************
**
** pin.c Headerfile für den PIN-Versuch
**/

#include <stdio.h>
#include <stdlib.h>

#include "pin.h"

int diff1, diff2;

int pin[9000], prob[9000];

/*
 * index - die Position der Zahl in der PIN
 * n - die Zahl [0..9]
 *
 * Die erste 1 hat eine Wahrscheinlichkeit von 4 (keine führende 0 und A = 10 -> 0 -> 1).
 * 0 - 5 (nicht erste 1) haben eine Wahrscheinlichkeit von 2 (z.B. C = 12 -> 2).
 * 6 - 9 haben eine Wahrscheinlichkeit von 1.
 */
int getProbability(int index, int n){
    if ((index == 0) && (n == 1)){
        return 4;
    }
    if ((index == 0) && (n > 1) && (n < 6)){
        return 2;
    }
    if ((index != 0) && (n > -1) && (n < 6)){
        return 2;
    }
    if ((n > 5) && (n < 10)){
        return 1;
    }
    return 0;
}

/*
 * Zwei Elemente tauschen.
 */
void swap(int *xp, int *yp){
    int temp = *xp;
    *xp = *yp;
    *yp = temp;
}

/*
 * Ein Sortieralgorithmus mit der Anpassung des Arrays von PINs.
 */
void selectionSort(int arr[], int index[]){
    for (int i = 0; i < 100; i++){
        int maxI = i;
        for (int j = i + 1; j < 9000; j++){
            if (arr[j] > arr[maxI]){
                maxI = j;
            }
        }
        swap(&arr[maxI], &arr[i]);
        swap(&index[maxI], &index[i]);
    }
}

/*
 * Das Ergebnis des letzten Tests war 418 Treffer in 3000 Versuchen (13.9%).
 */
void attack(void)
{
    // Array von Wahrscheinlichkeiten in Abhängigkeit von Position in PIN [0-3] und Zahl [0-9].
    int probabilityOfNumberInPosition[4][10];

    // Berechnung der Wahrscheinlichkeit für alle möglichen Zahlen in PINs.
    for (int i = 3; i > -1; i--){
        int d1 = diff1 % 10;
        diff1 /= 10;
        int d2 = diff2 % 10;
        diff2 /= 10;
        for (int j = 0; j < 10; j++){
            probabilityOfNumberInPosition[i][j] = getProbability(i, j) * getProbability(i, (10 + j - d1) % 10) * getProbability(i, (10 + j - d2) % 10);
        }
    }

    // Berechnung der Wahrscheinlichkeit für alle möglichen PINs (prob[]) und Speicherung von PINs (pin[]).
    for (int i = 0; i < 9; i++){
        for (int j = 0; j < 10; j++){
            for (int k = 0; k < 10; k++){
                for (int t = 0; t < 10; t++){
                    prob[i * 1000 + j * 100 + k * 10 + t] = probabilityOfNumberInPosition[0][i + 1] * probabilityOfNumberInPosition[1][j] * probabilityOfNumberInPosition[2][k] * probabilityOfNumberInPosition[3][t];
                    pin[i * 1000 + j * 100 + k * 10 + t] = (i + 1) * 1000 + j * 100 + k * 10 + t;
                }
            }
        }
    }

    // Sortierung des Arrays von Wahrscheinlichkeiten, um die 100 wahrscheinlichsten PINs zu finden.
    selectionSort(prob, pin);

    // Testen von 100 PINs auf Gültigkeit.
    int index = try_pins(pin, try_max());
    if (index != -1){
        printf("Die PIN ist: %d\n", pin[index]);
    }
}

int main(void)
{
	open_connection(0, &diff1, &diff2);
	attack();
	close_connection();
	exit(0);
}

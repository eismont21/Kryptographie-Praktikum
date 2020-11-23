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


int pin[9000], prob[9000], try[9000];

int getProbabilityFirst(int n){
    if (n == 1){
        return 4;
    } else if ((n > 1) && (n < 6)){
        return 2;
    } else if ((n > 5) && (n < 10)){
        return 1;
    }
    return 0;
}

int getProbabilityNotFirst(int n) {
    if ((n > -1) && (n < 6)) {
        return 2;
    } else if ((n > 5) && (n < 10)) {
        return 1;
    }
    return 0;
}

void swap(int *xp, int *yp){
    int temp = *xp;
    *xp = *yp;
    *yp = temp;
}

void selectionSort(int arr[], int index[]){
    int i, j, max_idx;
    for (i = 0; i < 100; i++){
        max_idx = i;
        for (j = i+1; j < 9000; j++){
            if (arr[j] > arr[max_idx]){
                max_idx = j;
            }
        }
        swap(&arr[max_idx], &arr[i]);
        swap(&index[max_idx], &index[i]);
    }
}

int attack(void)
{
  /*>>>>                                                      <<<<*/
  /*>>>>  Aufgabe: Bestimmen die PIN                          <<<<*/
  /*>>>>                                                      <<<<*/

    int probabilityOfNumberInPosition[4][10];
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 10; j++){
            probabilityOfNumberInPosition[i][j] = 0;
        }
    }

    int x = diff1;
    int y = diff2;

    int poolPin1[4], poolPin2[4];

    for (int i = 3; i > -1; i--){
        poolPin1[i] = x % 10;
        x /= 10;
        poolPin2[i] = y % 10;
        y /= 10;
    }


    for (int i = 0; i < 10; i++){
        probabilityOfNumberInPosition[0][i] = getProbabilityFirst(i) * getProbabilityFirst(abs(i - poolPin1[0])) * getProbabilityFirst(abs(i - poolPin2[0]));
    }

    for (int i = 1; i < 4; i++){
        for (int j = 0; j < 10; j++){
            probabilityOfNumberInPosition[i][j] = getProbabilityNotFirst(i) * getProbabilityNotFirst(abs(i - poolPin1[0])) * getProbabilityNotFirst(abs(i - poolPin2[0]));
        }
    }

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

    selectionSort(prob, pin);
    int index = try_pins(pin, try_max());
    if (index != -1){
        printf("Die PIN ist: %d\n", pin[index]);
    } else {
        printf("ne ugadal");
    }
    return index;
}

int main(void)
{
    int col = 0;
    for (int i = 0; i < 100; i++){
        open_connection(0, &diff1, &diff2);
        if (attack() != -1){
            col++;
        };
        close_connection();
    }
    printf("colichestvo: %d\n", col);
	//open_connection(0, &diff1, &diff2);
	//attack();
	//close_connection();
	exit(0);
}

#include <stdio.h>

int main() {
    int height;

    do {
        printf("Entrez la hauteur de la pyramide (un entier positif) : ");
        if (scanf("%d", &height) != 1) {
            printf("Ce n'est pas un entier valide. Essayez encore.\n");
            while (getchar() != '\n');
            height = 0;
        } else if (height <= 0) {
            printf("La hauteur doit être un entier positif. Essayez encore.\n");
        }
    } while (height <= 0);

    for (int i = 1; i <= height; i++) {
        for (int j = 0; j < height - i; j++) {
            printf(" ");
        }
        for (int k = 0; k < i; k++) {
            printf("#");
        }
        printf("  ");
        for (int k = 0; k < i; k++) {
            printf("#");
        }
        printf("\n");
    }

    return 0;
}
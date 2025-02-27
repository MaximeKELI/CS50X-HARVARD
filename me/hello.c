#include <stdio.h>

int main() {
    char nom[100];

    printf("Entrez votre nom : ");
    scanf("%99s", nom);

    // Affichez le message de salutation avec une virgule et un retour à la ligne
    printf("hello, %s\n", nom);

    return 0;
}
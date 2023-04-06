#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define MSG_LEN 100000
#define VIEW_MESSAGE 0

/**
 * @brief Euclid's algorithm to find the greatest common divisor of two integers
 */
int gcd(int a, int b) {
    int tmp = 0;
    while (b) {
        tmp = a;
        a = b;
        b = tmp % b;
    }
    return a;
}

/**
 * @brief Generate public key
 */
int public_key(int totient) {
    int e = 0;
    int coprime = 0;

    for (e = 2; e < totient; e++) {
        coprime = gcd(e, totient);
        if (coprime == 1) {
            break;
        }
    }
    return e;
}

/**
 * @brief Generate private key
 */
int private_key(int totient, int e) {
    int d = 0;
    for (int z = 1; z < totient; z++) {
        if (((z * totient) + 1) % e == 0) {
            d = ((z * totient) + 1) / e;
            break;
        }
    }
    return d;
}

/**
 * @brief Encrypt a message.
 */
void encrypt(int e, int n, char message[], int encrypted[]) {
    int cipher = 1;
    int len = strlen(message);
    for (int i = 0; i < len; i++) {
        for (int j = 1; j <= e; j++) {
            cipher = (cipher * message[i]) % n;
        }
        encrypted[i] = cipher;
        cipher = 1;
    }
}

/**
 * @brief Decryption of the ciphertext.
 */
void decrypt(int d, int n, char message[], int encrypted[], int decrypted[]) {
    int plain = 1;
    int len = strlen(message);
    for (int i = 0; i < len; i++) {
        for (int j = 1; j <= d; j++) {
            plain = (plain * encrypted[i]) % n;
        }
        decrypted[i] = plain;
        plain = 1;
    }
}

/**
 * @brief Driver code.
 */
int main(int argc, char* argv[]) {
    int p = 157;
    int q = 151;

    int n = p * q;
    int totient = (p - 1) * (q - 1);
    int e = public_key(totient);
    int d = private_key(totient, e);

    char message[MSG_LEN];
    int encrypted[MSG_LEN];
    int decrypted[MSG_LEN];

    struct timeval start, end;

    FILE* fp = fopen("data.txt", "r");
    if (fp == NULL) {
        printf("[!] Error opening file");
    }
    while (fgets(message, sizeof(message), fp) != NULL)
        ;
    fclose(fp);

    gettimeofday(&start, NULL);
    encrypt(e, n, message, encrypted);
    decrypt(d, n, message, encrypted, decrypted);
    gettimeofday(&end, NULL);

    printf("Public key: %d\n", e);
    printf("Private key: %d\n", d);
#if VIEW_MESSAGE
    printf("Original message: %s\n", message);
    printf("Encrypted message: ");
    for (int i = 0; i < strlen(message); i++) printf("%c", encrypted[i]);
    printf("\n");
    printf("Decrypted message: ");
    for (int i = 0; i < strlen(message); i++) printf("%c", decrypted[i]);
#endif
    double exec_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("Time taken: %f seconds.\n", exec_time);

    return 0;
}
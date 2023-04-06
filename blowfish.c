#include "inc/blowfish.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "inc/const.h"
#include "inc/impl.h"

int main(int argc, char* argv[]) {
    FILE *fptr, *f1;
    int status = 0;
    uint64_t hash_original, hash_encrypted;
    double runtime, rate;

    size_t filesize;
    char ch;

    char* filepath = "blowfish-data.txt";

    uint32_t* file = readfile(&filesize, filepath);

    size_t numblocks = filesize / sizeof(uint32_t);

    printf("[BLOWFISH] INFO: File size = %zu bytes, numblocks = %zu\n", filesize, numblocks / 2);

    // Encryption key

    char* key = "TESTKEY";

    printf("[BLOWFISH] INFO: Key = %s, length = %zu\n", key, strlen(key));

    // Create Blowfish context

    blowfish_context_t* context = malloc(sizeof(blowfish_context_t));

    if (!context) {
        printf("[BLOWFISH] ERR: Could not allocate enough memory!\n");
        return -1;
    }

    // Initialize key schedule
    status = blowfish_init(context, key, strlen(key));
    if (status) {
        printf("[BLOWFISH] ERR: Error initiating key\n");
        return -1;
    } else {
        printf("[BLOWFISH] INFO: Key schedule complete!\n");
    }

    // Hash original file
    hash_original = hash(file, numblocks);

    printf("[BLOWFISH] DBG: Original hash = %llx\n", (unsigned long long)hash_original);
    f1 = fopen("data.txt", "r");

    printf("[BLOWFISH] INFO: Encryption begins\n");

    blowfish_encryptptr(context, file, numblocks, &runtime, &rate);

    hash_encrypted = hash(file, numblocks);

    printf("[BLOWFISH] INFO: Encryption success\n");
    printf("[BLOWFISH] INFO: Time taken: %lf milliseconds\n", runtime * 1e3);
    printf("[BLOWFISH] INFO: Average speed: %lf MB/s\n", rate / MEGABYTE);
    printf("[BLOWFISH] INFO: Encrypted hash = %llx\n", (unsigned long long)hash_encrypted);
    fptr = fopen("encrypted.txt", "w");
    char b[100];
    sprintf(b, "%" PRIu64, hash_encrypted);
    fputs(b, fptr);

    blowfish_decryptptr(context, file, numblocks, &runtime, &rate);

    fptr = fopen("blowfish-decrypted.txt", "w");

    while ((ch = fgetc(f1)) != EOF) fputc(ch, fptr);

    blowfish_clean(context);

    free(file);
    fclose(f1);
    fclose(fptr);
    return 0;
}

#ifndef IMPL_H_
#define IMPL_H_

#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "blowfish.h"
#include "const.h"

void blowfish_encryptptr(blowfish_context_t* context, uint32_t* ptr, size_t numblocks,
                         double* runtime, double* rate) {
    size_t pos = 0;
    double start, end, local_runtime;
    start = omp_get_wtime();

#pragma omp parallel for
    for (pos = 0; pos < numblocks; pos += 2) {
        blowfish_encryptblock(context, ptr + pos, ptr + pos + 1);
    }

    end = omp_get_wtime();
    local_runtime = end - start;

    if (runtime) *runtime = local_runtime;

    if (rate) *rate = ((double)numblocks * sizeof(uint32_t)) / (local_runtime);
}

void blowfish_decryptptr(blowfish_context_t* context, uint32_t* ptr, size_t numblocks,
                         double* runtime, double* rate) {
    size_t pos = 0;
    double start, end, local_runtime;
    start = omp_get_wtime();

#pragma omp parallel for
    for (pos = 0; pos < numblocks; pos += 2) {
        blowfish_decryptblock(context, ptr + pos, ptr + pos + 1);
    }

    end = omp_get_wtime();
    local_runtime = end - start;

    if (runtime) *runtime = local_runtime;

    if (rate) *rate = ((double)numblocks * sizeof(uint32_t)) / (local_runtime);
}

#endif

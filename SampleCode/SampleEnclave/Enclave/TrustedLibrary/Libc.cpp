/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <string.h>
#include <time.h>
#include <math.h>

#include "sgx_cpuid.h"

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"

#define BILLION  1000000000.0

/* ecall_malloc_free:
 *   Uses malloc/free to allocate/free trusted memory.
 */
void ecall_malloc_free(void)
{
    void *ptr = malloc(100);
    assert(ptr != NULL);
    memset(ptr, 0x0, 100);
    free(ptr);
}

/* ecall_sgx_cpuid:
 *   Uses sgx_cpuid to get CPU features and types.
 */
void ecall_sgx_cpuid(int cpuinfo[4], int leaf)
{
    sgx_status_t ret = sgx_cpuid(cpuinfo, leaf);
    if (ret != SGX_SUCCESS)
        abort();
}

extern "C" sgx_status_t trts_mprotect(size_t start, size_t size, uint64_t perms);
extern "C" sgx_status_t trts_mmap(size_t start, size_t size);
extern "C" sgx_status_t trts_munmap(size_t start, size_t size);

extern uint8_t __ImageBase;


void perform_test(size_t start, size_t size)
{
    memset((void *) start, 0, size);

    long double trials = 1000.0;

    long double* trial_times = (long double*)malloc((int)trials * sizeof(long double));
    long double* ocall_times = (long double*)malloc((int)trials * sizeof(long double));

    long start_time[2], end_time[2];
    long double average_time_mprotect = 0.0;
    long double average_time_ocall = 0.0;

    /* Time mprotect and overhead */
    for (int i = 0; i < trials; i++)
    {
        //get mprotect timings
        ocall_gettime(start_time);
        trts_mprotect(start, size, 0x4);
        // trts_mprotect(start, size, 0x7);
        trts_munmap(start, size);
        trts_mmap(start, size);
        ocall_gettime(end_time);

        if (end_time[1] - start_time[1] < 0 || end_time[0] - start_time[0] < 0)
        {
            // repeat attempted trial if data is invalid
            i = i -1;
            continue;
        }
        trial_times[i] = ((end_time[1] - start_time[1]) + (end_time[0] - start_time[0]) / BILLION);
        average_time_mprotect = average_time_mprotect + trial_times[i] ;
    }
    //get ocall overhead timings
    for (int i = 0; i < trials; i++)
    {
        ocall_gettime(start_time);
        ocall_nothing();
        ocall_gettime(end_time);
        if (end_time[1] - start_time[1] < 0 || end_time[0] - start_time[0] < 0)
        {
            // repeat attempted trial if data is invalid
            i = i -1;
            continue;
        }
        
        ocall_times[i] = ((end_time[1] - start_time[1]) + (end_time[0] - start_time[0]) / BILLION);
        average_time_ocall = average_time_ocall + ocall_times[i];
    }

    //get means
    long double mprotect_time = average_time_mprotect/trials;
    long double ocall_time = average_time_ocall/trials;

    //compute standard deviation & CI
    long double mprotect_deviation = 0;
    long double mprotect_sumsqr = 0;
    long double ocall_deviation = 0;
    long double ocall_sumsqr = 0;

    for (int i = 0; i < trials; i++)
    {
        mprotect_deviation = trial_times[i] - mprotect_time;
        mprotect_sumsqr += mprotect_deviation * mprotect_deviation;

        ocall_deviation = ocall_times[i] - ocall_time;
        ocall_sumsqr += ocall_deviation * ocall_deviation;
    }
    long double mprotect_var = mprotect_sumsqr/trials;
    long double ocall_var = ocall_sumsqr/trials;

    long double mprotect_stddeviation = sqrt(mprotect_var);
    long double ocall_stddeviation = sqrt(ocall_var);

    long double CI_mprotect = 1.962 * (mprotect_stddeviation/sqrt(trials));
    long double CI_Ocall = 1.962 * (ocall_stddeviation/sqrt(trials));

    printf("mprotect time without ocall: %Lf s\n", mprotect_time - ocall_time);
    printf("mprotect time confidence interval: %Lf s\n\n", CI_mprotect);
}


void ecall_test_mprotect(void)
{
    //allocate pages
    size_t start = (size_t) malloc(4096 * 129); //allocate 256 pages - reuse pages for 1, 2, 4, 8, 16, .... 

    //align start to page boundary
    start = (start +  4096 - 1) & ~(4096  - 1);

    size_t size[8] = {4096, 4096*2, 4096 * 4, 4096 *8,4096 *16,4096 *32,4096 *64, 4096 * 128};
    int page = 1;
    for (int i = 0; i < 8; i++)
    {
        printf("Page Size: %d\n", page);
        perform_test(start, size[i]);
        page *= 2;
    }
    // free malloc space
    printf("done");
    // free(&start);
    // free(size);
}
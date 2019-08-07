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
#include "sgx_cpuid.h"

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"

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
extern uint8_t __ImageBase;

void ecall_test_mprotect(void)
{
    //allocate pages
    size_t start = (size_t) malloc(4096 + 4096);
    start = (start + 4096 - 1) & ~(4096 - 1);
    size_t size  = 4096; // One page (4KB)

    memset((void *) start, 0, size);
    
    unsigned long start_time, end_time;
    unsigned long average_time_mprotect = 0.0;
    unsigned long average_time_ocall = 0.0;
    int trials = 10000;

    /* Time mprotect and overhead */
    for (int i = 0; i < trials; i++)
    {
        //get mprotect timings
        ocall_gettime(&start_time);
        trts_mprotect(start, size, 0x4);
        // trts_mprotect(start, size, 0x7);
        ocall_gettime(&end_time);
        
        if ((end_time - start_time) < 0)
        {
            average_time_mprotect += 1000000000 + end_time - start_time;
        }

        else 
        {
            average_time_mprotect += end_time - start_time;
        }   
    }

    //get ocall overhead timings
    for (int i = 0; i < trials; i++)
    {
        ocall_gettime(&start_time);
        ocall_nothing();
        ocall_gettime(&end_time);

        if ((end_time - start_time) < 0)
        {
            average_time_ocall += 1000000000 + end_time - start_time;
        }

        else 
        {
            average_time_ocall += end_time - start_time;
        }   
    }

    unsigned long mprotect_time = average_time_mprotect/trials;
    unsigned long ocall_time = average_time_ocall/trials;

    printf("\nAverage trts_mprotect time: %lu ns \n", mprotect_time);
    printf("Average ocall time: %lu ns\n", ocall_time);
    printf("mprotect time without ocall: %lu ns\n\n", mprotect_time - ocall_time);
}
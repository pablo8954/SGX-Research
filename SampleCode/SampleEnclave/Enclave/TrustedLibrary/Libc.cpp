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


// void perform_test(size_t start, size_t size)
// {
//     memset((void *) start, 0, size);

//     unsigned long start_time[2], end_time[2];
//     double average_time_mprotect = 0.0;
//     long double average_time_ocall = 0.0;
//     int trials = 1;

//     /* Time mprotect and overhead */
//     for (int i = 0; i < trials; i++)
//     {
//         //get mprotect timings
//         ocall_gettime(start_time);
//         //trts_mprotect(start, size, 0x4);
//         //trts_mprotect(start, size, 0x7);
//         trts_munmap(start, size);
//         trts_mmap(start, size);
//         ocall_gettime(end_time);

//         average_time_mprotect = (end_time[1] - start_time[1]) + (end_time[0] - start_time[0]) / BILLION;
//         for (int j = 0; j < 2; j++){
//             if (j ==0){
//                 printf("NANO: %lu\n", start_time[i]);
//             }
//             else{
//                 printf("SEC: %lu\n", start_time[i]);
//             }
//         }

//         for (int j = 0; j < 2; j++){
//             if (j ==0){
//                 printf("NANO: %lu\n", end_time[i]);
//             }
//             else{
//                 printf("SEC: %lu\n", end_time[i]);
//             }
//         }
//     }
//     //get ocall overhead timings
//     for (int i = 0; i < trials; i++)
//     {
//         ocall_gettime(start_time);
//         ocall_nothing();
//         ocall_gettime(end_time);
//         printf("__________");
//         average_time_ocall = (end_time[1] - start_time[1]) + (end_time[0] - start_time[0]) / BILLION;
//         for (int j = 0; j < 2; j++){
//             if (j ==0){
//                 printf("NANO: %lu\n", start_time[i]);
//             }
//             else{
//                 printf("SEC: %lu\n", start_time[i]);
//             }
//         }

//         for (int j = 0; j < 2; j++){
//             if (j ==0){
//                 printf("NANO: %lu\n", end_time[i]);
//             }
//             else{
//                 printf("SEC: %lu\n", end_time[i]);
//             }
//         }
//     }
//     printf("Average Time Mprotect: %f\n", average_time_mprotect);
//     printf("Average Time Ocall: %f\n", average_time_ocall);

//     // unsigned long mprotect_time = average_time_mprotect/trials;
//     // unsigned long ocall_time = average_time_ocall/trials;

//     // printf("\nAverage trts_mprotect time: %f s \n", mprotect_time);
//     // printf("Average ocall time: %f s\n", ocall_time);
//     // printf("mprotect time without ocall: %f s\n\n", mprotect_time - ocall_time);
// }


void test_entry(void)
{
    printf("HELLO WORLD");
}

void ecall_test_mprotect(void)
{
    /* 
    Todo: Create array of all the page sizes
    
    loop the tests through them
        modify the timings to not be in nanoseconds
    
    donzo
    
    */
    void* ptr = (void*) &test_entry;

    size_t size = 4096;
    //align start to page boundary 
    size_t start = ((uintptr_t)ptr +  4096 - 1) & ~(4096  - 1);
    trts_mprotect(start, size*2, 0x7);
    test_entry();



    // //allocate pages
    // size_t start = (size_t) malloc(4096 + 4096); //allocate 256 pages - reuse pages for 1, 2, 4, 8, 16, .... 

    // //align start to page boundary
    // start = (start +  4096 - 1) & ~(4096  - 1);
    // size_t size  = 4096; // One page (4KB)


    // for (int i = 0; i < 1; i++)
    // {
    //     perform_test(start, size);
    // }
    // // free malloc space
}


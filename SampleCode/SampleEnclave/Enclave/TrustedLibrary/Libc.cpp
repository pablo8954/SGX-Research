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

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "sgx_cpuid.h"
#include "../../../../linux-sgx/common/inc/internal/rts.h"
#include "../../../../linux-sgx/sdk/trts/trts_emodpr.h"
#include "../../../../linux-sgx/common/inc/internal/arch.h"

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"
#include "sgx_arch.h"
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
extern "C" sgx_status_t NesTEE_trts_mprotect(size_t start,size_t size, uint64_t perms);

extern uint8_t __ImageBase;

char* helloWorld (void)
{
   // TEST CASE: Basic Array Allocator
   // Code for basic allocator sourced from GeekforGeeks 
   int val = 256;
   char* buffer = (char*)malloc(val);
   int cx;
   cx = snprintf(buffer, val,"Starting Allocation||");
   int* ptr;
   int n,i;
   ptr = (int*)malloc(n*sizeof(int));

   for (int i = 0; i < n; i++)
   {
   ptr[i] = i + 1;
   }
   snprintf(buffer + cx,val - cx,"Memory Allocated, returning back to APP||");
   free(ptr);
   return buffer; 
}

void ecall_test_mprotect(void)
{
    //set up timing experiment
    long trials = 1000.0;
    long* execution_time = (long *)malloc((int)trials * sizeof(long));
    
    long start_time[2], end_time[2];
    long average_execution_time = 0.0;
    char* log = NULL;
    for (int i = 0; i < trials; i++)
    {
      	ocall_gettime(start_time);
      	log = helloWorld();
        ocall_gettime(end_time);
        if (i < trials -1)
	{
	   free(log);
	}
	
	if (end_time[1] - start_time[1] < 0 || end_time[0] - start_time[0] < 0)
	{
	   // repeat attempted trial if data is invalid
	   i = i -1;
	   continue;
	}
	execution_time[i] = ((end_time[1] - start_time[1]) * BILLION) + (end_time[0] - start_time[0]);
	average_execution_time = average_execution_time + execution_time[i];
    }
 	// print log output
	printf("%s \n", log);
	
        //get averages
	long execution_time_measured = average_execution_time/trials;
	
	//compute standard deviation & CI
	long deviation = 0;
	long sumsqr = 0;
	
	for (int i = 0; i < trials; i++)
	     {
	       deviation = execution_time[i] - execution_time_measured;
	       sumsqr += deviation * deviation;
	     }
	long var = sumsqr/trials;
	
	long stddeviation = sqrt(var);
	
	long CI_execution = 1.962 * (stddeviation/sqrt(trials));
	
	printf("\n\nExecution Timing: %lu ns\n", execution_time_measured);
	printf("Confidence Interval: %lu ns\n", CI_execution);
}

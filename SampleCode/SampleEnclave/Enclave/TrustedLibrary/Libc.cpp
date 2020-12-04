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

void NesTEE_Entry(size_t *page, size_t *stack, void* fun_addr)
{
   __asm__ __volatile__(
        // Unprotext NesTEE Page
        "mov $06H, %%eax \n"
        "mov $7, %%rbx \n" //TODO: verify this line is correct SECINFO_RWX
        "mov %0, %%rcx \n"
        "ENCLU \n"
        
        // Check ENCLU parameters
        "cmp $06H, %%eax \n" 
        "jne Crash \n"
        "cmp %0, %%rcx \n"
        "jne Crash \n"
        
        // Set up secure stack
        "mov %%rsp, %%rbx \n"
        "mov %1, %%rsp \n"
        "push %rbx \n"


        // Go to NesTEE LibOS
        "jmp %2"//TODO: find how to force the jump to NesTEE_LibOS_Start()"
        :: "r" (page), 
        "z" (stack), 
        "x" (fun_addr)
        );
        // TODO: ask whether we need 'PR' SECINFO.Flags to be set to 1 (p.19 of manual)
}

// void* ptr = (void*) &NesTEE_LibOS_Start()

void NesTEE_Exit(size_t *page, size_t *stack)
{
    unsigned long long emodpr = 0x0e;
   __asm__ __volatile__(

        // protect the NesTEE page
        "mov %1, %eax"
        "mov $1, %rbx"
        "mov %0, %rcx"
        "ENCLU"

        // check enclu parameters
        "cmp %1, %eax"
        "jne Crash"
        "cmp $1, %rbx"
        "jne Crash"
        "cmp %0, %rcx"
        "jne Crash"

        // restore user stack
        "pop %rbx"
        "mov %2, %rsp"

        //return to caller
        "ret"
        :: "r" (page), "a" (emodpr), "b" (stack)
        ); 
}

void NesTEE_Crash(int)
{
   __asm__ __volatile__("HLT"); 
}

void
__attribute__((section(".security_monitor"), unused))
helloWorld (void)
{
    printf("HELLO WORLD");
}

void ecall_test_mprotect(void)
{

    void* ptr = (void*) &helloWorld; //test entry function
    //ptr = 0x7fbbb8002000

    size_t size = 4096;
    //align start to page boundary 
    size_t start = ((uintptr_t)ptr +  4096 - 1) & ~(4096  - 1);
    trts_mprotect(start, size*1, 0x1);
    printf("Addr: %p\n", start);
    helloWorld();
}

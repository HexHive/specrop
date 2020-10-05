#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include <sys/mman.h>
#include "config.h"
#include "util.h"

char FR_buffer[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

void __attribute__((optimize(0))) malicious_foo(char *c) {
  c[0] = c[1] ^ c[2];
}

void __attribute__((optimize(0))) harmless_foo(char *c) {
  c[512] = c[513];
}

uint64_t __attribute__((aligned(PAGE_SIZE))) run(void (**ptr)(char *), char *FR_buffer, volatile unsigned *junk) {
  uint64_t tsc;

  /* Flush phase of Flush+Reload */
  _mm_clflush(FR_buffer);
  // _mm_mfence();
  busy_wait(junk);

  /* Access part */
  (*ptr)(FR_buffer);

  /* Reload phase of Flush+Reload */
  tsc = _rdtscp((unsigned int *)junk);
  *junk = *junk ^ FR_buffer[0];
  tsc = _rdtscp((unsigned int *)junk) - tsc;

  return tsc;
}

uint64_t __attribute__((aligned(PAGE_SIZE))) get_relevant_bits() {
  uint64_t relevant_bits = 0;

  void (**ptr)(char *);
  ptr = malloc(MAX(sizeof(*ptr), 2 * CL_SIZE));
  *ptr = malicious_foo;

  for(unsigned bits = 12; bits < 47; bits++) {
    uint64_t (*run_copy)(void (**)(char *), char *, volatile unsigned *);
    run_copy = FLIP_BIT(run, bits);
    if(run_copy != mmap(run_copy, PAGE_SIZE, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) {
      // printf("Unable to mmap page flipping bit 2^%d\n", bits);
      continue;
    }

    memcpy(run_copy, run, PAGE_SIZE);
    VERIFY(mprotect(run_copy, PAGE_SIZE, PROT_READ | PROT_EXEC) == 0, "Making page executable failed");

    // printf("***************** Run for bit flip: %d *****************\n", bits);
    // printf("run: %p run_copy: %p diff: %"PRIx64"\n", run, run_copy, XOR(run, run_copy));
    for(int i = 29; i >= 0; i--) {
      uint64_t tsc;
      if(i % 6 != 0){
        *ptr = malicious_foo;
        tsc = run(ptr, FR_buffer, &junk);
      } else {
        *ptr = harmless_foo;
        _mm_clflush(ptr);
        tsc = run_copy(ptr, FR_buffer, &junk);
        
        if(i == 0)
          relevant_bits |= (tsc > L1_THRESHOLD)? 1ull << bits: 0;
      }
      // printf("Timestamp: %"PRIu64" %s\n", tsc, (i % 6 == 0)? " Poisoned?": "");
    }

    VERIFY(munmap(run_copy, PAGE_SIZE) == 0, "munmap failed?");
  }

  free(ptr);
  return relevant_bits;
}

int main() {

  /* All bits are relevant to begin with */
  uint64_t bits = -1, new_bits = -1, tmp;
  int confidence = 0;

  do {
    do {
      bits = new_bits;
      tmp = get_relevant_bits();
      new_bits = bits & tmp;
      printf("Remaining relevant bits %"PRIx64"\n", new_bits);
    } while(bits != new_bits);

    confidence++;
  } while(confidence < 5);

  printf("Final relevant bits %"PRIx64"\n", new_bits);
}
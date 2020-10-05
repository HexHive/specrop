#pragma once
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <x86intrin.h>
#include <sys/types.h>

#define BLOCK_SIZE 256
#define MAX_VAL    255

volatile char FR_array[(MAX_VAL + 1) * BLOCK_SIZE] __attribute__((aligned(BLOCK_SIZE)));
int order[MAX_VAL + 1] __attribute__((aligned(BLOCK_SIZE)));

volatile void* FR_init() {
  srand(__rdtsc() ^ getpid());

  /* Generating 'random' permutation of 0...MAX_VAL
    * to store in order. This permutation will be used for
    * accesses to hopefully disable hardware stride prefetcher */
  for(int i = 0; i <= MAX_VAL; i++)
    order[i] = -1;
  for(int i = 0; i <= MAX_VAL; i++) {
    int rand_idx;
    do {
      rand_idx = rand() & MAX_VAL;
    } while(order[rand_idx] != -1);
    order[rand_idx] = i;
  }
  volatile char *ptr = FR_array;
  for(int i = 0; i <= MAX_VAL; i++) {
    *ptr = 0xff;
    ptr += BLOCK_SIZE;
  }

  return FR_array;
}

void FR_flush() {
  volatile char *ptr = FR_array;
  for(int i = 0; i <= MAX_VAL; i++) {
    _mm_clflush((void *)ptr);
    _mm_mfence();
    ptr += BLOCK_SIZE;
  }
}

char glob_junk;
void FR_reload(bool *accessed, uint64_t threshold) {
  unsigned junk = 0xde;
  uint64_t tsc;
  uint64_t tscs[MAX_VAL + 1];

  for(int i = 0; i <= MAX_VAL; i++) {
    int idx = order[i];
    volatile char *ptr = &FR_array[idx * BLOCK_SIZE];
    tsc = __rdtscp(&junk);
    junk ^= *ptr;
    tscs[idx] = __rdtscp(&junk) - tsc;
    _mm_clflush((void *)ptr);

    accessed[idx] = (tscs[idx] < threshold);
  }
  glob_junk ^= junk;

  for(int i = 0; i <= MAX_VAL; i++){
      printf("%5"PRIu64", " , tscs[i]);
      if((i + 1) % 16 == 0)
        printf("\n");
  }
  printf("\n");
}

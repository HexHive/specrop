#define _GNU_SOURCE
#include <inttypes.h>
#include <x86intrin.h>

#include "config.h"
#include "macros.h"
#include "synch.h"
#include "util.h"
#include "gadgets_description.h"

volatile void __attribute__((aligned(4096))) **ptr_ptr;
volatile void __attribute__((aligned(4096))) *ptr;

/************** vulnerable leaky code ******************/
uint64_t __attribute__((aligned(4096)))
smotherSpectreIter(uint64_t __attribute__((unused)) bit_offset, synch *s, uint64_t secret) {
  register uint64_t tsc, tmp;
  unsigned junk;
  register void __attribute__((unused)) *first_jmp;

  const uint64_t sources[] = {0xcafebabe, 0xdeadbeed, 0xabcdabcd, 0xc001d00d};
  SET_GP_REGISTERS(sources);

  /* set and flush the indirect jump target */
  /* This usage of '&&' is a GCC extension and might 
   * not work on other compilers */
  ptr_ptr = &ptr;
  ptr = &&TARGET;
  _mm_clflush(&ptr);
  _mm_clflush(&ptr_ptr);

  synch_sync(s);

  /* prepare branch predictor state */
  asm("BEG:;");
  JMPNEXT64

  /* indirect jump : BTI gadget*/
  PADDING(1);
  asm("JUMP:;");
  JMP_EXPL(*ptr_ptr, "rcx");
  PADDING(256);

  /* victim's real target - do nothing */
TARGET:
  asm("TARGET:;");
  asm("jmp END;");
  PADDING(256);

  /* Shifts by various lengths */
  SHIFT_JUMPN(7, ptr, secret);
  SHIFT_JUMPN(6, ptr, secret);
  SHIFT_JUMPN(5, ptr, secret);
  SHIFT_JUMPN(4, ptr, secret);
  SHIFT_JUMPN(3, ptr, secret);
  SHIFT_JUMPN(2, ptr, secret);
  SHIFT_JUMP1(ptr, secret);

  /* Smother gadget */
  asm("SPECULATE_THIS:;");
  VICTIM_GADGET(secret)
  asm("lfence;" :::);

  /* gather timing information (dead code) */
  tsc = __rdtscp(&junk);
  CRC32(1)
  tsc = __rdtscp(&junk) - tsc;

  asm("END:;");

  return tsc;
}

int __attribute__((aligned(4096)))
main(int argc, char **argv) {
  synch s;
  unsigned core, i, j, k;

  /* DEBUG */
  printf("SMotherspectre iter: %p\n", smotherSpectreIter);

  /* Verify args */
	VERIFY(argc >= 4, "Usage: ./victim <core> <data output folder> <secret>\n");
	sscanf(argv[1], "%u", &core);
  pin(core);

  /* Connect to shared memory for synchronization */
  synch_connect(&s);

  char *secret = argv[3];
  PADDING(0xaa);
  
  for(i = 0; i < NCHARS;i++) {
    for(j = 0; j < NBITS; j++)
      for(k = 0; k < NSAMPLES; k++)
        smotherSpectreIter(0, &s, secret[i]);
  }
}

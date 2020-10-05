#define JMPNEXT \
    asm("cmp    %%rax,%%rax;" \
        "jle label%=;" \
        "label%=:;" \
        : : :);
        
#define JMPNEXT1 JMPNEXT
#define JMPNEXT2 JMPNEXT1 JMPNEXT1
#define JMPNEXT4 JMPNEXT2 JMPNEXT2
#define JMPNEXT8 JMPNEXT4 JMPNEXT4
#define JMPNEXT16 JMPNEXT8 JMPNEXT8
#define JMPNEXT32 JMPNEXT16 JMPNEXT16
#define JMPNEXT64 JMPNEXT32 JMPNEXT32
#define JMPNEXT128 JMPNEXT64 JMPNEXT64
#define JMPNEXT256 JMPNEXT128 JMPNEXT128
#define JMPNEXT512 JMPNEXT256 JMPNEXT256
#define JMPNEXT1024 JMPNEXT512 JMPNEXT512
#define JMPNEXT2048 JMPNEXT1024 JMPNEXT1024
#define JMPNEXT4096 JMPNEXT2048 JMPNEXT2048

#define SET_GP_REGISTERS(source) asm ( \
      "mov %0, %%r12;"  \
      "mov %1, %%r13;"  \
      "mov %2, %%r14;"  \
      "mov %3, %%r15;"  \
      : \
      : "ri" ((source)[0]), "ri" ((source)[1]), \
        "ri" ((source)[2]), "ri" ((source)[3])  \
      : "r12", "r13", "r14", "r15"  \
      );

#define CRC32_all asm volatile( \

#define CRC32(N)                        \
    asm(".rept " #N ";"                 \
        "crc32 %%r12, %%r12;"           \
        "crc32 %%r13, %%r13;"           \
        "crc32 %%r14, %%r14;"           \
        ".endr;"                        \
        ::: "r12", "r13", "r14", "r15");

#define OR(N)                           \
    asm(".rept " #N ";"                 \
        "or %%r13, %%r12;"              \
        "or %%r14, %%r13;"              \
        "or %%r15, %%r14;"              \
        "or %%rsi, %%r15;"              \
        ".endr;"                        \
        ::: "r12", "r13", "r14", "r15");

#define PADDING(N) \
    asm(".rept " #N "; nop; .endr;")

#define JMP_EXPL(PTR, RXX)               \
    asm("movq %[target], %%" RXX ";"        \
        "jmp *%%" RXX ";":: [target] "r" (PTR): )

#define JMPM(PTR)   \
    asm("jmp *%[target];" :: [target] "m" (PTR));

#define JMPR(PTR)   \
    asm("jmp *%[target];" :: [target] "r" (PTR));

/* Separate shift jump macros for shifts of 1 and N
 * This is to keep the length of code for both sequences = 16B */
#define SHIFT_JUMP1(PTR, SECRET) \
    asm("shr $1, %[secret];":: [secret] "r" (SECRET): ); \
    PADDING(1); \
    JMPM(PTR); \
    PADDING (4090);

#define SHIFT_JUMPN(OFF, PTR, SECRET) \
    asm("shr %[offset], %[secret];":: [offset] "i" (OFF), [secret] "r" (SECRET)); \
    JMPM(PTR); \
    PADDING (4090);

#define SHIFT_JUMPA(OFF, PTR, SECRET) \
    PADDING(4); \
    JMPM(PTR);  \
    PADDING(4090)  

#define SIZEOF_SHIFT_JUMP  4096  

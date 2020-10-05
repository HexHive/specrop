.PHONY: all clean run
all: expt

clean: 
	rm expt
	rm chaining_expt_*

expt: main.c flush_reload.c config.h
	gcc -g -O2 main.c -lpthread -o expt

run: expt
	for n in `seq 0 9`; do for i in `seq 1 1000`; do ./expt ; done > chaining_results_expt_$n ; done
	./process.py


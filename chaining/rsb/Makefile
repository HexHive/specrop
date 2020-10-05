expt:
	gcc-4.8 -O0  -o expt  helper_func.S rsb.c

run: expt
	for i in `seq 1 1000`; do ./expt ; done
	mv 1.txt expt-data.txt
	./process.py
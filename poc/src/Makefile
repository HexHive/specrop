
.PHONY: clean all check_offsets

all: attack victim orchestrator

clean:
	rm -f attack victim orchestrator *.csv

attack: attack.c config.h gadgets_description.h macros.h synch.h util.h 
	gcc -g -O1 -fPIC attack.c -lpthread -lrt -o attack

victim: victim.c config.h gadgets_description.h macros.h synch.h util.h 
	gcc -g -O1 -fPIC victim.c -lpthread -lrt -o victim

orchestrator: orchestrator.c synch.h config.h
	gcc -g orchestrator.c -lpthread -lrt -o orchestrator
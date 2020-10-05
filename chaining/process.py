#!/usr/bin/env python3
import matplotlib.pyplot as plt
import string
import statistics

def main():
    threshold = 100

    procs = ['expt'] # Can be '6700K', etc. Assumes files called "chaining_results_<proc>_<i>"
    n_iters = 10
    max_chain_length = 8

    f = plt.figure()
    for proc in procs:
        victim_chains_runs = []
        for iter in range(0, n_iters):
            with open('chaining_results_' + proc + '_' + str(iter), 'r') as res:
                attack_chains = [0] * 16
                victim_chains = [0] * 16

                for n in range(0, 1000):
                    victim_timings = res.readline()
                    # Ignore next seven lines
                    for i in range(0, 7):
                        res.readline()

                    attack_timings = res.readline()
                    # Ignore next seven lines
                    for i in range(0, 7):
                        res.readline()

                    # Ignore blank line
                    res.readline()

                    reloaded = [int(x) < threshold for x in victim_timings.rstrip().split(',') if x != '']
                    reloaded_at = [int(x) < threshold for x in attack_timings.rstrip().split(',') if x != '']

                    #print(str(n) + attack_timings)
                    for i in range(0,16):
                        if(reloaded[i]):
                            victim_chains[i] += 1
                        if(reloaded_at[i]):
                            attack_chains[i] += 1

                # attack_chains = [ x/1000 for x in attack_chains]       
                # plt.plot(range(1, 9), attack_chains[1:9], 'r--', label = 'attack')

                # This is the probability on one run of 1000 repetitions
                victim_chains = [x / 1000 for x in victim_chains] 
                victim_chains_runs.append(victim_chains)

        # transpose list of lists, to put values for one chain length in a single list
        victim_chains_runs = list(map(list, zip(*victim_chains_runs)))
        # Snip to max number of chaining wanted
        victim_chains_runs = victim_chains_runs[0:max_chain_length]

        # Get Statistics
        mean_runs = [sum(x) / len(x) for x in victim_chains_runs]
        median_runs = [statistics.median(x) for x in victim_chains_runs]
        max_runs = [max(x) for x in victim_chains_runs]
        min_runs = [min(x) for x in victim_chains_runs]

        # Plot centred around median
        central_line = median_runs
        updiff = [(x[0] - x[1]) for x in zip(max_runs, central_line)]
        lodiff = [(x[0] - x[1]) for x in zip(central_line, min_runs)]


        # Plot central, with error bars for max and min
        x = range(1, max_chain_length + 1)
        label = 'i7-' + proc
        if label.endswith('_ucode'):
            label = label[:-6] + ' (factory)'
        plt.errorbar(x, central_line, yerr = [lodiff, updiff], uplims=True, lolims=True, label = label, capsize=3)
        
    size=15
    #plt.title('Indirect jumps chained')
    plt.xlabel('Number of gadgets chained (with indirect jumps)', fontsize=size)
    plt.ylabel('Fraction of runs $n^{th}$ gadget reached', fontsize=size)
    plt.legend(loc='upper right', fontsize=size)
    plt.tick_params(labelsize=size * 0.8)
    f.savefig('bti_prob.pdf', bbox_inches='tight')

    # plt.show()
    plt.savefig('bti_prob.png')


if __name__ == '__main__':
  main()

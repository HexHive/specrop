#!/usr/bin/env python3
import matplotlib.pyplot as plt
import string
import statistics

proc_data = {}

def load_data(core, niters = 10):

	with open(core + '-data.txt', 'r') as data_file:
		max_chain_length = 11

		data = []
		for i in range(0, max_chain_length):
			data.append([])

		for iter in range(0, niters):

			for i in range(0, max_chain_length):
				line = data_file.readline().split()

				if(int(line[0]) != i + 1):
					print('Unexpected input')
					exit(1)

				data[i].append(int(line[1]) / 1000)

			# Ignore two empty lines
			for i in range(0, 2):
				data_file.readline()


	proc_data[core] = data

def plot_pdfs(max_chain_length = 8):
	
	f = plt.figure()
	for proc, data in proc_data.items():
		data = data[0:max_chain_length]
		max_proc = [max(x) for x in data]
		min_proc = [min(x) for x in data]
		med_proc = [statistics.median(x) for x in data]

		x = range(1, max_chain_length + 1)
		updiff = [(x[0] - x[1]) for x in zip(max_proc, med_proc)]
		lodiff = [(x[0] - x[1]) for x in zip(med_proc, min_proc)]
		plt.errorbar(x, med_proc, yerr = [lodiff, updiff], uplims=True, lolims=True, label = proc, capsize=3)
		# print(proc)
		# print(max_proc)
		# print(med_proc)
		# print(min_proc)

	size=15
	plt.xlabel('Number of gadgets chained (with indirect jumps)', fontsize=size)
	plt.ylabel('Fraction of runs $n^{th}$ gadget reached', fontsize=size)
	plt.legend(loc='upper right', fontsize=size)
	plt.tick_params(labelsize=size * 0.8)
	plt.show()
	f.savefig('rsb_chaining_prob.pdf', bbox_inches='tight')

def main():
	cores = ['expt'] # ['i7-6700K', 'i7-8700', 'E5-1620']
	for core in cores:
		load_data(core)
	plot_pdfs()
	# while True:
	# 	pass

if __name__ == '__main__':
  main()

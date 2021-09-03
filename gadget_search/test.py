#! /usr/bin/env python3
from z3 import *
from capstone.x86 import *
import analyzer
import semantics
import instruction_properties
import formatting
import sys
import binary_walker
import x86_model
from tqdm import tqdm
import constraints
import argparse
import pickle
import ntpath
import os.path
from os import path

def gadget_chaining_store(all_gadgets, cache_file):
    chains = []

    loading_from = dict(map(lambda r: (r, []), x86_model.GPR))
    loading_to = dict(map(lambda r: (r, []), x86_model.GPR))
    shifting_from = dict(map(lambda r: (r, []), x86_model.GPR))
    # FIXME do deepcopy using package copy

    for gadget_index in tqdm(range(len(all_gadgets))):
        gadget_info = all_gadgets[gadget_index]
        code_snippet = gadget_info[0]

        solv = semantics.gadget_to_constraints(code_snippet) # To get the gadget simplification into constraints
        n_instr = len(code_snippet) # If checking last state, do it against 'n_instr - 1'

        # Adding the constraints
        if solv.check() == z3.sat: # Condition for fixed values, e.g. ax_0 should be 7
            last_ins = gadget_info[0][-1]

            for reg in x86_model.GPR:
                solv.push()
                solv.add(constraints.is_shifted_left(reg, n_instr))
                check = solv.check()
                solv.pop()
                if check == z3.unsat: # TODO and instruction_properties.not_as_operand(last_ins, reg):
                    shifting_from[reg].append(gadget_index)

                solv.push()
                solv.add(constraints.is_loaded_from(reg, n_instr))
                check = solv.check()
                solv.pop()
                if check == z3.unsat: # TODO and instruction_properties.not_as_operand(last_ins, reg):
                    loading_from[reg].append(gadget_index)

                solv.push()
                solv.add(constraints.is_loaded_to(reg, n_instr))
                check = solv.check()
                solv.pop()
                # TODO check if register is used for jump
                if check == z3.unsat: # TODO and instruction_properties.not_as_operand(last_ins, reg):
                    loading_to[reg].append(gadget_index)

    # Store as an array of bits over the all_gadgets array denoting the constraints they meet
    # Or better: As the starting addresses
    with open(cache_file, 'wb') as cache_gadgets_file:
        pickle.dump((loading_from, shifting_from, loading_to), cache_gadgets_file)
    print("Gadgets stored in cache file " + cache_file)
    return

def gadgets_chaining_load_analyze(all_gadgets, cache_file, options=["shifting"], **kwargs):
    (loading_from,shifting_from,loading_to) = pickle.load(open(cache_file, 'rb'))

    if "loading_from" in options:
    # TODO make the function always load the results
        print("### LOADING FROM ###")
        for k in loading_from.keys():
            print(k)
            for loading_from_index in loading_from[k]:
                gadget = all_gadgets[loading_from_index]
                print(formatting.format_gadget(gadget))
    if "loading_to" in options:
        print("### LOADING TO ###")
        for k in loading_to.keys():
            print(k)
            for loading_to_index in loading_to[k]:
                gadget = all_gadgets[loading_to_index]
                print(formatting.format_gadget(gadget))
    if "shifting" in options:
        print("### SHIFTING ###")
        for k in shifting_from.keys():
            print(k)
            for shifting_from_index in shifting_from[k]:
                gadget = all_gadgets[shifting_from_index]
                print(formatting.format_gadget(gadget))
            print()
    if "reverse_shifting" in options:
        for k in shifting_from.keys():
            count = len(shifting_from[k]) * len(loading_from[k]) * len(loading_to[k])
            print("Gadgets working by shifting " + str(k) + ": " + str(count))
            for shift_index in shifting_from[k]:
                shift = all_gadgets[shift_index] # TODO the same for all
                for load_src in all_gadgets[loading_from[k]]:
                    for load_dst in all_gadgets[loading_to[k]]:
                        full_chain = []
                        full_chain += load_dst[0][:-1]
                        full_chain += shift[0][:-1]
                        full_chain += load_src[0]
                        print(formatting.format_gadget((full_chain, load_dst[1], load_src[2])))
                        print("Entry points")
                        print(load_dst[1])
                        print(shift[1])
                        print(load_src[1])
    # TODO rank the gadgets
    return

def data_movement(all_gadgets):
    covered = []
    c_len = len(x86_model.GPR)*(len(x86_model.GPR)-1)
    for gadget_info in tqdm(all_gadgets):
        if(len(covered) == c_len):
            print("all data movement combinations covered")
            break

            ## TODO better use a list of booleans and index over it
            for reg_src in x86_model.GPR:
                dest_GPR = x86_model.GPR.copy()
                dest_GPR.remove(reg_src)
                for reg_dest in dest_GPR:
                    if (reg_src, reg_dest) in covered:
                        continue
                    solv.push()
                    solv.add(BitVec(reg_dest+"_"+str(n_instr-1), x86_model.BS) !=
                             BitVec(reg_src+"_0", x86_model.BS))
                    if solv.check() == z3.unsat:
                        solv.pop()
                        covered.append((reg_src, reg_dest))
                        print("added {}".format(str((reg_src, reg_dest))))
                        break
                    solv.pop()

    print("Information flow: {}".format(str(covered)))
    print("Data movements covered : {}".format(len(covered)))
    print("Not included: ", end = '')
    for reg_src in x86_model.GPR:
        dest_GPR = x86_model.GPR.copy()
        dest_GPR.remove(reg_src)
        for reg_dest in dest_GPR:
            if (reg_src, reg_dest) not in covered:
                print(str((reg_src, reg_dest)) + ", ", end='')
    print()

def first_mov_from_mem(insns):
    counter = 0
    for i in insns:
        counter += 1
        if instruction_properties.is_mov(i) and instruction_properties.op1_reg(i) and i.operands[1].type == X86_OP_MEM:
            break
    return counter


def main(filename, register=x86_model.REG_MAPPING["rdi"], offset=0x78, analyze=True, check_data_movement=False, **kwargs):
    print("Disassemblying...")
    contents, start_address = analyzer.file_code_info(sys.argv[1])

    print("Finding gadgets...")
    orig_g, alig_g, unalig_g = binary_walker.find_gadgets(contents, **kwargs)

    all_gadgets = orig_g + alig_g + unalig_g
    print("Number of gadgets: {}".format(len(all_gadgets)))
    print("Unaligned gadgets: {}".format(len(unalig_g)))

    print("Gadgets meeting specifications: ")
    cache_file = ntpath.basename(filename) + '.cache'
    if not path.exists(cache_file):
        print("Cache file doesn't exist, creating... " + cache_file)
        # Store the indexes of each type of gadget in the cache file
        gadget_chaining_store(all_gadgets, cache_file)
    if analyze:
        gadgets_chaining_load_analyze(all_gadgets, cache_file, **kwargs)
    if check_data_movement:
        data_movement(all_gadgets)
    return

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print(formatting.bcolors.FAIL + "ERROR: Invalid number of arguments" + formatting.bcolors.ENDC + """
USAGE: ./test.py library.so [options1=value1 option2=value2...]""")
        exit()
    to_analyze = sys.argv[1]
    processing_options = {}
    # Parsing options
    for option in sys.argv[2:]:
        print(option)
        s = option.split('=')
        processing_options[s[0]] = s[1]
    print("Processing `{}` with options: {}".format(to_analyze, str(processing_options)))
    main(to_analyze, **processing_options)


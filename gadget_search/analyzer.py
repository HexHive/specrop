from capstone import *
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
import sys
import x86_model
import instruction_properties
import formatting
import binary_walker

def print_instructions(insns):
    for ins in insns:
        print("Instruction at 0x{:x}".format(ins.address))
        for x in range (0,8):
            print("0x{:x} ".format(contents[ins.address+x]), end='')
        print("\n\t", end='')
        print(formatting.format_ins(ins))

def raw_contents(contents):
    for bi in range(len(contents)):
        print("0x{:x} ".format(contents[bi]), end='')
    print()

def search_opcodes(contents):
    for x in range(len(contents)):
        if contents[x] == 0xFF:
            print("ind jump: 0x{:x}".format(x))
            for ins in binary_walker.dism(contents[x:-1], 0):
                print("0x{:x} ".format(contents[ins.address]), end='')
            print()
        if contents[x] == 0xC3:
            print("return: 0x{:x}".format(x))
            raw_contents(contents[x:-1])

# given a list of instructions and the beginning point,
def add_until_mispred(insns):
    if (insns == [] or instruction_properties.is_ret(insns[0]) or instruction_properties.subtle_to_ind_jump_mispred(insns[0])): return []
    return ([insns[0]] + add_until_mispred(insns[1:]))

def print_file_ins(insns):
    for i in insns: print(formatting.ins_info(i))

def gadgets_info(gadgets, list_only_shift_jump=True):
    r_str = ""
    map_gadgets = dict(map(lambda index: (index, gadgets[index]), range(len(gadgets)))) # A dictionary index-gadget

    r_str += ("Number of gadgets: {}".format(len(gadgets))) + "\n"
    gadgets_shift = set(filter(lambda index: any(list(map(lambda y: instruction_properties.is_shift(y), gadgets[index][0]))), map_gadgets.keys()))
    r_str += ("Number of gadgets with shift modifications: {}".format(len(gadgets_shift))) + "\n"
    gadgets_arithm = set(filter(lambda index: any(list(map(lambda y: instruction_properties.is_arithm(y), gadgets[index][0]))), map_gadgets.keys()))
    r_str += ("Number of gadgets with arithm modifications: {}".format(len(gadgets_arithm))) + "\n"
    gadgets_ret_mispr = set(filter(lambda index: any(list(map(lambda y: instruction_properties.is_ret(y), gadgets[index][0]))), map_gadgets.keys()))
    r_str += ("Number of new gadgets with instructions subtle to return misprediction: {}".format(len(gadgets_ret_mispr))) + "\n"
    gadgets_ind_jump_mispr = set(filter(lambda index: any(list(map(lambda y: instruction_properties.subtle_to_ind_jump_mispred(y), gadgets[index][0]))), map_gadgets.keys()))
    r_str += ("Number of new gadgets with instructions subtle to jump misprediction: {}".format(len(gadgets_ind_jump_mispr))) + "\n"
    gadgets_shift_ind_jump = gadgets_shift.intersection(gadgets_ind_jump_mispr)
    r_str += ("Number of new gadgets with shift and indirect jump: {}".format(len(gadgets_shift_ind_jump))) + "\n"

    # R_Str +=  gadgets obtained + "\n"
    for index in gadgets_shift_ind_jump:
        r_str += formatting.format_gadget(map_gadgets[index])

    return (r_str, len(gadgets_shift_ind_jump))

def file_code_info(filename):
    fd = open(filename, 'rb')
    # contents = fd.read()
    # start_address = 0
    elf = ELFFile(fd)
    code = elf.get_section_by_name('.text')
    contents = code.data()
    start_address = code['sh_addr']
    return (contents, start_address)

from capstone import *
from capstone.x86 import *
import instruction_properties
from tqdm import tqdm

GADGETS_LENGTH = 6 # in instructions # FIX determined by the speculative window, as input to the function

def reset_state(ins):
    return instruction_properties.is_jump_call(ins) or instruction_properties.is_cond_jump(ins) or instruction_properties.is_ret(ins) or instruction_properties.is_halt(ins)

# List of capstone instructions return
def dism(byte_array, start_address):
    insns = []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True # It will ignore the invalid instructions and decode them as data (with ".byte" mnemo)
    # md.skipdata_setup = ("db", None, None) # Customize action when bad instruction found

    for insn in md.disasm(byte_array, start_address):
        insns.append(insn)

    return insns

# From each end_point, get all possible gadgets, the onesgot with
# natural disassembly and the ones that add new instructions when
# starting from another point
def find_gadgets(contents, ignore_reset=True, check_data_movement=False, **kwargs):
    original_gadgets = []
    aligned_gadgets = []
    unaligned_gadgets = []
    decoded_ins = set() # Byte addresses of the decoded instructions
    insns = dism(contents, 0)
    # TODO condition used as function argument
    end_points = list(filter(lambda index:
                             instruction_properties.is_ret(insns[index]) or
                             instruction_properties.subtle_to_ind_jump_mispred(insns[index])
                             # instruction_properties.is_endbr(insns[index])
                             , range(len(insns))))

    for end_point_index in tqdm(range(len(end_points))):
        end_point = end_points[end_point_index]
        end_point_address = insns[end_points[end_point_index]].address

        st = 0
        if end_point > GADGETS_LENGTH:
            st = end_point-GADGETS_LENGTH
        if end_point_index != 0 and insns[end_points[end_point_index-1]].address > insns[st].address:
            st = end_points[end_point_index-1]+1
        st_before_jumps = st

        if ignore_reset:
            # if jump, set start point in the next instruction
            for ins_index in range(st, end_point):
                if reset_state(insns[ins_index]):
                    st = ins_index+1

        # Retrieve original gadget
        original_gadgets.append((insns[st:end_point+1], insns[st].address, end_point_address))
        
        decoded_ins.add(insns[st].address) # Avoid original gadgets later

        address_instructions = []
        for x in range(st, end_point+1):
            address_instructions.append(insns[x].address)
 
        # From where do we start the decoding in the gadgets
        start_address = insns[st_before_jumps].address
        
        for b_offset in range(start_address+1, end_point_address): # We try with the possibles offset of bytes
            if b_offset in decoded_ins: # Same start point will produce same output
                continue
            
            new_insns = dism(contents[b_offset:end_point_address+insns[end_point].size], b_offset)

            # Compare the instructions obtained with the ones we have
            if new_insns != []: # If they differ in at least one instruction
                # We drop the instructions that are jumps, getting the index of the last one
                c = 0
                for ins_index in range(len(new_insns)-1):
                    if ignore_reset and reset_state(insns[ins_index]):
                        c = ins_index
                new_insns = new_insns[c:]

                if new_insns[0].address in decoded_ins:
                    continue
                
                decoded_ins.add(new_insns[0].address)

                if new_insns[0].address in address_instructions:
                    aligned_gadgets.append((new_insns, b_offset, end_point_address))
                else:
                    unaligned_gadgets.append((new_insns, b_offset, end_point_address))

    return (original_gadgets, aligned_gadgets, unaligned_gadgets)

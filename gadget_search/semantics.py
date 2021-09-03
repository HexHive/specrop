from z3 import *
from capstone.x86 import *
import x86_model
import formatting
import instruction_properties

# Used to model memory: Takes a bitvector and returns a new one
mem = Function('mem', BitVecSort(x86_model.BS), BitVecSort(x86_model.BS))

# Returns the constraint of a register must remain unmodified between origin and destiny
def unwritten_register_semantics(reg, origin, destiny):
    return(BitVec(reg+"_"+str(origin), x86_model.BS) == BitVec(reg+"_"+str(destiny), x86_model.BS))

# Keep the values from one step to another, except from a the registers given (it can be empty)
def keep_reg_values(regs, step):
    return list(map(lambda reg: unwritten_register_semantics(reg,step,step+1), list(filter(lambda x: x not in regs, x86_model.REGISTERS))))

# Tracks register overwriten assigning it to a fresh variable
def overwrite(reg, step):
    return(BitVec(reg+"_"+str(step), x86_model.BS) == BitVec("overwritten_"+str(step), x86_model.BS))

# For the encoding of instructions semantics, we have the next instructions
# IN: shift instruction (in capstone format), step we encode it in
# OUT: list of constraints for the solver

def arithm_semantics(insn, step): # The received instruction is in capstone format
    if insn.operands[0].type == X86_OP_REG:
        reg_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
        reg_src = BitVec(reg_name+"_"+str(step), x86_model.BS)
        reg_dest = BitVec(reg_name+"_"+str(step+1), x86_model.BS)
        constraints = keep_reg_values([reg_name], step)

        operand = BitVec(reg_name+"_sym_"+str(step),x86_model.BS) # FIXME when comes from memory! same in arithm etc.
        if insn.operands[1].type == X86_OP_IMM:
            operand = insn.operands[1].imm
        elif insn.operands[1].type == X86_OP_REG:
            operand = BitVec(x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[1].reg))]+"_"+str(step), x86_model.BS)

        if insn.mnemonic == "add":
            constraints.append(reg_dest == reg_src + operand)
            constraints.append(reg_src == BitVec("add_src_"+str(step), x86_model.BS))
            constraints.append(reg_dest == BitVec("add_dst_"+str(step), x86_model.BS))
        elif insn.mnemonic == "sub":
            constraints.append(reg_dest == reg_src - operand)
        constraints.append(overwrite(reg_name, step)) # Mark register overwritten
        return constraints
    else:
        print("arithm instruction not well formatted: %s" % formatting.format_ins(insn))

def logic_semantics(insn, step): # The received instruction is in capstone format
    if insn.operands[0].type == X86_OP_REG:
        reg_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
        reg_src = BitVec(reg_name+"_"+str(step), x86_model.BS)
        reg_dest = BitVec(reg_name+"_"+str(step+1), x86_model.BS)
        constraints = keep_reg_values([reg_name], step)

        if insn.mnemonic == "not":
            constraints.append(reg_dest == ~reg_src)
        else:
            operand = BitVec(reg_name+"_sym_"+str(step),x86_model.BS) # FIXME when comes from memory! same in arithm etc.
            if insn.operands[1].type == X86_OP_IMM:
                operand = insn.operands[1].imm
            elif insn.operands[1].type == X86_OP_REG:
                operand = BitVec(x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[1].reg))]+"_"+str(step), x86_model.BS)

            if insn.mnemonic == "and":
                constraints.append(reg_dest == reg_src & operand)
            elif insn.mnemonic == "or":
                constraints.append(reg_dest == reg_src | operand)
            elif insn.mnemonic == "xor":
                constraints.append(reg_dest == reg_src ^ operand)
        constraints.append(overwrite(reg_name, step)) # Mark register overwritten
        return constraints
    else:
        print("logic instruction not well formatted: %s" % formatting.format_ins(insn))


def shift_semantics(insn, step):
    if insn.operands[0].type == X86_OP_REG:
        reg_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
        reg_src = BitVec(reg_name+"_"+str(step), x86_model.BS)
        reg_dest = BitVec(reg_name+"_"+str(step+1), x86_model.BS)

        pos = 0 # FIX any other alternative?
        if insn.operands[1].type == X86_OP_IMM:
            pos = insn.operands[1].imm
        elif insn.operands[1].type == X86_OP_REG:
            pos_reg = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[1].reg))]
            pos = BitVec(pos_reg+"_"+str(step), x86_model.BS)

        constraints =  keep_reg_values([reg_name], step)

        if insn.mnemonic == "shl" or insn.mnemonic == "sal":
            constraints.append(reg_dest == reg_src << pos)
            constraints.append(reg_dest == BitVec("shl_dst_"+str(step), x86_model.BS))
            constraints.append(reg_src == BitVec("shl_src_"+str(step), x86_model.BS))
        elif insn.mnemonic == "shr":
            constraints.append(reg_dest == LShR(reg_src, pos))
            constraints.append(reg_dest == BitVec("shr_dst_"+str(step), x86_model.BS))
            constraints.append(reg_src == BitVec("shr_src_"+str(step), x86_model.BS))
        elif insn.mnemonic == "sar":
            constraints.append(reg_dest == reg_src >> pos)
            constraints.append(reg_dest == BitVec("shr_dst_"+str(step), x86_model.BS))
            constraints.append(reg_src == BitVec("shr_src_"+str(step), x86_model.BS))
        else:
            print("Undefined type of shift: " + str(insn.mnemonic))
        return constraints
    else:
        print("shift instruction not well formatted: %s" % formatting.format_ins(insn))

def rot_semantics(insn, step):
    if insn.operands[0].type == X86_OP_REG:
        reg_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
        reg_src = BitVec(reg_name+"_"+str(step), x86_model.BS)
        reg_dest = BitVec(reg_name+"_"+str(step+1), x86_model.BS)

        pos = 0 # FIX any other alternative?
        if insn.operands[1].type == X86_OP_IMM:
            pos = insn.operands[1].imm
        elif insn.operands[1].type == X86_OP_REG:
            pos_reg = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[1].reg))]
            pos = BitVec(pos_reg+"_"+str(step), x86_model.BS)

        constraints =  keep_reg_values([reg_name], step)
        # TODO split vector!
        if insn.mnemonic == "rcl" or insn.mnemonic == "rol": # TODO
            constraints.append(reg_dest == reg_src << pos)
            constraints.append(reg_dest == BitVec("rcl_dst_"+str(step), x86_model.BS))
            constraints.append(reg_src == BitVec("rcl_src_"+str(step), x86_model.BS))
        elif insn.mnemonic == "ror":
            constraints.append(reg_dest == LShR(reg_src, pos))
            constraints.append(reg_dest == BitVec("rcr_dst_"+str(step), x86_model.BS))
            constraints.append(reg_src == BitVec("rcr_src_"+str(step), x86_model.BS))
        elif insn.mnemonic == "rcr":
            constraints.append(reg_dest == reg_src >> pos)
            constraints.append(reg_dest == BitVec("rcr_dst_"+str(step), x86_model.BS))
            constraints.append(reg_src == BitVec("rcr_src_"+str(step), x86_model.BS))
        else:
            print("Undefined type of shift: " + str(insn.mnemonic))
        return constraints
    else:
        print("shift instruction not well formatted: %s" % formatting.format_ins(insn))

def pop_semantics(insn, step):
    if insn.operands[0].type == X86_OP_REG:
        reg_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
        reg_dest = BitVec(reg_name+"_"+str(step+1), x86_model.BS)
        reg_sp = BitVec(x86_model.REG_MAPPING["sp"]+"_"+str(step), x86_model.BS)
        reg_sp_end = BitVec(x86_model.REG_MAPPING["sp"]+"_"+str(step+1), x86_model.BS)
        
        constraints = keep_reg_values([reg_name], step)
        constraints.append(reg_dest == mem(reg_sp))
        constraints.append(reg_sp_end == reg_sp + 8)
        return constraints
    else:
        print("pop instruction not well formatted %s" % formatting.format_ins(insn))

def mov_semantics(insn, step):
    if insn.operands[0].type == X86_OP_REG:
        reg_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
        reg_dest = BitVec(reg_name+"_"+str(step+1), x86_model.BS)
        constraints =  keep_reg_values([reg_name], step)
        
        if insn.operands[1].type == X86_OP_IMM:
            orig = insn.operands[1].imm
            constraints.append(reg_dest == orig)
        elif insn.operands[1].type == X86_OP_REG:
            reg_src = BitVec(x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[1].reg))]+"_"+str(step), x86_model.BS)
            constraints.append(reg_dest == reg_src)
        elif insn.operands[1].type == X86_OP_MEM: # If comes from memory, make the register symbolic

            i = insn.operands[1]
            # if i.mem.segment != 0: # TODO use
            #     reg_segment = x86_model.REG_MAPPING[str(insn.reg_name(i.mem.segment))]
            if i.mem.base != 0:                
                reg_base = x86_model.REG_MAPPING[str(insn.reg_name(i.mem.base))]

                # FIXME change the semantics, create the variable depending on the base register: load_ax_0, this way checking is much easier. Also this way only we check unsat?
                index = 0
                if i.mem.index != 0:
                    index_reg = x86_model.REG_MAPPING[str(insn.reg_name(i.mem.index))]
                    index = BitVec(index_reg+"_"+str(step), x86_model.BS)
                scale = 1
                if i.mem.scale != 1:
                    scale = i.mem.scale
                displ = 0
                if i.mem.disp != 0:
                    displ = i.mem.disp # Is a number
                load_var = BitVec("load_"+str(step), x86_model.BS)
                constraints.append(reg_dest == load_var)
                reg_base_bv = BitVec(reg_base+"_"+str(step), x86_model.BS)
                constraints.append(BitVec("reg_base_"+str(step), x86_model.BS) == reg_base_bv)
                constraints.append(load_var == mem(reg_base_bv + displ + index*scale))
        constraints.append(overwrite(reg_name, step)) # Mark register overwritten
        return constraints
    else:
        print("move instruction not well formatted %s" % formatting.format_ins(insn))

def lea_semantics(insn, step):
    if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_MEM:
        reg_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
        reg_dest = BitVec(reg_name+"_"+str(step+1), x86_model.BS)
        constraints =  keep_reg_values([reg_name], step)
        
        i = insn.operands[1]
        
        # if i.mem.segment != 0: # TODO use
        #     reg_segment = x86_model.REG_MAPPING[str(insn.reg_name(i.mem.segment))]
        #     # print("reg_segment: %s" % reg_segment)
        if i.mem.base != 0:
            reg_base = x86_model.REG_MAPPING[str(insn.reg_name(i.mem.base))]
            # print("reg_base: %s" % reg_base)

            index = 0
            if i.mem.index != 0: # TODO use
                reg_index = x86_model.REG_MAPPING[str(insn.reg_name(i.mem.index))]
                # print("reg_index: %s" % reg_index)

            scale = 1
            if i.mem.scale != 1: # TODO use
                scale = i.mem.scale
            displ = 0
            if i.mem.disp != 0:
                displ = i.mem.disp # Is a number
                # print("displ: %s" % displ)
            constraints.append(reg_dest == BitVec(reg_base+"_"+str(step), x86_model.BS) + displ + index*scale)
        return constraints
    else:
        print("lea instruction not well formatted %s" % formatting.format_ins(insn))
    

def xchg_semantics(insn, step):
    if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_REG:
        reg_dest_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
        reg_src_name = x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[1].reg))]
        constraints = keep_reg_values([reg_src_name, reg_dest_name], step)
        constraints.append(BitVec(reg_src_name+"_"+str(step+1), x86_model.BS) == BitVec(reg_dest_name+"_"+str(step), x86_model.BS))
        constraints.append(BitVec(reg_dest_name+"_"+str(step+1), x86_model.BS) == BitVec(reg_src_name+"_"+str(step), x86_model.BS))
        return constraints
    else:
        print("xchg instruction not well formatted %s" % formatting.format_ins(insn))


# Input: set of instructions
# Output: Set of constraints to be applied, last step number
def gadget_to_constraints(insns):
    s = Solver()
    # constraints = []
    # for reg in x86_model.REGISTERS:
    #     constraints.append(BitVec(reg+"_start", x86_model.BS) == BitVec(reg+"_0", x86_model.BS))
    # s.add(constraints)
    step = 0
    for insn in insns:
        if instruction_properties.is_shift(insn) and instruction_properties.op1_reg(insn):
            s.add(shift_semantics(insn, step))
        elif instruction_properties.is_rotate(insn) and instruction_properties.op1_reg(insn):
            s.add(rot_semantics(insn, step))
        elif instruction_properties.is_arithm(insn) and instruction_properties.op1_reg(insn):
            s.add(arithm_semantics(insn, step))
        elif instruction_properties.is_logic(insn) and instruction_properties.op1_reg(insn):
            s.add(logic_semantics(insn, step))
        elif instruction_properties.is_pop(insn) and instruction_properties.op1_reg(insn):
            s.add(pop_semantics(insn, step))
        elif instruction_properties.is_lea(insn) and instruction_properties.op1_reg(insn):
            s.add(lea_semantics(insn, step))
        elif instruction_properties.is_mov(insn) and instruction_properties.op1_reg(insn):
            s.add(mov_semantics(insn, step))
        elif instruction_properties.is_xchg(insn):
            s.add(xchg_semantics(insn, step))
        elif instruction_properties.is_jump_call(insn): # All registers don't get modified
            () # Maybe return at this point?
        else:
            s.add(keep_reg_values([], step)) # All the registers remain unchanged
        step += 1
    return s

# Returns the main register used by the instructions, first operand,
# and in the case of being a memory address, returs the base register
def main_register(insn):
    if insn.operands[0].type == X86_OP_REG:
        return x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].reg))]
    elif insn.operands[0].type == X86_OP_MEM:
        return x86_model.REG_MAPPING[str(insn.reg_name(insn.operands[0].mem.base))]
    # Default case should't be reached

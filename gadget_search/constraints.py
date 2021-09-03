from z3 import BitVec
import x86_model
import semantics

# This constraints means that load address must be an specific
# register, so gadgets that don't meet it are the ones that use that
# register as base with an offset != 0
def concrete_load(first_mov, n_instr, reg, offset):
    constraints = []
    if first_mov == n_instr: return []

    # We use a pair of conditions, reducing this way the total number
    # of conditions and avoid a constraint per register
    load = BitVec("load_address", x86_model.BS)
    for s in range(0, first_mov):
        load_base = reg+"_"+str(s)
        load_address = semantics.mem(BitVec(load_base, x86_model.BS) + offset)
        constraints.append(load == load_address)
    for s in range(n_instr):
        constraints.append(BitVec("load_"+str(s), x86_model.BS) != load)
    return constraints

# Returns a list of constraints that must be pushed and popped to check if there's a load from the register specfied
def load_without_offset(first_mov, n_instr, reg): # FIX if register is overwritten e.g. mov bx, cx; mov ax, [cx] will be considered as a mov from cx because bx == cx at load time
    # Solution: maybe by ensuring start point, so at load time it should be the same
    constraints = []
    if first_mov == n_instr: return []

    # We use a pair of conditions, reducing this way the number of necessary conditions
    for s in range(n_instr):
        load_base = reg+"_"+str(s)
        constraints.append(BitVec("reg_base_"+str(s), x86_model.BS) != BitVec(load_base, x86_model.BS))
    return constraints

# SAT means is not modified
def unmodified_during_execution(src, dest, n_instr):
    last_reg = BitVec(dest+"_"+str(n_instr), x86_model.BS)
    constraints = [BitVec(src+"_0", x86_model.BS) != last_reg]
    for s in range(n_instr):
        constraints.append(BitVec(dest+"_"+str(s+1), x86_model.BS) != BitVec("load_"+str(s), x86_model.BS))
        constraints.append(BitVec(dest+"_"+str(s), x86_model.BS) != BitVec("overwritten_"+str(s), x86_model.BS))
    return constraints

def is_added(reg, n_instr): # FIX solve if register is load objective
    constraints = []
    for s in range(n_instr):
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("add_src_"+str(s), x86_model.BS))
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("add_dst_"+str(s), x86_model.BS))
    return constraints

def is_shifted_right(reg, n_instr): # FIX solve if register is load objective
    constraints = []
    for s in range(n_instr):
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("shr_src_"+str(s), x86_model.BS))
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("shr_dst_"+str(s), x86_model.BS))
    return constraints

def is_shifted_left(reg, n_instr): # FIX solve if register is load objective
    constraints = []
    for s in range(n_instr):
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("shl_src_"+str(s), x86_model.BS))
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("shl_dst_"+str(s), x86_model.BS))
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("rcl_src_"+str(s), x86_model.BS))
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("rcl_dst_"+str(s), x86_model.BS))
    return constraints


def is_rotated(reg, n_instr): # FIX solve if register is load objective
    constraints = []
    for s in range(n_instr):
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("rcr_src_"+str(s), x86_model.BS))
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("rcr_dst_"+str(s), x86_model.BS))
    return constraints

def is_loaded_from(reg, n_instr): # FIX solve if register is load objective
    constraints = []
    for s in range(n_instr):
        constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("reg_base_"+str(s), x86_model.BS))
    return constraints

def is_loaded_to(reg, n_instr): # FIX solve if register is load objective
    constraints = []
    for s in range(n_instr):
        constraints.append(BitVec(reg+"_"+str(s+1), x86_model.BS) != BitVec("load_"+str(s), x86_model.BS))
        # constraints.append(BitVec(reg+"_"+str(0), x86_model.BS) != BitVec("load_"+str(s), x86_model.BS))
    return constraints

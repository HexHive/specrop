from capstone.x86 import *
import x86_model

def is_shift(ins):
    return ins.mnemonic in ["shl", "shr", "sar", "sal"]

def is_rotate(ins):
    return ins.mnemonic in ["rcl", "rcr", "rol", "ror"] # TODO implement on semantics

def is_xchg(ins):
    return ins.mnemonic in ["xchg"] and ins.operands[0].type == X86_OP_REG  and ins.operands[1].type == X86_OP_REG

def is_lea(ins):
    return ins.mnemonic in ["lea"]

def is_logic(ins):
    return ins.mnemonic in ["or", "and", "xor", "not"]

def is_arithm(ins):
    return ins.mnemonic in ["add", "sub"] # TODO subb

def is_pop(ins):
    return ins.mnemonic in ["pop"]

def is_mov(ins): # TODO add mov instruction variante: movsxd, movsd...
    return ins.mnemonic in ["mov", "movsxd"]

def is_jump_call(ins):
    return ins.mnemonic in ["jmp", "call"]

# def is_jump_call(ins):
#     return ins.operands

def is_cond_jump(ins):
    return ins.mnemonic in ["ja", "jae", "jb", "jbe", "jc", "jcxz",
                            "jecxz", "je", "jg", "jge", "jl", "jna",
                            "jnae", "jn", "jnbe", "jnc", "jne", "jng",
                            "jnge", "jnl", "jnle", "jno", "jnp", "jns",
                            "jnz", "jo", "jp", "jpe", "jpo", "js", "jz"]


def subtle_to_ind_jump_mispred(ins): # Indirect jump and call # FIXME operand can be memory?
    return is_jump_call(ins) and any(list(map(lambda i: i.type == X86_OP_REG or i.type == X86_OP_MEM, ins.operands)))

def is_ret(ins):
    return ins.mnemonic in ["ret"]

def is_endbr(ins):
    return ins.mnemonic in ["endbr64"]

def is_halt(ins):
    return ins.mnemonic in ["hlt"]


def op1_reg(ins):
    return ins.operands[0].type == X86_OP_REG

def not_as_operand(ins, reg):
    cond = True
    if subtle_to_ind_jump_mispred(ins): # TODO we can also use `not `
        operand = ins.operands[0]
        if ins.operands[0].type == X86_OP_MEM:
            reg = ins.reg_name(operand.mem.base)
            cond = x86_model.REG_MAPPING[str(reg)] == reg
        elif ins.operands[0].type == X86_OP_REG:
            reg = ins.reg_name(operand.reg)
            cond = x86_model.REG_MAPPING[str(reg)] == reg

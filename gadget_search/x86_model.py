# https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture
# FIXME according to segments into the whole register!
REG_MAPPING = {"eax": "ax", "rax": "ax", "ax": "ax", "al": "ax", "ah": "ax",
               "ebx": "bx", "rbx": "bx", "bx": "bx", "bl": "bx", "bh": "bx",
               "ecx": "cx", "rcx": "cx", "cx": "cx", "cl": "cx", "ch": "cx",
               "edx": "dx", "rdx": "dx", "dx": "dx", "dl": "dx", "dh": "dx",
               "esp": "sp", "rsp": "sp", "sp": "sp", "spl": "sp",
               "ebp": "bp", "rbp": "bp", "bp": "bp", "bpl": "bp",
               "edi": "di", "rdi": "di", "di": "di", "dil": "di",
               "esi": "si", "rsi": "si", "si": "si", "sil": "si",
               "r8d": "r8", "r8": "r8", "r8w": "r8", "r8b": "r8",
               "r9d": "r9", "r9": "r9", "r9w": "r9", "r9b": "r9",
               "r10d": "r10", "r10": "r10", "r10w": "r10", "r10b": "r10",
               "r11d": "r11", "r11": "r11", "r11w": "r11", "r11b": "r11",
               "r12d": "r12", "r12": "r12", "r12w": "r12", "r12b": "r12",
               "r13d": "r13", "r13": "r13", "r13w": "r13", "r13b": "r13",
               "r14d": "r14", "r14": "r14", "r14w": "r14", "r14b": "r14",
               "r15d": "r15", "r15": "r15", "r15w": "r15", "r15b": "r15",
               "xmm0": "xmm0", "xmm1": "xmm1", "xmm2": "xmm2", "xmm3": "xmm3",
               "xmm4": "xmm4", "xmm5": "xmm5", "xmm6": "xmm6", "xmm7": "xmm7",
               "rip": "rip", "fs": "fs", "gs": "gs", "cs": "cs", "ds": "ds", "ss": "ss", "es": "es", "dr0" : "dr0", "cr0" : "cr0",  "cr1" : "cr1"
               }

# General Purpose Registers
GPR = ["ax", "bx", "cx", "dx", "di", "si", "sp", "bp",
       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

REGISTERS = set(REG_MAPPING.values())
BS = 64 # BitVector size

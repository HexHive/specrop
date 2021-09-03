class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def to_hex(s, prefix_0x = True):
    if prefix_0x:
        return " ".join("0x{0:02x}".format(c) for c in s)
    else:
        return " ".join("{0:02x}".format(c) for c in s)

def to_hex2(s):
    r = "".join("{0:02x}".format(c) for c in s)
    while r[0] == '0': r = r[1:]
    return r

def to_x(s):
    from struct import pack
    if not s: return '0'
    x = pack(">q", s)
    while x[0] in ('\0', 0): x = x[1:]
    return to_hex2(x)

def to_x_32(s):
    from struct import pack
    if not s: return '0'
    x = pack(">i", s)
    while x[0] in ('\0', 0): x = x[1:]
    return to_hex2(x)

def string_hex(code):
    result = ""
    for c in code:
        result += ("0x{:02x} ".format(c))
    result += "\n"
    return result

def format_ins(ins):
    st = ""
    for c in ins.bytes:
        st += ("0x{:02x} ".format(c))
    st += ("\t" + ins.mnemonic + " " + ins.op_str)
    return st
 
def ins_info(i):
    return "0x{:x}\t{} {}".format(i.address, i.mnemonic, i.op_str)

def format_gadget(gadget_with_info):
    (gadget, start, end) = gadget_with_info

    st = ("[0x{:x} - 0x{:x}]".format(start, end)) + "\n"
    for ins in gadget:
        # st += "\tPrefix:" + string_hex(ins.prefix)
        st += ("\t+"+ins_info(ins)) + "\t// " + string_hex(ins.bytes)
    return st

def reg_to_bin(reg):
    return format(int(reg[1:]), '05b')

def imm_to_bin(val, bits):
    val = int(val)
    if val < 0:
        val = (1 << bits) + val
    return format(val, f'0{bits}b')
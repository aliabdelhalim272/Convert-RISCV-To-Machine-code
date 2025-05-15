class TypeR:
    def __init__(self, funct7, rs2, rs1, funct3, rd, opcode):
        self.funct7 = funct7
        self.rs2 = rs2
        self.rs1 = rs1
        self.funct3 = funct3
        self.rd = rd
        self.opcode = opcode

    def to_bin(self):
        return self.funct7 + self.rs2 + self.rs1 + self.funct3 + self.rd + self.opcode

    def to_hex(self):
        return hex(int(self.to_bin(), 2))[2:].zfill(8)


class TypeI:
    def __init__(self, imm, rs1, funct3, rd, opcode):
        self.imm = imm
        self.rs1 = rs1
        self.funct3 = funct3
        self.rd = rd
        self.opcode = opcode

    def to_bin(self):
        return self.imm + self.rs1 + self.funct3 + self.rd + self.opcode

    def to_hex(self):
        return hex(int(self.to_bin(), 2))[2:].zfill(8)


class TypeS:
    def __init__(self, imm, rs2, rs1, funct3, opcode):
        self.imm = imm
        self.rs2 = rs2
        self.rs1 = rs1
        self.funct3 = funct3
        self.opcode = opcode

    def to_bin(self):
        imm7 = self.imm[:7]
        imm5 = self.imm[7:]
        return imm7 + self.rs2 + self.rs1 + self.funct3 + imm5 + self.opcode

    def to_hex(self):
        return hex(int(self.to_bin(), 2))[2:].zfill(8)


class TypeB:
    def __init__(self, imm, rs2, rs1, funct3, opcode):
        self.imm = imm
        self.rs2 = rs2
        self.rs1 = rs1
        self.funct3 = funct3
        self.opcode = opcode

    def to_bin(self):
        return f"{self.imm[0]}{self.imm[2:8]}{self.rs2}{self.rs1}{self.funct3}{self.imm[8:12]}{self.imm[1]}{self.opcode}"

    def to_hex(self):
        return hex(int(self.to_bin(), 2))[2:].zfill(8)


class TypeU:
    def __init__(self, imm, rd, opcode):
        self.imm = imm
        self.rd = rd
        self.opcode = opcode

    def to_bin(self):
        return self.imm + self.rd + self.opcode

    def to_hex(self):
        return hex(int(self.to_bin(), 2))[2:].zfill(8)


class TypeJ:
    def __init__(self, imm, rd, opcode):
        self.imm = imm
        self.rd = rd
        self.opcode = opcode

    def to_bin(self):
        return f"{self.imm[0]}{self.imm[10:20]}{self.imm[9]}{self.imm[1:9]}{self.rd}{self.opcode}"

    def to_hex(self):
        return hex(int(self.to_bin(), 2))[2:].zfill(8)
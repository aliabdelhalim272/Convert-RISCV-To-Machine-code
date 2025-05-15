import customtkinter as ctk
from tkinter import messagebox
import re

#===============================================
# RISC-V Converter Logic
#===============================================

# Register alias mapping
register_aliases = {
    'zero': 'x0',  'ra': 'x1',   'sp': 'x2',   'gp': 'x3',   'tp': 'x4',
    't0': 'x5',    't1': 'x6',   't2': 'x7',
    's0': 'x8',    'fp': 'x8',   # frame.pointer
    's1': 'x9',
    'a0': 'x10',   'a1': 'x11',  'a2': 'x12',  'a3': 'x13',
    'a4': 'x14',   'a5': 'x15',  'a6': 'x16',  'a7': 'x17',
    's2': 'x18',   's3': 'x19',  's4': 'x20',  's5': 'x21',
    's6': 'x22',   's7': 'x23',  's8': 'x24',  's9': 'x25',
    's10': 'x26',  's11': 'x27',
    't3': 'x28',   't4': 'x29',  't5': 'x30',  't6': 'x31'
}

def reg_to_bin(reg):
    """Convert register (e.g., 'x1') to 5-bit binary"""
    num = int(reg[1:])
    if 0 <= num <= 31:
        return format(num, '05b')
    raise ValueError(f"Invalid register: {reg}")

def imm_to_bin(imm, bits):
    """Convert immediate value to signed binary string"""
    try:
        if imm.startswith('-'):
            sign = -1
            imm = imm[1:]
        else:
            sign = 1
        if imm.startswith('0x'):
            val = int(imm, 16)
        elif imm.startswith('0b'):
            val = int(imm, 2)
        else:
            val = int(imm)
        val *= sign
        if -(1 << (bits - 1)) <= val <= (1 << (bits - 1)) - 1:
            return format(val & ((1 << bits) - 1), f'0{bits}b')
        raise ValueError(f"Immediate out of range: {imm}")
    except ValueError:
        raise ValueError(f"Invalid immediate value: {imm}")

class TypeR:
    """R-type instruction (register-register operations)"""
    def __init__(self, funct7, rs2, rs1, funct3, rd, opcode):
        self.binary = f"{funct7}{reg_to_bin(rs2)}{reg_to_bin(rs1)}{funct3}{reg_to_bin(rd)}{opcode}"
        if len(self.binary) != 32:
            raise ValueError("R-type binary length is not 32 bits")
    def to_bin(self): return self.binary
    def to_hex(self): return format(int(self.binary, 2), '08X')

class TypeI:
    """I-type instruction (immediate operations)"""
    def __init__(self, imm, rs1, funct3, rd, opcode):
        self.binary = f"{imm_to_bin(imm, 12)}{reg_to_bin(rs1)}{funct3}{reg_to_bin(rd)}{opcode}"
        if len(self.binary) != 32:
            raise ValueError("I-type binary length is not 32 bits")
    def to_bin(self): return self.binary
    def to_hex(self): return format(int(self.binary, 2), '08X')

class TypeS:
    """S-type instruction (store operations)"""
    def __init__(self, imm, rs2, rs1, funct3, opcode):
        imm_bin = imm_to_bin(imm, 12)
        self.binary = f"{imm_bin[0:7]}{reg_to_bin(rs2)}{reg_to_bin(rs1)}{funct3}{imm_bin[7:12]}{opcode}"
        if len(self.binary) != 32:
            raise ValueError("S-type binary length is not 32 bits")
    def to_bin(self): return self.binary
    def to_hex(self): return format(int(self.binary, 2), '08X')

class TypeB:
    """B-type instruction (branch operations)"""
    def __init__(self, imm, rs2, rs1, funct3, opcode):
        imm_bin = imm_to_bin(imm, 13)
        self.binary = f"{imm_bin[0]}{imm_bin[2:8]}{reg_to_bin(rs2)}{reg_to_bin(rs1)}{funct3}{imm_bin[8:12]}{imm_bin[1]}{opcode}"
        if len(self.binary) != 32:
            raise ValueError("B-type binary length is not 32 bits")
    def to_bin(self): return self.binary
    def to_hex(self): return format(int(self.binary, 2), '08X')

class TypeU:
    """U-type instruction (upper immediate)"""
    def __init__(self, imm, rd, opcode):
        self.binary = f"{imm_to_bin(imm, 20)}{reg_to_bin(rd)}{opcode}"
        if len(self.binary) != 32:
            raise ValueError("U-type binary length is not 32 bits")
    def to_bin(self): return self.binary
    def to_hex(self): return format(int(self.binary, 2), '08X')

class TypeJ:
    """J-type instruction (jump operations)"""
    def __init__(self, imm, rd, opcode):
        imm_bin = imm_to_bin(imm, 21)
        self.binary = f"{imm_bin[0]}{imm_bin[10:20]}{imm_bin[9]}{imm_bin[1:9]}{reg_to_bin(rd)}{opcode}"
        if len(self.binary) != 32:
            raise ValueError("J-type binary length is not 32 bits")
    def to_bin(self): return self.binary
    def to_hex(self): return format(int(self.binary, 2), '08X')

def validate_register(reg):
    """Check if register is valid (x0-x31 or alias)"""
    reg = reg.lower()  # Normalize to lowercase
    if reg in register_aliases:
        reg = register_aliases[reg]  # Map alias to xN (e.g., t0 → x5)
    elif reg.startswith('x') and reg[1:].isdigit() and 0 <= int(reg[1:]) <= 31:
        return True  # Already in xN format
    else:
        return False
    return reg.startswith('x') and reg[1:].isdigit() and 0 <= int(reg[1:]) <= 31

def validate_immediate(val, bits):
    """Check if immediate value fits in specified bits"""
    try:
        if val.startswith('0x'):
            num = int(val, 16)
        elif val.startswith('0b'):
            num = int(val, 2)
        else:
            num = int(val)
        return -(1 << (bits - 1)) <= num <= (1 << (bits - 1)) - 1
    except ValueError:
        return False

def parse_load_store(parts):
    """Parse load/store instructions with offset(rs1) format"""
    if len(parts) != 3:
        return None, None, None
    rd_or_rs2, offset_paren = parts[1], parts[2]
    match = re.match(r'(\d+|0x[0-9a-fA-F]+|0b[01]+)\((\w+)\)', offset_paren)
    if not match:
        return None, None, None
    offset, base = match.groups()
    # Convert base register to lowercase and map alias if necessary
    base = register_aliases.get(base.lower(), base.lower())
    return rd_or_rs2, offset, base

def tokenize_instruction(instr):
    """Tokenize instruction, removing comments and handling offset(rs1)"""
    instr = re.sub(r'#.*', '', instr).strip()
    if not instr or instr.isspace():
        return []
    offset_match = re.search(r'(\d+|0x[0-9a-fA-F]+|0b[01]+)\(\w+\)', instr)
    if offset_match:
        placeholder = "__OFFSET_PAREN__"
        instr = instr.replace(offset_match.group(0), placeholder)
        parts = re.split(r'[,\s]+', instr)
        parts = [p if p != placeholder else offset_match.group(0) for p in parts if p]
    else:
        parts = re.split(r'[,\s]+', instr)
        parts = [p for p in parts if p]
    return parts

def convert_instruction(instr):
    """Convert single RISC-V instruction to machine code"""
    parts = tokenize_instruction(instr)
    if not parts:
        return "Empty instruction", ""
    op = parts[0].lower()
    # Convert register aliases and normalize case
    parts = [register_aliases.get(p.lower(), p.lower()) for p in parts]

    # Basic validation of operation name
    if not re.match(r'^[a-z]+$', op):
        suggestions = []
        for valid_op in opcode_map.keys():
            if any(c in op for c in valid_op) and len(op) == len(valid_op):
                suggestions.append(valid_op)
        suggestion_str = f" Did you mean {' or '.join(suggestions)}?" if suggestions else ""
        return f"Invalid instruction name: {op}{suggestion_str}", ""

    # Supported instructions
    opcode_map = {
        "add":  ("0110011", "000", "0000000"),
        "sub":  ("0110011", "000", "0100000"),
        "addi": ("0010011", "000", ""),
        "lw":   ("0000011", "010", ""),
        "sw":   ("0100011", "010", ""),
        "beq":  ("1100011", "000", ""),
        "lui":  ("0110111", "", ""),
        "jal":  ("1101111", "", "")
    }

    # Handle pseudo-instructions
    if op == "li":
        if len(parts) != 3:
            return "Invalid number of operands for li, expected li rd, imm", ""
        rd, imm = parts[1], parts[2]
        if not (validate_register(rd) and validate_immediate(imm, 12)):
            return "Invalid operand(s) for li", ""
        obj = TypeI(imm, "x0", "000", rd, "0010011")
        return obj.to_bin(), obj.to_hex()

    if op not in opcode_map:
        return f"Unsupported instruction: {op}", ""

    try:
        if op in ("add", "sub"):
            if len(parts) != 4:
                return "Invalid number of operands, expected rd, rs1, rs2", ""
            rd, rs1, rs2 = parts[1:4]
            if not all(validate_register(r) for r in (rd, rs1, rs2)):
                return "Invalid register(s)", ""
            obj = TypeR(opcode_map[op][2], rs2, rs1, opcode_map[op][1], rd, opcode_map[op][0])

        elif op == "addi":
            if len(parts) != 4:
                return "Invalid number of operands, expected rd, rs1, imm", ""
            rd, rs1, imm = parts[1:4]
            if not (validate_register(rd) and validate_register(rs1) and validate_immediate(imm, 12)):
                return "Invalid operand(s)", ""
            obj = TypeI(imm, rs1, opcode_map[op][1], rd, opcode_map[op][0])

        elif op == "lw":
            rd, offset, base = parse_load_store(parts)
            if not all([rd, offset, base]):
                return "Invalid format for lw, expected lw rd, offset(rs1)", ""
            if not (validate_register(rd) and validate_register(base) and validate_immediate(offset, 12)):
                return "Invalid operand(s) for lw", ""
            obj = TypeI(offset, base, opcode_map[op][1], rd, opcode_map[op][0])

        elif op == "sw":
            rs2, offset, base = parse_load_store(parts)
            if not all([rs2, offset, base]):
                return "Invalid format for sw, expected sw rs2, offset(rs1)", ""
            if not (validate_register(rs2) and validate_register(base) and validate_immediate(offset, 12)):
                return "Invalid operand(s) for sw", ""
            obj = TypeS(offset, rs2, base, opcode_map[op][1], opcode_map[op][0])

        elif op == "beq":
            if len(parts) != 4:
                return "Invalid number of operands, expected rs1, rs2, imm", ""
            rs1, rs2, imm = parts[1:4]
            if not (validate_register(rs1) and validate_register(rs2) and validate_immediate(imm, 13)):
                return "Invalid operand(s)", ""
            obj = TypeB(imm, rs2, rs1, opcode_map[op][1], opcode_map[op][0])

        elif op == "lui":
            if len(parts) != 3:
                return "Invalid number of operands, expected rd, imm", ""
            rd, imm = parts[1:3]
            if not (validate_register(rd) and validate_immediate(imm, 20)):
                return "Invalid operand(s)", ""
            obj = TypeU(imm, rd, opcode_map[op][0])

        elif op == "jal":
            if len(parts) != 3:
                return "Invalid number of operands, expected rd, imm", ""
            rd, imm = parts[1:3]
            if not (validate_register(rd) and validate_immediate(imm, 21)):
                return "Invalid operand(s)", ""
            obj = TypeJ(imm, rd, opcode_map[op][0])

        return obj.to_bin(), obj.to_hex()

    except ValueError as e:
        return f"Error: {str(e)}", ""
    except Exception as e:
        return f"Error processing {op}: {str(e)}", ""

#==============================================
# GUI Application
#==============================================

class RISC_V_Converter(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window configuration
        self.title("RISC-V to Machine Code Converter")
        self.geometry("850x700")
        self.minsize(600, 400)
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        
        # Create UI
        self.create_widgets()
    
    def create_widgets(self):
        """Build all GUI components"""
        # Main container
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Title
        self.title_label = ctk.CTkLabel(
            self,
            text="RISC-V Assembly to Machine Code Converter",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.title_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        # Input frame
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        self.input_frame.grid_columnconfigure(0, weight=1)
        self.input_frame.grid_rowconfigure(1, weight=1)
        
        self.input_label = ctk.CTkLabel(
            self.input_frame,
            text="Enter RISC-V Instructions (one per line):",
            font=ctk.CTkFont(size=14)
        )
        self.input_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")
        
        self.input_text = ctk.CTkTextbox(
            self.input_frame,
            font=ctk.CTkFont(family="Courier", size=14),
            wrap="none"
        )
        self.input_text.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        # Button frame
        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.convert_btn = ctk.CTkButton(
            self.button_frame,
            text="Convert",
            command=self.convert,
            width=120
        )
        self.convert_btn.pack(side="left", padx=10, pady=5)
        
        self.clear_btn = ctk.CTkButton(
            self.button_frame,
            text="Clear All",
            command=self.clear_all,
            width=120,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        self.clear_btn.pack(side="left", padx=10, pady=5)
        
        self.help_btn = ctk.CTkButton(
            self.button_frame,
            text="Help",
            command=self.show_help,
            width=120
        )
        self.help_btn.pack(side="left", padx=10, pady=5)
        
        # Output frame
        self.output_frame = ctk.CTkFrame(self)
        self.output_frame.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.output_frame.grid_columnconfigure(0, weight=1)
        self.output_frame.grid_rowconfigure(1, weight=1)
        
        self.output_label = ctk.CTkLabel(
            self.output_frame,
            text="Machine Code Output:",
            font=ctk.CTkFont(size=14)
        )
        self.output_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")
        
        self.output_text = ctk.CTkTextbox(
            self.output_frame,
            font=ctk.CTkFont(family="Courier", size=14),
            wrap="none"
        )
        self.output_text.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.output_text.bind("<Key>", lambda e: "break")  # Make read-only
        
        # Copy button
        self.copy_btn = ctk.CTkButton(
            self,
            text="Copy Output",
            command=self.copy_output,
            width=120
        )
        self.copy_btn.grid(row=4, column=0, pady=(0, 20))
    
    def show_help(self):
        """Show help dialog with supported instructions"""
        help_text = """Supported Instructions:
- add rd, rs1, rs2
- sub rd, rs1, rs2
- addi rd, rs1, imm
- li rd, imm
- lw rd, offset(rs1)
- sw rs2, offset(rs1)
- beq rs1, rs2, imm
- lui rd, imm
- jal rd, imm

Registers: x0-x31 or aliases (e.g., t0, t6, a0, s0)
Immediate formats: decimal (e.g., 123), hex (e.g., 0x7B), binary (e.g., 0b111)"""
        messagebox.showinfo("Help", help_text)
    
    def convert(self):
        """Handle conversion process"""
        assembly = self.input_text.get("1.0", "end").strip()
        if not assembly:
            messagebox.showerror("Error", "Please enter RISC-V instructions")
            return
        
        lines = assembly.splitlines()
        output = []
        errors = []
        
        for i, line in enumerate(lines, 1):
            if line.strip():
                binary, hex_code = convert_instruction(line)
                if binary.startswith("Error") or binary.startswith("Invalid") or binary.startswith("Unsupported"):
                    errors.append(f"Line {i}: {binary}")
                else:
                    output.append(f"{line.strip():<25} → Binary: {binary} | Hex: 0x{hex_code}")
        
        self.output_text.delete("1.0", "end")
        
        if errors:
            self.output_text.insert("end", "Errors:\n" + "\n".join(errors) + "\n\n")
        
        if output:
            self.output_text.insert("end", "Results:\n" + "\n".join(output))
        
        if errors:
            messagebox.showwarning("Conversion Issues", f"Found {len(errors)} error(s)")
        else:
            messagebox.showinfo("Success", "Conversion completed!")
    
    def clear_all(self):
        """Clear all input and output fields"""
        if messagebox.askyesno("Confirm", "Clear all fields?"):
            self.input_text.delete("1.0", "end")
            self.output_text.delete("1.0", "end")
    
    def copy_output(self):
        """Copy output text to clipboard"""
        output = self.output_text.get("1.0", "end").strip()
        if output:
            try:
                self.clipboard_clear()
                self.clipboard_append(output)
                messagebox.showinfo("Copied", "Output copied to clipboard!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")
        else:
            messagebox.showwarning("Empty", "No output to copy")

#==============================================
# Run Application
#==============================================

if __name__ == "__main__":
    app = RISC_V_Converter()
    app.mainloop()
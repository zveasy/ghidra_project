# disassemble.py
import sys
from capstone import *

def disassemble_binary(binary_path, arch=CS_ARCH_X86, mode=CS_MODE_64):
    # Read file bytes
    with open(binary_path, 'rb') as f:
        code = f.read()
    
    # Initialize Capstone
    md = Cs(arch, mode)
    
    # Disassemble
    for i in md.disasm(code, 0x0):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python disassemble.py <binary_file>")
        sys.exit(1)

    binary_path = sys.argv[1]
    disassemble_binary(binary_path)

# myGhidraAnalysisScript.py (headless Ghidra Python)
#@author 
#@category MyScripts
#@keybinding 
#@menupath 
#@toolbar 
import sys

# Add Ghidra's library paths manually
sys.path.append("/opt/homebrew/Caskroom/ghidra/11.3-20250205/ghidra_11.3_PUBLIC/Ghidra/Features/Base/lib/")
sys.path.append("/opt/homebrew/Caskroom/ghidra/11.3-20250205/ghidra_11.3_PUBLIC/Ghidra/Framework/Utility/lib/")

# Now import the module
from ghidra.program.model.block import BasicBlockModel

print("Successfully imported Ghidra modules!")

def run():
    currentProgram = getCurrentProgram()
    bbm = BasicBlockModel(currentProgram)
    # Example: iterate basic blocks, print their start addresses
    block_iter = bbm.getCodeBlocks(True)
    while block_iter.hasNext():
        block = block_iter.next()
        print("Block start:", hex(block.getMinAddress().getOffset()))

from IPython import embed
import argparse

import lief
import dumbGadget
from capstone.x86_const import *


parser = argparse.ArgumentParser()
parser.add_argument('file')

group = parser.add_mutually_exclusive_group()
group.add_argument('-b','--bytes',metavar='N',type=int,help='search gadgets up to N bytes')
group.add_argument('-c','--cost',metavar='N',type=int,help='search gadgets up to a cost of N (default)')
group.add_argument('-i','--instr',metavar='N',type=int,help='search gadgets up to N instructions')


REG64_codes = [X86_REG_RAX,X86_REG_RBX,X86_REG_RCX,X86_REG_RDX,X86_REG_RSI,X86_REG_RDI,X86_REG_RBP,X86_REG_R8,X86_REG_R9,X86_REG_R10,X86_REG_R11,X86_REG_R12,X86_REG_R13,X86_REG_R14,X86_REG_R15]
REG64_strings = ['X86_REG_RAX','X86_REG_RBX','X86_REG_RCX','X86_REG_RDX','X86_REG_RSI','X86_REG_RDI','X86_REG_RBP','X86_REG_R8','X86_REG_R9','X86_REG_R10','X86_REG_R11','X86_REG_R12','X86_REG_R13','X86_REG_R14','X86_REG_R15']


def limit(gdgtCol, gadget, bound, context):
    if bound < context:
        gdgtcpy = gadget.copy()
        gdgtCol.gdgtCollection.append(gdgtcpy)            
        return True
    elif bound == context:
        gdgtCol.gdgtCollection.append(gadget)            
        return False
    else:
        return False

def limitNbrInsts(gdgtCol, gadget, context):
    bound = gadget.gadgetMatrix.nbrInsts
    return limit(gdgtCol, gadget, bound, context)

def limitNbrBytes(gdgtCol, gadget, context):
    bound = len(gadget.bytes())
    return limit(gdgtCol, gadget, bound, context)

def limitCost(gdgtCol, gadget, context):
    bound = gadget.cost()
    return limit(gdgtCol, gadget, bound, context)



if __name__ == '__main__':
    args = parser.parse_args()

    print('\nParsing', args.file)
    binary = lief.parse(args.file)
    
    sctext = None
    
    for section in binary.sections:
        if section.name == '.text':
            sctext = section
            break


    gdgtCollection = dumbGadget.dumbGadget('x64', bytearray(sctext.content))

    callback = limitCost
    context = 64

    if args.bytes != None:
        callback = limitNbrBytes
        context = args.bytes
    elif args.instr != None:
        callback = limitNbrInsts
        context = args.instr
    elif args.cost != None:
        context = args.cost
        
    print('\nGathering gadgets')
    gdgtCollection.dumbGadgets(callback=callback, context=context)

    print('\n',len(gdgtCollection.gdgtCollection), ' gadgets found.\n')

    sF = gdgtCollection.arch.stackFirst
    stackTop = gdgtCollection.arch.stackTop
    sL = gdgtCollection.arch.stackLast

    STACK_codes = [i for i in range(sF,sL+1)]
    STACK_strings = ["stack_"+str(i-stackTop) for i in range(sF,sL+1)]
    
    deref = gdgtCollection.arch.deref
    memR = gdgtCollection.arch.memRead
    
    embed()

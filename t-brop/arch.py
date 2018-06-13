# -*- coding: utf-8 -*-

import numpy as np
from scipy import sparse

import capstone
from capstone.x86_const import *

# must be at least 1 for shared mem/stack
# at least 2 for separate mem/stack
MEM_RESERVED_INDICES = 58

STACK_PROP = 4 #stack proportions: 1/n over top, (n-1)/n under top


STACK_MAX_DIFF = 0X8000 # if we look further than that, we are not in the stack anymore

class Arch():
    def __init__(self, dependencies):
        assert(MEM_RESERVED_INDICES > 6 + STACK_PROP)
        
        self.matrix = dependencies
        self.size, _ = dependencies.shape
        
        self.deref = self.size - MEM_RESERVED_INDICES
        
        self.memRead = self.deref + 1
        self.memWrite = self.memRead + 1
        
        self.stackRead = self.size - 2
        self.stackWrite = self.size - 1
        self.stackOverRead = self.memWrite + 1 
        self.stackOverWrite = self.stackOverRead + 1
        self.stackSize = self.stackRead - self.stackOverWrite - 1
        
        self.stackTop = self.stackOverWrite + 1 + (self.stackSize//STACK_PROP)
        
        self.stackFirst = self.stackOverWrite + 1
        self.stackLast = self.stackRead - 1
        
        assert(self.stackOverWrite < self.stackFirst < self.stackTop < self.stackLast < self.stackRead)
        assert(self.stackFirst + self.stackSize == self.stackLast + 1)
        
        self.stackREG = 0
        self.flagREG = 0
        self.opTypeINVALID = None
        self.opTypeREG = None
        self.opTypeIMM = None
        self.opTypeMEM = None
        self.opTypeFP = None
        
        self.addrSize = 8 #in bytes

        self.regDepDict = {}

    def getRegDependencies(self, id_):
        if id_ in self.regDepDict:
            return self.regDepDict[id_]
        else:
            _, childrens = self.matrix.getrow(id_).nonzero()
            parents, _ = self.matrix.getcol(id_).nonzero()
            parents = list(parents)
            childrens = list(childrens)
            parents.remove(id_)
            childrens.remove(id_)
            self.regDepDict[id_] = parents, childrens
            return parents, childrens


    # return index of stack cell at offset (in number of cells)
    def indexStackRead(self, offsetCell):
        index = self.stackTop + offsetCell
        if index < self.stackFirst:
            return self.stackOverRead
        elif index > self.stackLast:
            return self.stackRead
        else:
            return index

    # return index of stack cell at offset (in number of cells)
    def indexStackWrite(self, offsetCell):
        index = self.stackTop + offsetCell
        if index < self.stackFirst:
            return self.stackOverWrite
        elif index > self.stackLast:
            return self.stackWrite
        else:
            return index


    def shiftStack(self, offsetByte):
        stackDispl = offsetByte // self.addrSize
        reg_reset = set(range(self.stackFirst, self.stackLast+1))
        flows = []
        flows.append(([self.stackREG], [self.stackREG]))

        for i in range(self.stackFirst, self.stackLast + 1):
            
            srcs = [self.indexStackRead(i - self.stackTop + stackDispl)]
            if offsetByte % self.addrSize != 0:
                srcs.append(self.indexStackRead(i - self.stackTop + stackDispl + 1))
            flows.append(([i], srcs))

            dsts = [self.indexStackWrite(i - self.stackTop - stackDispl)]
            if offsetByte % self.addrSize != 0:
                dsts.append(self.indexStackWrite(i - self.stackTop - (stackDispl + 1)))
            flows.append((dsts, [i]))

        if offsetByte > self.addrSize*self.stackSize:
            flows.append(([self.stackOverWrite], [self.stackRead]))
        elif offsetByte < - self.addrSize*self.stackSize:
            flows.append(([self.stackWrite], [self.stackOverRead]))

        flows.append(([self.deref],[self.stackREG]))
        
        return reg_reset, flows
            
    def killStack(self, killer=[]):
        reg_reset = set(range(self.stackFirst, self.stackLast+1))
        reg_reset.update([self.stackOverRead, self.stackOverWrite, self.stackRead, self.stackWrite])
        flows = [(list(reg_reset), [self.memRead]+killer), ([self.memWrite], list(reg_reset))]
        return reg_reset, flows
        
    def corruptedStack(self, instW):
        if self.stackREG in instW:
            return True
        _, childrens = self.getRegDependencies(self.stackREG)
        for reg in childrens:
            if reg in instW:
                return True
        return False


    def getOperandIndices(self, op):
        opR = []
        opW = []
        deref = []

        op_type = op.type
        op_access = op.access
        op_reg = op.reg
        if op_type == self.opTypeREG:
            if op_access & capstone.CS_AC_READ:
                opR.append(op_reg)
            if op_access & capstone.CS_AC_WRITE:
                opW.append(op_reg)
        elif op_type == self.opTypeMEM:
            #TODO: check if base (and/or index?) is RSP

            op_mem_base = op.mem.base
            op_mem_index = op.mem.index
            if op_mem_base != 0:
                deref.append(op_mem_base)
            if op_mem_index != 0:
                deref.append(op_mem_index)

            #Are we in the stack?
            op_mem_disp = op.mem.disp
            if op_mem_base == self.stackREG and op_mem_index == 0 and abs(op_mem_disp) < STACK_MAX_DIFF:
                stackDispl = op_mem_disp // self.addrSize
                if op_access & capstone.CS_AC_READ or op_access == 0:
                    opR.append(self.indexStackRead(stackDispl))
                    if op_mem_disp % self.addrSize != 0:
                        opR.append(self.indexStackRead(stackDispl+1))
                if op_access & capstone.CS_AC_WRITE:
                    opW.append(self.indexStackWrite(stackDispl))                
                    if op_mem_disp % self.addrSize != 0:
                        opW.append(self.indexStackWrite(stackDispl+1))
            else:
                if op_access & capstone.CS_AC_READ or op_access == 0:
                    opR.append(self.memRead)
                    opR.extend(deref)
                    # We only consider deref as interesting flows on memory reads
                if op_access & capstone.CS_AC_WRITE:
                    opW.append(self.memWrite)
        return opW, opR, deref
            
    
    def checkInstFlows(self, inst, reg_reset, flows):
        for index in reg_reset:
            if index < 0 or index >= self.size:
                print(inst.mnemonic, inst.op_str)
                raise IndexError
        
        for dst,src in flows:
            for index in dst:
                if index < 0 or index >= self.size:
                    print(inst.mnemonic, inst.op_str)
                    raise IndexError
            for index in src:
                if index < 0 or index >= self.size:
                    print(inst.mnemonic, inst.op_str)
                    raise IndexError

        return reg_reset, flows
        
    def getInstFlows(self, inst):
        src, dst = inst.regs_access()
#        if src == (): src = []
#        if dst == (): dst = []
        reg_reset = set(dst)
        dst = set(dst)
        src = set(src)
        ##################
        # HORRIBLE HACK
        # self.stackREG is implicitely used only in pop/push/ret/call (right?)
        # they should be properly handled
        # this is necessary if I do not want:
        # mov qword ptr [rsp], rax
        # to imply a dependency stack_0 <--- rax, _rsp_
        src.discard(self.stackREG)
        dst.discard(self.stackREG)
        reg_reset.discard(self.stackREG)
        ##################
        allDeref = set()
        for op in inst.operands:
            opW, opR, deref = self.getOperandIndices(op)
            src.update(opR)
            dst.update(opW)
            reg_reset.update(opW)
            allDeref.update(deref)
            stackReset = set(opW).intersection(range(self.stackFirst, self.stackLast + 1))
            #if a write span several stack cells, they should not be reseted
            if len(stackReset) == 1:
                reg_reset.update(stackReset)
            #this is not a satisfying solution, we do not know here the size of the write!
        flows = [(dst, src), ([self.deref], allDeref)]
        if self.corruptedStack(dst):
            reg_resetStack, flowStack = self.killStack(list(src))
            reg_reset.update(reg_resetStack)
            flows = flows + flowStack
#        return self.checkInstFlows(inst, reg_reset, flows)
        return reg_reset, flows

    def __str__(self):

        _str = ""

        for i in range(self.size):
            _str += "%.3d" % i
            for j in range(self.size):
                if (i,j) in self.matrix : _str += "x"
                else : _str += "."
            _str += "\n"


class Arch_x86_64(Arch):
    def __init__(self):
        size = X86_REG_ENDING + MEM_RESERVED_INDICES # 1 reserved for mem dependencies 1 for bottom of stack, the rest for top of stack
        dependencies = sparse.lil_matrix((size,size),dtype=np.bool)
        
        for i in range(size):
            dependencies[i,i] = True

        # RAX    
        dependencies[X86_REG_RAX, X86_REG_EAX] = True
        dependencies[X86_REG_RAX, X86_REG_AX] = True
        dependencies[X86_REG_RAX, X86_REG_AH] = True
        dependencies[X86_REG_RAX, X86_REG_AL] = True
        dependencies[X86_REG_EAX, X86_REG_AX] = True
        dependencies[X86_REG_EAX, X86_REG_AH] = True
        dependencies[X86_REG_EAX, X86_REG_AL] = True
        dependencies[X86_REG_AX, X86_REG_AH] = True
        dependencies[X86_REG_AX, X86_REG_AL] = True
        # RBX    
        dependencies[X86_REG_RBX, X86_REG_EBX] = True
        dependencies[X86_REG_RBX, X86_REG_BX] = True
        dependencies[X86_REG_RBX, X86_REG_BH] = True
        dependencies[X86_REG_RBX, X86_REG_BL] = True
        dependencies[X86_REG_EBX, X86_REG_BX] = True
        dependencies[X86_REG_EBX, X86_REG_BH] = True
        dependencies[X86_REG_EBX, X86_REG_BL] = True
        dependencies[X86_REG_BX, X86_REG_BH] = True
        dependencies[X86_REG_BX, X86_REG_BL] = True
        # RCX    
        dependencies[X86_REG_RCX, X86_REG_ECX] = True
        dependencies[X86_REG_RCX, X86_REG_CX] = True
        dependencies[X86_REG_RCX, X86_REG_CH] = True
        dependencies[X86_REG_RCX, X86_REG_CL] = True
        dependencies[X86_REG_ECX, X86_REG_CX] = True
        dependencies[X86_REG_ECX, X86_REG_CH] = True
        dependencies[X86_REG_ECX, X86_REG_CL] = True
        dependencies[X86_REG_CX, X86_REG_CH] = True
        dependencies[X86_REG_CX, X86_REG_CL] = True
        # RDX    
        dependencies[X86_REG_RDX, X86_REG_EDX] = True
        dependencies[X86_REG_RDX, X86_REG_DX] = True
        dependencies[X86_REG_RDX, X86_REG_DH] = True
        dependencies[X86_REG_RDX, X86_REG_DL] = True
        dependencies[X86_REG_EDX, X86_REG_DX] = True
        dependencies[X86_REG_EDX, X86_REG_DH] = True
        dependencies[X86_REG_EDX, X86_REG_DL] = True
        dependencies[X86_REG_DX, X86_REG_DH] = True
        dependencies[X86_REG_DX, X86_REG_DL] = True
        # R8
        dependencies[X86_REG_R8, X86_REG_R8D] = True
        dependencies[X86_REG_R8, X86_REG_R8W] = True
        dependencies[X86_REG_R8, X86_REG_R8B] = True
        dependencies[X86_REG_R8D, X86_REG_R8W] = True
        dependencies[X86_REG_R8D, X86_REG_R8B] = True
        dependencies[X86_REG_R8W, X86_REG_R8B] = True
        # R9
        dependencies[X86_REG_R9, X86_REG_R9D] = True
        dependencies[X86_REG_R9, X86_REG_R9W] = True
        dependencies[X86_REG_R9, X86_REG_R9B] = True
        dependencies[X86_REG_R9D, X86_REG_R9W] = True
        dependencies[X86_REG_R9D, X86_REG_R9B] = True
        dependencies[X86_REG_R9W, X86_REG_R9B] = True
        # R10
        dependencies[X86_REG_R10, X86_REG_R10D] = True
        dependencies[X86_REG_R10, X86_REG_R10W] = True
        dependencies[X86_REG_R10, X86_REG_R10B] = True
        dependencies[X86_REG_R10D, X86_REG_R10W] = True
        dependencies[X86_REG_R10D, X86_REG_R10B] = True
        dependencies[X86_REG_R10W, X86_REG_R10B] = True
        # R11
        dependencies[X86_REG_R11, X86_REG_R11D] = True
        dependencies[X86_REG_R11, X86_REG_R11W] = True
        dependencies[X86_REG_R11, X86_REG_R11B] = True
        dependencies[X86_REG_R11D, X86_REG_R11W] = True
        dependencies[X86_REG_R11D, X86_REG_R11B] = True
        dependencies[X86_REG_R11W, X86_REG_R11B] = True
        # R12
        dependencies[X86_REG_R12, X86_REG_R12D] = True
        dependencies[X86_REG_R12, X86_REG_R12W] = True
        dependencies[X86_REG_R12, X86_REG_R12B] = True
        dependencies[X86_REG_R12D, X86_REG_R12W] = True
        dependencies[X86_REG_R12D, X86_REG_R12B] = True
        dependencies[X86_REG_R12W, X86_REG_R12B] = True
        # R13
        dependencies[X86_REG_R13, X86_REG_R13D] = True
        dependencies[X86_REG_R13, X86_REG_R13W] = True
        dependencies[X86_REG_R13, X86_REG_R13B] = True
        dependencies[X86_REG_R13D, X86_REG_R13W] = True
        dependencies[X86_REG_R13D, X86_REG_R13B] = True
        dependencies[X86_REG_R13W, X86_REG_R13B] = True
        # R14
        dependencies[X86_REG_R14, X86_REG_R14D] = True
        dependencies[X86_REG_R14, X86_REG_R14W] = True
        dependencies[X86_REG_R14, X86_REG_R14B] = True
        dependencies[X86_REG_R14D, X86_REG_R14W] = True
        dependencies[X86_REG_R14D, X86_REG_R14B] = True
        dependencies[X86_REG_R14W, X86_REG_R14B] = True
        # R15
        dependencies[X86_REG_R15, X86_REG_R15D] = True
        dependencies[X86_REG_R15, X86_REG_R15W] = True
        dependencies[X86_REG_R15, X86_REG_R15B] = True
        dependencies[X86_REG_R15D, X86_REG_R15W] = True
        dependencies[X86_REG_R15D, X86_REG_R15B] = True
        dependencies[X86_REG_R15W, X86_REG_R15B] = True
        # RSP
        dependencies[X86_REG_RSP, X86_REG_ESP] = True
        dependencies[X86_REG_RSP, X86_REG_SP] = True
        dependencies[X86_REG_RSP, X86_REG_SPL] = True
        dependencies[X86_REG_ESP, X86_REG_SP] = True
        dependencies[X86_REG_ESP, X86_REG_SPL] = True
        dependencies[X86_REG_SP, X86_REG_SPL] = True
        # RBP
        dependencies[X86_REG_RBP, X86_REG_EBP] = True
        dependencies[X86_REG_RBP, X86_REG_BP] = True
        dependencies[X86_REG_RBP, X86_REG_BPL] = True
        dependencies[X86_REG_EBP, X86_REG_BP] = True
        dependencies[X86_REG_EBP, X86_REG_BPL] = True
        dependencies[X86_REG_BP, X86_REG_BPL] = True
        # RSI
        dependencies[X86_REG_RSI, X86_REG_ESI] = True
        dependencies[X86_REG_RSI, X86_REG_SI] = True
        dependencies[X86_REG_RSI, X86_REG_SIL] = True
        dependencies[X86_REG_ESI, X86_REG_SI] = True
        dependencies[X86_REG_ESI, X86_REG_SIL] = True
        dependencies[X86_REG_SI, X86_REG_SIL] = True
        # RDI
        dependencies[X86_REG_RDI, X86_REG_EDI] = True
        dependencies[X86_REG_RDI, X86_REG_DI] = True
        dependencies[X86_REG_RDI, X86_REG_DIL] = True
        dependencies[X86_REG_EDI, X86_REG_DI] = True
        dependencies[X86_REG_EDI, X86_REG_DIL] = True
        dependencies[X86_REG_DI, X86_REG_DIL] = True
        # RIP
        # dependencies[X86_REG_RIP, X86_REG_EIP] = True
        # dependencies[X86_REG_RIP, X86_REG_IP] = True
        # dependencies[X86_REG_EIP, X86_REG_IP] = True

        matrix = dependencies.tocsr(True)

        Arch.__init__(self, matrix)
        
        self.opTypeINVALID = X86_OP_INVALID
        self.opTypeREG = X86_OP_REG
        self.opTypeIMM = X86_OP_IMM
        self.opTypeMEM = X86_OP_MEM
        # self.opTypeFP = X86_OP_FP
        
        self.stackREG = X86_REG_RSP
        self.flagREG = X86_REG_EFLAGS

        self.addrSize = 8

    def getInstFlows(self, inst):

        # print "%s %s" % (inst.mnemonic, inst.op_str)
        if inst.mnemonic == "lea":
            src, dst = inst.regs_access()
            if src == (): src = []
            if dst == (): dst = []
            return set(dst), [(dst,src)]

        elif inst.mnemonic.startswith("pusha") or inst.mnemonic.startswith("popa"):
            #raise Exception("TODO: deal with pusha/popa")
            return Arch.getInstFlows(self, inst)
            
        elif inst.mnemonic.startswith("push") or capstone.CS_GRP_CALL in inst.groups:
            reg_reset = set(range(self.stackFirst, self.stackLast+1))
            flows = [([], []) for i in range(self.stackSize+3)]

            flows[0] = ([self.stackFirst], [self.stackOverRead])
            for i in range(1, self.stackTop-self.stackFirst):
                flows[i]=([self.stackFirst + i], [self.stackFirst + i - 1])

            if capstone.CS_GRP_CALL in inst.groups:
                #TODO: should we ignore RIP dependencies? (because RIP is a constant at a given address...)
                #            flowSTop = [self.stackTopIndex],[X86_REG_RIP]
                #            reg_reset.add(X86_REG_RIP)                
                opW, opR, deref = self.getOperandIndices(inst.operands[0])
                assert(opW == [])
                flowSTop = [self.stackTop], []
                flows[self.stackSize+2] = [self.deref], deref+[self.stackREG]
            elif inst.mnemonic.startswith("pushf"):
                flowSTop = [self.stackTop],[self.flagREG]
                flows[self.stackSize+2] = [self.deref], [self.stackREG]
            else:
                opW, opR, deref = self.getOperandIndices(inst.operands[0])
                assert(opW == [])
                flowSTop = ([self.stackTop] + opW), opR+deref
                flows[self.stackSize+2] = [self.deref], deref+[self.stackREG]
            flows[self.stackTop-self.stackFirst] = flowSTop

            for i in range(self.stackTop-self.stackFirst + 1, self.stackSize):
                flows[i]=([self.stackFirst + i], [self.stackFirst + i - 1])

            flows[self.stackSize] = [self.stackWrite], [self.stackLast]
                
            flows[self.stackSize+1] = [self.stackREG, self.deref], [self.stackREG]
            reg_reset.add(self.stackREG)

            return reg_reset, flows
            
        elif inst.mnemonic.startswith("popf") or inst.mnemonic == "pop":
            reg_reset = set(range(self.stackFirst, self.stackLast+1))
            flows = [([], []) for i in range(self.stackSize+3)]

            flows[0] = ([self.stackOverWrite], [self.stackFirst])
            for i in range(1, self.stackTop-self.stackFirst):
                flows[i]=([self.stackFirst + i - 1], [self.stackFirst + i])

            if inst.mnemonic.startswith("popf"):
                opW = [self.flagREG]
                deref = []
            else:
                opW, opR, deref = self.getOperandIndices(inst.operands[0])
                assert(opR == [])
                # We only consider deref as interesting flows on memory reads
            reg_reset.update(opW)
            flows[self.stackSize+2] = [self.deref], deref+[self.stackREG]
            flows[self.stackTop-self.stackFirst] = opW+[self.stackTop-1], [self.stackTop]

            for i in range(self.stackTop-self.stackFirst + 1, self.stackSize):
                flows[i]=([self.stackFirst + i - 1], [self.stackFirst + i])

            flows[self.stackSize] = [self.stackLast], [self.stackRead]
                
            flows[self.stackSize+1] = [self.stackREG, self.deref], [self.stackREG]
            reg_reset.add(self.stackREG)

            return reg_reset, flows
        
        elif inst.mnemonic == "xor" \
            and inst.operands[0].type == inst.operands[1].type == self.opTypeREG \
            and inst.operands[0].reg == inst.operands[1].reg:
            if self.corruptedStack([inst.operands[0].reg]):
                reg_resetStack, flowStack = self.killStack()
                reg_resetStack.update([inst.operands[0].reg, self.flagREG])
                return reg_resetStack, flowStack
            else:
                return set([inst.operands[0].reg, self.flagREG]),[]

        elif inst.mnemonic == "xchg":
            regReset = set()
            if inst.operands[0].type == self.opTypeREG:
                regReset.add(inst.operands[0].reg)
            if inst.operands[1].type == self.opTypeREG:
                regReset.add(inst.operands[1].reg)
            opW0, opR0, deref0 = self.getOperandIndices(inst.operands[0])
            opW1, opR1, deref1 = self.getOperandIndices(inst.operands[1])

            flows = [(opW0, opR1+deref1), (opW1, opR0+deref0), ([self.deref], deref0+deref1)]

            if self.corruptedStack(opW0+opW1):
                reg_resetStack, flowStack = self.killStack()            
                regReset.update(reg_resetStack)
                flows = flows + flowStack
            return regReset, flows
            
        elif capstone.CS_GRP_RET in inst.groups:
            displ = self.addrSize
            if len(inst.operands) == 1 and inst.operands[0].type == self.opTypeIMM:
                displ += inst.operands[0].imm
            return self.shiftStack(displ)

            
            
        elif (inst.mnemonic == "add" or inst.mnemonic == "sub") \
            and inst.operands[0].type == self.opTypeREG \
            and (inst.operands[0].reg == X86_REG_RSP or inst.operands[0].reg == X86_REG_ESP) \
            and inst.operands[1].type == self.opTypeIMM \
            and abs(inst.operands[1].imm) < STACK_MAX_DIFF:
            displ = inst.operands[1].imm
            if inst.mnemonic == "sub":
                displ = -displ
                
            reg_reset, flows = self.shiftStack(displ)
            
            reg_reset.add(self.flagREG)
            flows.append(([self.flagREG],[self.stackREG]))

            return reg_reset, flows
            
        else:
            return Arch.getInstFlows(self, inst)

class Arch_x86_32(Arch_x86_64):

    def __init__(self):

        Arch_x86_64.__init__(self)

        # RAX    
        self.matrix[X86_REG_RAX, X86_REG_EAX] = False
        self.matrix[X86_REG_RAX, X86_REG_AX] = False
        self.matrix[X86_REG_RAX, X86_REG_AH] = False
        self.matrix[X86_REG_RAX, X86_REG_AL] = False
        # RBX    
        self.matrix[X86_REG_RBX, X86_REG_EBX] = False
        self.matrix[X86_REG_RBX, X86_REG_BX] = False
        self.matrix[X86_REG_RBX, X86_REG_BH] = False
        self.matrix[X86_REG_RBX, X86_REG_BL] = False
        # RCX    
        self.matrix[X86_REG_RCX, X86_REG_ECX] = False
        self.matrix[X86_REG_RCX, X86_REG_CX] = False
        self.matrix[X86_REG_RCX, X86_REG_CH] = False
        self.matrix[X86_REG_RCX, X86_REG_CL] = False
        # RDX    
        self.matrix[X86_REG_RDX, X86_REG_EDX] = False
        self.matrix[X86_REG_RDX, X86_REG_DX] = False
        self.matrix[X86_REG_RDX, X86_REG_DH] = False
        self.matrix[X86_REG_RDX, X86_REG_DL] = False
        # RSP
        self.matrix[X86_REG_RSP, X86_REG_ESP] = False
        self.matrix[X86_REG_RSP, X86_REG_SP] = False
        self.matrix[X86_REG_RSP, X86_REG_SPL] = False
        # RBP
        self.matrix[X86_REG_RBP, X86_REG_EBP] = False
        self.matrix[X86_REG_RBP, X86_REG_BP] = False
        self.matrix[X86_REG_RBP, X86_REG_BPL] = False
        # RSI
        self.matrix[X86_REG_RSI, X86_REG_ESI] = False
        self.matrix[X86_REG_RSI, X86_REG_SI] = False
        self.matrix[X86_REG_RSI, X86_REG_SIL] = False
        # RDI
        self.matrix[X86_REG_RDI, X86_REG_EDI] = False
        self.matrix[X86_REG_RDI, X86_REG_DI] = False
        self.matrix[X86_REG_RDI, X86_REG_DIL] = False

        self.addrSize = 4
        self.stackREG = X86_REG_ESP

SUPPORTED_ARCH = {

    'x64':Arch_x86_64,
    'x86':Arch_x86_32,

}
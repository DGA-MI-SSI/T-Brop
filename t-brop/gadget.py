import capstone

import numpy as np
from scipy import sparse

from time import time

instMatrixDict = {}

class InstMatrix(object):

    @property
    def matrix(self):
        return self._matrix

    @matrix.setter
    def matrix(self, value):
        self._cache_matrix_last_modification = time()
        self._matrix = value

    def __init__(self, arch, inst=None):

        self.arch = arch
        self.inst = inst

        if inst==None:
            self.matrix = None
            self.reg_reset = set()
            self.flows = []
        else:
            self.matrix = sparse.identity(arch.size, dtype=np.bool).tolil()
            self.reg_reset, self.flows = self.arch.getInstFlows(inst)
            self.initDependencies()
    
    def removeIdDependencies(self):
        for reg in self.reg_reset:
            self.matrix[reg,reg] = False
            _, childrens = self.arch.getRegDependencies(reg)
            for i in childrens:
                self.matrix[i,i] = False

    def addCrossDependencies(self, dstList, srcList):
        for dst in dstList:
            for src in srcList:
                self.matrix[dst, src] = True

    def addDependencies(self):
        for (dstFlow, srcFlow) in self.flows:
            for src in srcFlow:
                srcParents, srcChilds = self.arch.getRegDependencies(src)
                srcList = [src]+srcChilds
                for dst in dstFlow:
                    dstParents, dstChilds = self.arch.getRegDependencies(dst)
                    dstList = dstParents+[dst]+dstChilds
                    self.addCrossDependencies(dstList, srcList)

    def initDependencies(self):
            self.removeIdDependencies()
            self.addDependencies()
            self.matrix = self.matrix.tocsc()
            
    def printIndexName(self, index, postfix=""):

        if index < self.arch.deref:
            return self.inst.reg_name(index) + postfix
        elif index == self.arch.deref:
            return "deref"
        elif index == self.arch.memRead:
            return "mem_r"
        elif index == self.arch.memWrite:
            return "mem_w"
        elif index == self.arch.stackRead:
            return "stack_r"
        elif index == self.arch.stackWrite:
            return "stack_w"
        elif index == self.arch.stackOverRead:
            return "stackOver_r"
        elif index == self.arch.stackOverWrite:
            return "stackOver_w"
        else:
            index = index - self.arch.stackTop
            if index < 0:
                return "stack_{"+str(index)+"}" + postfix
            else:
                return "stack_"+str(index) + postfix

    def lookupRegisterIndexByName(self, name):

        if name in self.RegisterIndexByNameCache:
            return self.RegisterIndexByNameCache[name]

        for index in range(self.arch.deref):
            RegisterName = self.inst.reg_name(index)
            if name == RegisterName: 
                self.RegisterIndexByNameCache[RegisterName] = index
                return index

        return None

    def lookupDependenceIndexByName(self, name):

        if lookupRegisterIndexByName(name): 
            return lookupRegisterIndexByName(name)
        elif name == "deref":
            return self.arch.deref
        elif name == "mem_r":
            return self.arch.memRead
        elif name == "mem_w":
            return self.arch.memWrite
        elif name == "stack_r":
            return self.arch.stackRead
        elif name == "stack_w":
            return self.arch.stackWrite
        elif name == "stackOver_r":
            return self.arch.stackOverRead
        elif name == "stackOver_w":
            return self.arch.stackOverWrite
        else:
            pass
            # if "stack_" in name:

            # index = index - self.arch.stackTop
            # if index < 0:
            #     return "stack_{"+str(index)+"}" + postfix
            # else:
            #     return "stack_"+str(index) + postfix

    def printRegistersIo(self, verbose=False):

        _str = ''

        depStrings = [None for i in range(self.arch.size)]
        for dst,src in zip(*self.matrix.nonzero()): 
            if dst != src:
                SRCparents, _ = self.arch.getRegDependencies(src)
                DSTparents, _ = self.arch.getRegDependencies(dst)
                bparents = False
                for dstP in DSTparents:
                    bparents = bparents or self.matrix[dstP, src]
                for srcP in SRCparents:
                    bparents = bparents or self.matrix[dst, srcP]
                    for dstP in DSTparents:
                        bparents = bparents or self.matrix[dstP, srcP]
                if not bparents and \
                (   verbose\
                    or dst < self.arch.memRead\
                    or src <= self.arch.memRead\
                    ):
                    if depStrings[dst] == None:
                        depStrings[dst] = self.printIndexName(src)
                    else:
                        depStrings[dst] = depStrings[dst] + ", " + self.printIndexName(src)
        for i in range(self.arch.size):
            if depStrings[i] == None:
                parents, _ = self.arch.getRegDependencies(i)
                if not self.matrix[i,i] and len(parents) == 0 and verbose:
                    _str += "%s <-/- %s\n" % (self.printIndexName(i), self.printIndexName(i))
            else:
                if self.matrix[i,i]:
                    depStrings[i] = self.printIndexName(i) + ", " + depStrings[i]
                _str += "%s <--- %s\n" % (self.printIndexName(i), depStrings[i])
                
        return _str

    def toStrings(self):
        accDiagFalse = ";"
        accNDiagTrue = ";"
        for i in range(self.arch.size):
            if not self.matrix[i,i]:
                accDiagFalse += "!"+str(i)+";"
        for i, j in zip(*self.matrix.nonzero()):
            if i != j:
                accNDiagTrue += str(i)+","+str(j)+";"
        return accDiagFalse, accNDiagTrue
            
    def toSets(self):

        def UpdateToSets(self):
            accDiagFalse = set()
            accNDiagTrue = set()

            diagonal = self.matrix.diagonal()
            for State, Index in zip(diagonal, range(len(diagonal))):
                if State == False: accDiagFalse.add(Index)

            for i, j in zip(*self.matrix.nonzero()):
                if i != j:
                    accNDiagTrue.add((i, j))
            return accDiagFalse, accNDiagTrue

        if '_cache_to_sets' not in self.__dict__:
            self._cache_to_sets = UpdateToSets(self)
        elif self._cache_matrix_last_modification > time():
            self._cache_to_sets = UpdateToSets(self)

        return self._cache_to_sets


            
class GadgetMatrix(InstMatrix):
    def __init__(self, arch, chainInst = None):
        InstMatrix.__init__(self, arch, None)
        


        self.chainCond = None
        
        # we do not need those for gadgets
        self.reg_access_read = None
        self.reg_access_write = None
        self.flows = None
        self.nbrInsts = 0
        self.nbrBytes = 0
        
        if chainInst != None:
            self.addInst(chainInst)
        
    def initChainCond(self, chainInst):

        if self.inst == None : self.inst = chainInst
        self.matrix = sparse.identity(self.arch.size, dtype=np.bool).tocsr()
        # groups = chainInst.groups
        self.chainCond = sparse.lil_matrix((1,self.arch.size), dtype=np.bool)
        len_chainInst_operands = len(chainInst.operands)
        if capstone.CS_GRP_RET in chainInst.groups:
            if len_chainInst_operands == 0:
                self.chainCond[0,self.arch.stackTop] = True
            # I am not sure we still are arch independent
            elif len_chainInst_operands == 1 and chainInst.operands[0].type == self.arch.opTypeIMM:
                offset = chainInst.operands[0].imm // self.arch.addrSize
                index = self.arch.indexStackRead(offset)
                self.chainCond[0, index] = True
                if chainInst.operands[0].imm % self.arch.addrSize != 0:
                    index = self.arch.indexStackRead(offset+1)
                    self.chainCond[0, index] = True
            else:
                raise ValueError("RET with more than one operands")
        elif capstone.CS_GRP_JUMP in chainInst.groups \
        or capstone.CS_GRP_CALL in chainInst.groups:
            opw, opr, deref = self.arch.getOperandIndices(chainInst.operands[0])
            for src in opr+deref:
                srcParents, srcChilds = self.arch.getRegDependencies(src)
                self.chainCond[0, src] = True
                for child in srcChilds:
                    self.chainCond[0, child] = True
        else:
            raise ValueError("invalid chainInst: "+chainInst.mnemonic+" "+chainInst.op_str)
        
    def updateChainCond(self, instMatrix):
        self.chainCond *= instMatrix.matrix
    
    def lookupFromCache(self, inst):
        bytes_str = inst.bytes.hex()
        if bytes_str not in instMatrixDict:
            instMatrixDict[bytes_str] = InstMatrix(self.arch, inst)
        return instMatrixDict[bytes_str]

    def addInst(self, inst):

        instMatrix = self.lookupFromCache(inst)

        # init chain cond or update
        if self.chainCond == None:
            self.initChainCond(inst)
        else:
            #TODO: Hypothesis no side effect on chainInst
            self.updateChainCond(instMatrix)

        self.matrix *= instMatrix.matrix
        self.nbrBytes += len(inst.bytes)
        self.nbrInsts += 1

    def copy(self):
        gdgtCpy = GadgetMatrix(self.arch)
        if self.chainCond != None:
            gdgtCpy.chainCond = self.chainCond.copy()
        gdgtCpy.matrix = self.matrix.copy()
        gdgtCpy.inst = self.inst
        gdgtCpy.nbrBytes = self.nbrBytes
        gdgtCpy.nbrInsts = self.nbrInsts
        return gdgtCpy
    
    def printDep(self):
        _str = "\n++++ DepMatrix ++++\n"
        _str += self.printRegistersIo()
        _str += "\n++++ chainCond ++++\n"
        for src in self.chainCond.nonzero()[1]:
            parents, _ = self.arch.getRegDependencies(src)
            bparents = False
            for parent in parents:
                bparents = bparents or self.chainCond[0, parent]
            if not bparents:
                _str += "%s" % (self.printIndexName(src, "_init"))

        return _str
                
    def toStrings(self):
        strDiagFalse, strNDiagTrue = InstMatrix.toStrings(self)
        accChCo = ";"
        for i, j in zip(*self.chainCond.nonzero()):
            accChCo += str(j)+";"
        return strDiagFalse, strNDiagTrue, accChCo
    
    def toSets(self):

        def UpdateToSets(self):

            DiagFalse, NDiagTrue = InstMatrix.toSets(self)
            accChCo = set()
            for i, j in zip(*self.chainCond.nonzero()):
                accChCo.add(j)
            return DiagFalse, NDiagTrue, accChCo
        
        if '_cache_to_sets' not in self.__dict__:
            self._cache_to_sets = UpdateToSets(self)
        elif self._cache_matrix_last_modification > time():
            self._cache_to_sets = UpdateToSets(self)

        return self._cache_to_sets


class Gadget(GadgetMatrix):
    
    def __init__(self, arch, instList = [], max_cost=64):

        self.instList = instList
        self.firstInst = None if instList == [] else instList[0]

        self.arch = arch
        self.max_cost = max_cost

        self.gadgetMatrix = GadgetMatrix(arch)
        
#        self.gadgetMatrix.matrix = sparse.identity(arch.size, dtype=np.bool).tocsr()
        
        for i in range(len(self.instList)-1,-1,-1):
            self.gadgetMatrix.addInst(self.instList[i])

    def __str__(self):
        result = ""
            
        for inst in self.instList:
            result += inst.mnemonic
            if inst.op_str != "":
                result += " "+inst.op_str
            result += "; "

        return result

    def bytes(self):
        result = b""
            
        for inst in self.instList:
            result += inst.bytes

        return result
        
    def getString(self):
        return self.__str__()

    def getAddress(self):
        return self.instList[0].address

    def getLength(self):
        return len(self.instList)

    def getRegisterAccess(self, frm=None, to=None, rflags=False):
        #TODO: use self.gadgetMatrix
        return None

    def getChainCondition(self):
        return set(self.gadgetMatrix.chainCond.nonzero()[1])


    def getReturnCondition(self, to):
        #TODO: use self.gadgetMatrix
        return None
        
    
    def countDep(self):
        self._cache_countDep = self.gadgetMatrix.matrix.count_nonzero()
        return self._cache_countDep
        
    def getChainCondDep(self):

        def UpdateChainCondDep(self):

            chainCond_maxDep = set()
            for i in self.gadgetMatrix.chainCond.nonzero()[1]:
                parents, _ = self.arch.getRegDependencies(i)
                bparents = False
                for parent in parents:
                    if self.gadgetMatrix.chainCond[0, parent]:
                        bparents = True
                        break

                if not bparents:
                    chainCond_maxDep.add(i)
            return chainCond_maxDep
        
        self._cache_chain_cond_dep = UpdateChainCondDep(self)
        return self._cache_chain_cond_dep

    def countChainCondDep(self):
        chainCond_maxDep = self.getChainCondDep()
        chainCond_maxDep.discard(self.arch.memRead)
        return len(chainCond_maxDep)

    def getDerefDep(self):

        def UpdateDerefDep(self):
            deref_maxDep = set()
            derefRow = self.gadgetMatrix.matrix.getrow(self.arch.deref)
            for i in derefRow.nonzero()[1]:
                parents, _ = self.arch.getRegDependencies(i)
                bparents = False
                for parent in parents:
                    if derefRow[0, parent]:
                        bparents = True
                        break

                if not bparents:
                    deref_maxDep.add(i)
            deref_maxDep.discard(self.arch.deref)
            return deref_maxDep


        self._cache_deref_dep = UpdateDerefDep(self)
        return self._cache_deref_dep

    def countDerefDep(self):
        deref_maxDep = self.getDerefDep()
        count = len(deref_maxDep)
        if self.arch.stackREG in deref_maxDep:
            count -= 0.5
        return count
        
    def cost(self):
        # cost linked to non-trivial dependencies, penalties = 10/dim
        dim, _ = self.gadgetMatrix.matrix.get_shape()
        matNotZ = max(0, self.countDep() - dim) # -dim because diag is ok
        costMat = (10*matNotZ)//dim
        # cost linked to chain condition, penalties = 10
        costChainCond = max(0, 10*(self.countChainCondDep()-1))
        # -1 because 1 dep is ok
        # should we drop gadget if chainCond is empty?
        # cost associated to deref, penalties = 10
        costDeref = int(10*self.countDerefDep())
        costLength = self.getLength()*8

        totalcost = costMat + costChainCond + costDeref + costLength
        
#        if totalcost > self.max_cost:
#            print(str(costMat), str(costChainCond), str(costDeref), str(costLength))

        return totalcost
        

    def canBeExtended(self, max_cost=None):
        if max_cost == None: max_cost = self.max_cost
        return self.cost() < max_cost 

    def copy(self):
        gdgt = Gadget(self.arch)
        gdgt.instList = [i for i in self.instList]
        gdgt.firstInst = self.firstInst
        gdgt.gadgetMatrix = self.gadgetMatrix.copy()
        gdgt.max_cost = self.max_cost
        return gdgt

    def extend(self, inst):
        self.instList.insert(0, inst)
        self.firstInst = inst
        self.gadgetMatrix.addInst(inst)

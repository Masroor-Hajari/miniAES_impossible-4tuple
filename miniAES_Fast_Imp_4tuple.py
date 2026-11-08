# Impossible 4-tuple cryptanalysis applied to miniAES
# Fast Variant
# I. First Phase
    #1. Precomputation
    #2. Data Collection
    #3. 4-tuple Extraction
    
# II. Second Phase
    #1. Precomputation
    #2. Data Collection
    #3. 4-tuple Extraction

import numpy as np  
import GFexp2to4 as gf
import miniAES_Functions as func
from miniAES_Oracle import CtxGen
from random import randint
from math import floor

###############################Precompute#################################
def Precompute(Address: str, parameter: int) -> None:
    try:
        if type(Address) != str:
            raise TypeError("The first input must be a valid address.")
        elif type(parameter) != int or parameter < 0 or parameter > 15:
            raise ValueError("The second input must be a valid integer between 0 and 15.")
        else:
            MAT = "0123456789abcdef"
            Address += "\\miniAES_Precomp.txt"
            X = np.array([0, 0], dtype = np.uint8)
            Y = X.copy()
            Z = X.copy()
            with open(Address,"w") as f:
                for i in range(0, parameter):
                    Y[0] = np.uint8(i)
                    for j in range(0, parameter):
                        Y[1] = np.uint8(j)
                        Z = func.SingleMixColumn(Y)
                        X[0] = func.InvSBox(Z[0])
                        X[1] = func.InvSBox(Z[1])
                        f.write("0x" + MAT[X[0]] + MAT[X[1]] + "\n")
                f.close()

    except TypeError as e1:
        print("Error: Invalid input.", e1)

    except ValueError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

##############################DataCollector###############################
def DataCollector(Address: str) -> list:
    try:
        if type(Address) != str:
            raise TypeError("Input must be a valid address.")
        else:
            randomList = []
            element1 = randint(0, 15)
            element2 = randint(0, 15)
            element3 = randint(0, 15)
            element4 = randint(0, 15)
            element5 = randint(0, 15)
            element6 = randint(0, 15)
            element7 = randint(0, 15)
            element8 = randint(0, 15)
            randomList.append(element1)
            randomList.append(element2)
            randomList.append(element3)
            randomList.append(element4)
            randomList.append(element5)
            randomList.append(element6)
            randomList.append(element7)
            randomList.append(element8)
            MAT = "0123456789abcdef"
            Address += "\\miniAES_Ptx.txt"
            with open(Address,"w") as f:
                for i in range(0, 16):
                    for j in range(0, 16):
                        f.write("0x" + MAT[i] + MAT[element1] + MAT[element2] + MAT[j] + "\n")
                for i in range(0, 16):
                    for j in range(0, 16):
                        f.write("0x" + MAT[i] + MAT[element3] + MAT[element4] + MAT[j] + "\n")
                for i in range(0, 16):
                    for j in range(0, 16):
                        f.write("0x" + MAT[element5] + MAT[i] + MAT[j] + MAT[element6] + "\n")
                for i in range(0, 16):
                    for j in range(0, 16):
                        f.write("0x" + MAT[element7] + MAT[i] + MAT[j] + MAT[element8] + "\n")
                f.close()
            return randomList

    except TypeError as e:
        print("Error: Invalid input.", e)
########################################################################## 

################################ctxReader#################################
def ctxReader(Address: str) -> list:
    try:
        if type(Address) != str:
            raise TypeError("Input must be a valid address.")
        else:
            ctxList = []
            Address += "\\miniAES_Ctx.txt"
            with open(Address, 'r') as f:
                ctxStr = f.read()
                f.close()
            L = len(ctxStr)
            try:
                if (L != 7168 and L != 7169) or (L == 7169 and ctxStr[7168] != "\n"):
                    raise ValueError("Invalid ciphertext list. Rewrite it, then run the script again.")
                else:
                    for i in range(0, 1024):
                        ctxList.append(np.array([[gf.Str2Num(ctxStr[7 * i + 2]), gf.Str2Num(ctxStr[7 * i + 4])],
                                                 [gf.Str2Num(ctxStr[7 * i + 3]), gf.Str2Num(ctxStr[7 * i + 5])]], dtype = np.uint8))
                    return ctxList

            except ValueError as e1:
                print("Invalid input.", e1)

    except TypeError as e2:
        print("Invalid input.", e2)
##########################################################################

##############################PreCompReader###############################
def PreCompReader(Address: str, parameter: int) -> list:
    try:
        if type(Address) != str or type(parameter) != int or parameter < 1 or parameter > 15:
            raise TypeError("The first input must be a valid address and the second input must be an integer between 1 and 15.")
        else:
            dataList = []
            Address += "\\miniAES_Precomp.txt"
            with open(Address, 'r') as f:
                dataStr = f.read()
                f.close()
            L = len(dataStr)
            N = (parameter ** 2) * 5
            try:
                if (L != N and L != N + 1) or (L == N + 1 and dataStr[N] != "\n"):
                    raise ValueError("Invalid precomputation list. Rewrite it, then run the script again.")
                else:
                    N = parameter ** 2
                    for i in range(0, N):
                        dataList.append(np.array([gf.Str2Num(dataStr[5 * i + 2]), gf.Str2Num(dataStr[5 * i + 3])], dtype = np.uint8))
                    return dataList

            except ValueError as e1:
                print("Invalid input.", e1)

    except TypeError as e2:
        print("Invalid input.", e2)
##########################################################################

#################################Sieving##################################
def Sieving(preCompList: list, ctxList: list, phase: int) -> list:
    try:
        if type(preCompList) != list or type(ctxList) != list or type(phase) != int and phase < 1 or phase > 2:
            raise TypeError("The first and second inputs must be lists and the last input must be either 1 or 2.")
        else:
            L1 = len(preCompList)
            L2 = len(ctxList)
            metric = 0
            sqrVec = [1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225]
            for i in range(0, 15):
                if sqrVec[i] - L1 == 0:
                    metric = i + 1
                    break
            try:
                if L2 != 1024 or metric == 0:
                    raise ValueError("Either precomputation or ciphertext lists are not valid.")
                else:
                    keyCandidate = []
                    P0 = np.array([0, 0], dtype = np.uint8)
                    P1 = P0.copy()
                    P2 = P0.copy()
                    P3 = P0.copy()
                    C0 = np.array([[0, 0],
                                   [0, 0]], dtype = np.uint8)
                    if phase == 1:
                        offset = 0
                        index0 = 0
                        index1 = 1
                    else:
                        offset = 512
                        index0 = 1
                        index1 = 0
                    for k0 in range (0, 16):
                        for k1 in range (0, 16):
                            discardFlag = False
                            for i in range(0, metric):
                                for j in range(i + 1, metric):
                                    for l in range(0, metric):
                                        for m in range(l + 1, metric):
                                            numX0 = metric * i + l
                                            numX1 = metric * j + m
                                            numX2 = metric * j + l
                                            numX3 = metric * i + m
                                            X0 = preCompList[numX0].copy()
                                            X1 = preCompList[numX1].copy()
                                            X2 = preCompList[numX2].copy()
                                            X3 = preCompList[numX3].copy()
                                            P0[index0] = gf.NibXor(X0[index0], np.uint8(k0))
                                            P1[index0] = gf.NibXor(X1[index0], np.uint8(k0))
                                            P2[index0] = gf.NibXor(X2[index0], np.uint8(k0))
                                            P3[index0] = gf.NibXor(X3[index0], np.uint8(k0))
                                            P0[index1] = gf.NibXor(X0[index1], np.uint8(k1))
                                            P1[index1] = gf.NibXor(X1[index1], np.uint8(k1))
                                            P2[index1] = gf.NibXor(X2[index1], np.uint8(k1))
                                            P3[index1] = gf.NibXor(X3[index1], np.uint8(k1))
                                            num0 = int(16 * P0[0] + P0[1])
                                            num1 = int(16 * P1[0] + P1[1])
                                            num2 = int(16 * P2[0] + P2[1])
                                            num3 = int(16 * P3[0] + P3[1])
                                            for n in range(0, 2):
                                                C0 = ctxList[num0 + offset + 256 * n]
                                                C1 = ctxList[num1 + offset + 256 * n]
                                                C2 = ctxList[num2 + offset + 256 * n]
                                                C3 = ctxList[num3 + offset + 256 * n]
                                                delC01 = func.AddRoundKey(C0, C1)
                                                delC23 = func.AddRoundKey(C2, C3)
                                                if (delC01[0][0] == 0 and delC01[1][1] == 0 and (delC23[0][0] != 0 or delC23[1][1] != 0)):
                                                    discardFlag = True
                                                    break
                                                elif (delC23[0][0] == 0 and delC23[1][1] == 0 and (delC01[0][0] != 0 or delC01[1][1] != 0)):
                                                    discardFlag = True
                                                    break
                                                elif (delC01[0][1] == 0 and delC01[1][0] == 0 and (delC23[0][1] != 0 or delC23[1][0] != 0)):
                                                    discardFlag = True
                                                    break
                                                elif (delC23[0][1] == 0 and delC23[1][0] == 0 and (delC01[0][1] != 0 or delC01[1][0] != 0)):
                                                    discardFlag = True
                                                    break
                                                else:
                                                    continue
                                            if discardFlag == True:
                                                break
                                        if discardFlag == True:
                                            break
                                    if discardFlag == True:
                                        break
                                if discardFlag == True:
                                    break
                            if discardFlag == False:
                                keyCandidate.append([k0, k1])
                            else:
                                p = 100 * offset / 1024 + floor(50 * (k1 + 16 * k0) / 256)
                                print(f"{p}% of fast impossible 4-tuple cryptanalsis has been completed.")
                                continue
                    return keyCandidate

            except ValueError as e1:
                print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

###############################Key Recovery###############################
def KeyRecovery(phase1Keys: list, phase2Keys: list, randomList: list, ctxList: list) -> None:
    try:
        if type(phase1Keys) != list or type(phase2Keys) != list or type(randomList) != list or type(ctxList) != list:
            raise TypeError("All inputs must be lists.")
        elif len(randomList) != 8 or len(ctxList) != 2:
            raise ValueError("The third input must be a list of length 8 and the fourth input must be a list of length 2.")
        elif len(phase1Keys) == 0 or len(phase2Keys) == 0:
            raise ValueError("The first and second inputs must be non-empty lists.")
        else:
            if len(phase1Keys) == 1 and len(phase2Keys) == 1:
                RecKey = np.array([[phase1Keys[0][0], phase2Keys[0][0]],
                                   [phase2Keys[0][1], phase1Keys[0][1]]], dtype = np.uint8)
                recFlag = True
            else:
                P1 = np.array([[0, randomList[1]],
                               [randomList[0], 0]], dtype = np.uint8)
                P2 = np.array([[randomList[6], 15],
                               [15, randomList[7]]], dtype = np.uint8)
                C1 = ctxList[0]
                C2 = ctxList[1]
                L1 = len(phase1Keys)
                L2 = len(phase2Keys)
                recFlag = False
                for i in range(0, L1):
                    for j in range(0, L2):
                        testKey = np.array([[phase1Keys[i][0], phase2Keys[j][0]],
                                            [phase2Keys[j][1], phase1Keys[i][1]]], dtype = np.uint8)
                        cHat1 = func.AES_Enc(P1, testKey, 5)
                        mat = func.AddRoundKey(cHat1, C1)
                        if np.sum(mat) == 0:
                            cHat2 = func.AES_Enc(P2, testKey, 5)
                            mat = func.AddRoundKey(cHat2, C2)
                            if np.sum(mat) == 0:
                                RecKey = testKey.copy()
                                recFlag = True
                                break
                    if recFlag == True:
                        break
            if recFlag == False:
                print("Error: Key has not been recovered! Please check the inputs.")
            else:
                print("Recovered master key:")
                print("\tBlock representation: ", [[int(RecKey[0][0]), int(RecKey[0][1])], [int(RecKey[1][0]), int(RecKey[1][1])]])
                print("\tStream representation: ", end = "")
                for i in range(0, 2):
                    for j in range(0, 2):
                        keyStream = gf.Int2Nib(RecKey[j][i])
                        for k in range(0, 4):
                            print(keyStream[k], end = "")
                print(" ")
                print("\tHexadecimal representation: ", end = "")
                MAT = "0123456789abcdef"
                key = "0x"
                for i in range(0, 2):
                    for j in range(0, 2):
                        key += MAT[RecKey[j][i]]
                print(key)

    except TypeError as e:
        print("Error: Invalid input.", e)
##########################################################################

#############################AddressModifier##############################
def AddressModifiy(Address: str) -> str:
    try:
        if type(Address) != str:
            raise TypeError("Invalid address.")
        else:
            Address.replace("\\", "\\\\")
            modifyAddress = Address
            return modifyAddress

    except TypeError as e:
        print("Error: Invalid input.", e)
##########################################################################

################################MainDriver################################
def main():
    Address = input("Please enter the target address to start the fast impossible 4-tuple cryptanalysis of miniAES. \nAddress: ")
    Address = AddressModifiy(Address)
    Precompute(Address, 6)
    preCompList = PreCompReader(Address, 6)
    randomList = DataCollector(Address)
    CtxGen(Address)
    ctxList = ctxReader(Address)
    keySet1 = Sieving(preCompList, ctxList, 1)
    keySet2 = Sieving(preCompList, ctxList, 2)
    ctxTestVec = []
    ctxTestVec.append(ctxList[0].copy())
    ctxTestVec.append(ctxList[1023].copy())
    KeyRecovery(keySet1, keySet2, randomList, ctxTestVec)

if __name__ == "__main__":
    main()
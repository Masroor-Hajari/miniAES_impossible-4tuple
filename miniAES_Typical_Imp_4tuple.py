# Impossible 4-tuple cryptanalysis of miniAES
#Typical Variant
# I. First Phase
    #1. Partial Decryption
    #2. Data Collection
    
# II. Second Phase
    #1. Partial Decryption
    #2. Data Collection

import numpy as np  
import GFexp2to4 as gf
import miniAES_Functions as func
from miniAES_Oracle import CtxGen
from random import randint
from math import floor

############################Partial Decryption############################
def PartDec(parameter: int) -> list:
    try:
        if type(parameter) != int or parameter < 1 or parameter > 15:
            raise TypeError("Input must be a valid integer between 1 and 15.")
        else:
            preList = []
            Y0 = np.array([0, 0], dtype = np.uint8)
            Y1 = Y0.copy()
            Y2 = Y0.copy()
            Y3 = Y0.copy()
            V0 = Y0.copy()
            V1 = Y0.copy()
            V2 = Y0.copy()
            V3 = Y0.copy()
            X0 = Y0.copy()
            X1 = Y0.copy()
            X2 = Y0.copy()
            X3 = Y0.copy()
            ctr = 0
            for i in range(0, parameter):
                Y0[0] = np.uint8(i)
                Y3[0] = np.uint8(i)
                for j in range(0, parameter):
                    Y0[1] = np.uint8(j)
                    Y2[1] = np.uint8(j)
                    V0 = func.SingleMixColumn(Y0)
                    X0[0] = func.InvSBox(V0[0])
                    X0[1] = func.InvSBox(V0[1])
                    for l in range(i + 1, parameter):
                        Y1[0] = np.uint8(l)
                        Y2[0] = np.uint8(l)
                        V2 = func.SingleMixColumn(Y2)
                        X2[0] = func.InvSBox(V2[0])
                        X2[1] = func.InvSBox(V2[1])
                        for m in range(j + 1, parameter):
                            Y1[1] = np.uint8(m)
                            Y3[1] = np.uint8(m)
                            V1 = func.SingleMixColumn(Y1)
                            V3 = func.SingleMixColumn(Y3)
                            X1[0] = func.InvSBox(V1[0])
                            X1[1] = func.InvSBox(V1[1])
                            X3[0] = func.InvSBox(V3[0])
                            X3[1] = func.InvSBox(V3[1])
                            preList.append(X0.copy())
                            preList.append(X1.copy())
                            preList.append(X2.copy())
                            preList.append(X3.copy())
            return preList

    except TypeError as e:
        print("Error: Invalid input.", e)
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
            randomList.append(element1)
            randomList.append(element2)
            randomList.append(element3)
            randomList.append(element4)
            MAT = "0123456789abcdef"
            Address += "\\miniAES_Ptx.txt"
            with open(Address,"w") as f:
                for i in range(0, 16):
                    for j in range(0, 16):
                        f.write("0x" + MAT[i] + MAT[element1] + MAT[element2] + MAT[j] + "\n")
                for i in range(0, 16):
                    for j in range(0, 16):
                        f.write("0x" + MAT[element3] + MAT[i] + MAT[j] + MAT[element4] + "\n")
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
                if (L != 3584 and L != 3585) or (L == 3585 and ctxStr[3584] != "\n"):
                    raise ValueError("Invalid ciphertext list. Rewrite it, then run the script again.")
                else:
                    for i in range(0, 512):
                        ctxList.append(np.array([[gf.Str2Num(ctxStr[7 * i + 2]), gf.Str2Num(ctxStr[7 * i + 4])],
                                                 [gf.Str2Num(ctxStr[7 * i + 3]), gf.Str2Num(ctxStr[7 * i + 5])]], dtype = np.uint8))
                    return ctxList

            except ValueError as e1:
                print("Invalid input.", e1)

    except TypeError as e2:
        print("Invalid input.", e2)
##########################################################################

#################################Sieving##################################
def Sieving(preList: list, ctxList: list, phase: int) -> list:
    try:
        if type(preList) != list or type(ctxList) != list or type(phase) != int and phase < 1 or phase > 2:
            raise TypeError("The first and second inputs must be lists and the last input must be either 1 or 2.")
        else:
            L1 = len(preList)
            L2 = len(ctxList)
            try:
                if L1 % 4 != 0 or L2 != 512:
                    raise ValueError("Either the first or second input lists are not valid.")
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
                        offset = 256
                        index0 = 1
                        index1 = 0
                    M = L1 // 4
                    for k0 in range (0, 16):
                        for k1 in range (0, 16):
                            discardFlag = False
                            for i in range(0, M):
                                P0[index0] = gf.NibXor(preList[4 * i][index0], np.uint8(k0))
                                P1[index0] = gf.NibXor(preList[4 * i + 1][index0], np.uint8(k0))
                                P2[index0] = gf.NibXor(preList[4 * i + 2][index0], np.uint8(k0))
                                P3[index0] = gf.NibXor(preList[4 * i + 3][index0], np.uint8(k0))
                                P0[index1] = gf.NibXor(preList[4 * i][index1], np.uint8(k1))
                                P1[index1] = gf.NibXor(preList[4 * i + 1][index1], np.uint8(k1))
                                P2[index1] = gf.NibXor(preList[4 * i + 2][index1], np.uint8(k1))
                                P3[index1] = gf.NibXor(preList[4 * i + 3][index1], np.uint8(k1))
                                num0 = int(16 * P0[0] + P0[1])
                                num1 = int(16 * P1[0] + P1[1])
                                num2 = int(16 * P2[0] + P2[1])
                                num3 = int(16 * P3[0] + P3[1])
                                C0 = ctxList[num0 + offset]
                                C1 = ctxList[num1 + offset]
                                C2 = ctxList[num2 + offset]
                                C3 = ctxList[num3 + offset]
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
                            if discardFlag == False:
                                keyCandidate.append([k0, k1])
                            else:
                                p = 100 * offset / 512 + floor(50 * (k1 + 16 * k0) / 256)
                                print(f"{p}% of typical impossible 4-tuple cryptanalsis has been completed.")
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
        elif len(randomList) != 4 or len(ctxList) != 2:
            raise ValueError("The third input must be a list of length 4 and the fourth input must be a list of length 2.")
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
                P2 = np.array([[randomList[2], 15],
                               [15, randomList[3]]], dtype = np.uint8)
                C1 = ctxList[0]
                C2 = ctxList[1]
                L1 = len(phase1Keys)
                L2 = len(phase2Keys)
                recFlag = False
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
    Address = input("Please enter the target address to start the typical impossible 4-tuple cryptanalysis of miniAES. \nAddress: ")
    Address = AddressModifiy(Address)
    preList = PartDec(8)
    randomList = DataCollector(Address)
    CtxGen(Address)
    ctxList = ctxReader(Address)
    keySet1 = Sieving(preList, ctxList, 1)
    keySet2 = Sieving(preList, ctxList, 2)
    ctxTestVec = []
    ctxTestVec.append(ctxList[0].copy())
    ctxTestVec.append(ctxList[511].copy())
    KeyRecovery(keySet1, keySet2, randomList, ctxTestVec)

if __name__ == "__main__":
    main()
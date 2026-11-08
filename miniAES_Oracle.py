#miniAES encryption Oracle.
#Insert 16-bit master key and chosen plaintexts in text files, "miniAES_Key.txt", and "miniAES_Ptx.txt." respectively.
#Oracle provides the corresponding ciphertexts in the text file, "miniAES_Ctx.txt".
import numpy as np
import GFexp2to4 as gf
from miniAES_Functions import AES_Enc

################################KeyReader#################################
def keyReader(Address: str) -> np.uint8:
    try:
        if type(Address) != str:
            raise TypeError("Input must be a valid address.")
        else:
            Key = np.array([[0, 0],
                            [0, 0]], dtype = np.uint8)
            Address += "\\miniAES_Key.txt"
            with open(Address, 'r') as f:
                keyStr = f.read()
                f.close()
            L = len(keyStr)
            try:
                if (L != 6 and L != 7) or (L == 7 and keyStr[6] != "\n"):
                    raise ValueError("Invalid master key. Rewrite it, then run the script again.")
                elif keyStr[0] != "0" or keyStr[1] != "x":
                    raise ValueError("Invalid master key. It must be started with ""0x"" prefix. Rewrite it, then run the script again.")
                else:
                    Key[0][0] = gf.Str2Num(keyStr[2])
                    Key[1][0] = gf.Str2Num(keyStr[3])
                    Key[0][1] = gf.Str2Num(keyStr[4])
                    Key[1][1] = gf.Str2Num(keyStr[5])
                    return Key

            except ValueError as e1:
                print(e1)

    except TypeError as e2:
        print("Invalid input.", e2)
##########################################################################

################################PtxReader#################################
def ptxReader(Address: str) -> list:
    try:
        if type(Address) != str:
            raise TypeError("Input must be a valid address.")
        else:
            ptxList = []
            Address += "\\miniAES_Ptx.txt"
            with open(Address, 'r') as f:
                ptxStr = f.read()
                f.close()
            L = len(ptxStr)
            try:
                if (L != 3584 and L != 3585 and L != 7168 and L != 7169) or (L == 3585 and ptxStr[3584] != "\n" and L == 7169 and ptxStr[7168] != "\n"):
                    raise ValueError("Invalid ciphertext list. Rewrite it, then run the script again.")
                else:
                    N = L // 7
                    for i in range(0, N):
                        ptxList.append(np.array([[gf.Str2Num(ptxStr[7 * i + 2]), gf.Str2Num(ptxStr[7 * i + 4])],
                                                 [gf.Str2Num(ptxStr[7 * i + 3]), gf.Str2Num(ptxStr[7 * i + 5])]], dtype = np.uint8))
                    return ptxList

            except ValueError as e1:
                print("Invalid input.", e1)

    except TypeError as e2:
        print("Invalid input.", e2)
##########################################################################

##############################CtxGenerator################################
def CtxGen(Address: list) -> None:
    try:
        if type(Address) != str:
            raise TypeError("Inputs must be a valid address.")
        else:
            ptxList = ptxReader(Address)
            masterKey = keyReader(Address)
            ctxList = []
            L = len(ptxList)
        try:
            if L != 512 and L != 1024:
                raise ValueError("The text file ""miniAES_Ptx.txt"" does not have either 512 or 1024 plaintexts.")
            else:
                for i in range(0, L):
                    ctxList.append(AES_Enc(ptxList[i], masterKey, 5))
                CtxWriter(ctxList, Address)

        except ValueError as e1:
            print("Invalid input.", e1)

    except TypeError as e2:
        print("Invalid input.", e2)
##########################################################################

##############################CtxWriter################################
def CtxWriter(ctxList: list, Address: str) -> None:
    try:
        L = len(ctxList)
        if type(Address) != str:
            raise TypeError("The second input must be a valid address.")
        elif L != 512 and L != 1024:
            raise ValueError("The first input must be a list of either 512 or 1024 ciphertexts.")
        else:
            Address += "\\miniAES_Ctx.txt"
            MAT = "0123456789abcdef"
            with open(Address, "w") as f:
                for i in range(0, L):
                    f.write("0x" + MAT[ctxList[i][0][0]] + MAT[ctxList[i][1][0]] + MAT[ctxList[i][0][1]] + MAT[ctxList[i][1][1]] + "\n")
                f.close()

    except TypeError as e1:
        print("Invalid input.", e1)

    except ValueError as e2:
        print("Invalid input.", e2)
##########################################################################
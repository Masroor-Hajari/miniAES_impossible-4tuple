# Galois Field 2^4: P(X) = X^4 + X + 1
import numpy as np

#################################Int2Nib##################################
#Extract the corresponding nibble form of integer numbers between 0 and 15.
def Int2Nib(I: np.uint8) -> np.uint8:
    try:
        if I.dtype != np.uint8:
            raise TypeError("Input must be an integer number.")
        elif I > 15 or I < 0:
            raise ValueError("Input is out of range. It must be an integer number between 0 and 15.")
        else:
            B = np.array([0, 0, 0, 0], dtype = np.uint8)
            Temp = I
            B[0] = Temp // 8
            for i in range(0, 3):
                B[3 - i] = Temp % 2
                Temp = (Temp - B[3 - i]) // 2
            return B.astype(np.uint8)

    except TypeError as e1:
        print("Error: Invalid input.", e1)

    except ValueError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

#################################Nib2Int##################################
#Extract the corresponding integer number from the input nibble.
def Nib2Int(B: np.uint8) -> np.uint8:
    l = len(B)
    try:
        if l != 4 or B.dtype != np.uint8:
            raise TypeError("Input must be a 4-bit binary vector.")
        elif max(B) > 1 or min(B) < 0:
            raise ValueError("Input must be a 4-bit binary vector.")
        else:
            I = 8 * B[0] + 4 * B[1] + 2 * B[2] + B[3]
            return I.astype(np.uint8)
    
    except TypeError as e1:
        print("Error: Invalid input.", e1)

    except ValueError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

#################################NibXor###################################
#Xor operation applied on 4-bit nibbles.
def NibXor(nib1: np.uint8, nib2: np.uint8) -> np.uint8:
    try:
        if nib1.dtype != np.uint8 or nib2.dtype != np.uint8:
            raise TypeError("Inputs must be integer numbers.")
        elif nib1 > 15 or nib1 < 0 or nib2 > 15 or nib2 < 0:
            raise ValueError("Inputs must be integers between 0 and 15.")
        else:
            B3 = np.array([0, 0, 0, 0], dtype = np.uint8)
            B1 = Int2Nib(nib1)
            B2 = Int2Nib(nib2)
            for i in range(0, 4):
                B3[i] = B1[i] ^ B2[i]
            nibXor = Nib2Int(B3)
            return nibXor.astype(np.uint8)

    except TypeError as e1:
        print("Error: Invalid input.", e1)

    except ValueError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

################################multiply2#################################
#multiplying the input nibble into 0x2 (0010).
def multiply2(nibInput: np.uint8) -> np.uint8:
    try:
        if nibInput.dtype != np.uint8:
            raise TypeError("Input must be an integer number.")
        elif nibInput > 15 or nibInput < 0:
            raise ValueError("Input must be integers between 0 and 15.")
        else:
            B = Int2Nib(nibInput)
            C = np.array([0, 0, 0, 0], dtype = np.uint8)
            for i in range(1, 4):
                C[i - 1] = B[i]
            if B[0] == 1:
                C[2] = 1 - C[2]
                C[3] = 1 - C[3]
            nibOutput = Nib2Int(C)
            return nibOutput.astype(np.uint8)

    except TypeError as e1:
        print("Error: Invalid input.", e1)

    except ValueError as e2:
        print("Error: Invalid input.", e2)
##########################################################################
        
################################multiply3#################################
#multiplying the input nibble into 0x3 (0011).
def multiply3(nibInput: np.uint8) -> np.uint8:
    try:
        if nibInput.dtype != np.uint8:
            raise TypeError("Input must be an integer number.")
        elif nibInput > 15 or nibInput < 0:
            raise ValueError("Input must be integers between 0 and 15.")
        else:
            temp = multiply2(nibInput)
            nibOutput = NibXor(temp, nibInput)
            return nibOutput.astype(np.uint8)

    except TypeError as e1:
        print("Error: Invalid input.", e1)

    except ValueError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

#################################Str2Num##################################
def Str2Num(st: str) -> np.uint8:
    try:
        if type(st) != str or ord(st) < 48 or ord(st) > 102 or (ord(st) > 57 and ord(st) < 97):
            raise TypeError("Input must be a hexadecimal character which it belongs to {0,1,2,...,9,a,b,...,f}.")
        else:
            u = ord(st)
            if u < 58:
                n = np.uint8(u - 48)
            else:
                n = np.uint8(u - 87)
            return n.astype(np.uint8)

    except TypeError as e:
        print("Error: Invalid input.", e)
##########################################################################

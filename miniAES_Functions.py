# Implementation of miniAES block cipher
import numpy as np
import GFexp2to4 as gf

##################################SBox####################################
#miniAES SBOX function.
def SBox(i: np.uint8) -> np.uint8:
    try:
        if i.dtype != np.uint8:
            raise TypeError("Input must be an integer number.")
        elif i > 15 or i < 0:
            raise ValueError("Input must be integers between 0 and 15.")
        else:
            S = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]
            j = np.uint8(S[i])
            return j.astype(np.uint8)

    except TypeError as e1:
        print("Error: Invalid input.", e1)

    except ValueError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

#################################InvSBox##################################
#miniAES inverse-SBOX function.
def InvSBox(i: np.uint8) -> np.uint8:
    try:
        if i.dtype != np.uint8:
            raise TypeError("Input must be an integer number.")
        elif i > 15 or i < 0:
            raise ValueError("Input must be integers between 0 and 15.")
        else:
            IS = [14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5]
            j = np.uint8(IS[i])
            return j.astype(np.uint8)

    except TypeError as e1:
        print("Error: Invalid input.", e1)

    except ValueError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

###############################SubNibbles#################################
#miniAES SubNibbles operation.
def SubNibbles(X: np.uint8) -> np.uint8:
    m, n = X.shape
    try:
        if m != 2 or n != 2:
            raise ValueError("Input must be a 2x2 matrix.")
        elif X.dtype != np.uint8 or np.max(X) > 15 or np.min(X) < 0:
            raise TypeError("Input must be an integer matrix and each elements of it must be between 0 and 15.")
        else:
            Y = np.array([[0, 0],
                          [0, 0]], dtype = np.uint8)
            for i in range(0, 2):
                for j in range(0, 2):
                    Y[i][j] = SBox(X[i][j])
            return Y.copy()

    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

##############################InvSubNibbles###############################
#miniAES inverse-SubNibbles operation.
def InvSubNibbles(X: np.uint8) -> np.uint8:
    m, n = X.shape
    try:
        if m != 2 or n != 2:
            raise ValueError("Input must be a 2x2 matrix.")
        elif X.dtype != np.uint8 or np.max(X) > 15 or np.min(X) < 0:
            raise TypeError("Input must be an integer matrix and each elements of it must be between 0 and 15.")
        else:
            Y = np.array([[0, 0],
                          [0, 0]], dtype = np.uint8)
            for i in range(0, 2):
                for j in range(0, 2):
                    Y[i][j] = InvSBox(X[i][j])
            return Y.copy()

    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

################################ShiftRows#################################
#miniAES ShiftRows operation.
def ShiftRows(X):
    m, n = X.shape
    try:
        if m != 2 or n != 2:
            raise ValueError("Input must be a 2x2 matrix.")
        elif X.dtype != np.uint8 or np.max(X) > 15 or np.min(X) < 0:
            raise TypeError("Input must be an integer matrix and each elements of it must be between 0 and 15.")
        else:
            Y = np.array([[0, 0],
                          [0, 0]], dtype = np.uint8)
            for i in range(0, 2):
                for j in range(0, 2):
                    Y[i][j] = X[i][(j + i) % 2]
            return Y.copy()

    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

##############################oneMixColumn################################
#miniAES Mixing of one input column operation.
def SingleMixColumn(X):
    L = len(X)
    try:
        if L != 2:
            raise ValueError("Input must a 2-element vector.")
        elif X.dtype != np.uint8 or np.max(X) > 15 or np.min(X) < 0:
            raise TypeError("Input must be an integer matrix and each elements of it must be between 0 and 15.")
        else:
            Y = np.array([0, 0], dtype = np.uint8)
            Y[0] = gf.NibXor(gf.multiply2(X[0]), gf.multiply3(X[1]))
            Y[1] = gf.NibXor(gf.multiply3(X[0]), gf.multiply2(X[1]))
            return Y.copy()

    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

###############################MixColumns#################################
#miniAES MixColumns operation.
def MixColumns(X):
    m, n = X.shape
    try:
        if m != 2 or n != 2:
            raise ValueError("Input must be a 2x2 matrix.")
        elif X.dtype != np.uint8 or np.max(X) > 15 or np.min(X) < 0:
            raise TypeError("Input must be an integer matrix and each elements of it must be between 0 and 15.")
        else:
            Y = np.array([[0, 0],
                          [0, 0]], dtype = np.uint8)
            for i in range(0, 2):
                Y[0][i] = gf.NibXor(gf.multiply3(X[0][i]), gf.multiply2(X[1][i]))
                Y[1][i] = gf.NibXor(gf.multiply2(X[0][i]), gf.multiply3(X[1][i]))
            return Y.copy()

    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

###############################AddRoundKey################################
#miniAES MixColumns operation.
def AddRoundKey(X: np.uint8, K:np.uint8):
    m, n = X.shape
    p, q = K.shape
    try:
        if m != 2 or n != 2 or p != 2 or q != 2:
            raise ValueError("Inputs must be a 2x2 matrices.")
        elif X.dtype != np.uint8 or K.dtype != np.uint8 or np.max(X) > 15 or np.min(X) < 0 or np.max(K) > 15 or np.min(K) < 0:
            raise TypeError("Inputs must be integer matrice and each elements of it must be between 0 and 15.")
        else:
            Y = np.array([[0, 0],
                          [0, 0]], dtype = np.uint8)
            for i in range(0, 2):
                for j in range(0, 2):
                    Y[i][j] = gf.NibXor(X[i][j], K[i][j])
            return Y.copy()

    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

##############################RoundFunction###############################
#miniAES round funvtion.
def RoundFunc(X: np.uint8, K:np.uint8) -> np.uint8:
    m, n = X.shape
    p, q = K.shape
    try:
        if m != 2 or n != 2 or p != 2 or q != 2:
            raise ValueError("Inputs must be a 2x2 matrices.")
        elif X.dtype != np.uint8 or K.dtype != np.uint8 or np.max(X) > 15 or np.min(X) < 0 or np.max(K) > 15 or np.min(K) < 0:
            raise TypeError("Inputs must be integer matrice and each elements of it must be between 0 and 15.")
        else:
            Z = SubNibbles(X)
            W = ShiftRows(Z)
            V = MixColumns(W)
            Y = AddRoundKey(V, K)
            return Y.copy()
    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

###############################KeySchedule################################
#miniAES one-round key schedule process.
def KeySchdl(MK: np.uint8, r: int):
    m, n = MK.shape
    try:
        if m != 2 or n != 2 or type(r) != int or r > 10 or r < 0:
            raise ValueError("The first input must be a 2x2 matrix and the second input must be an integer between 0 and 10.")
        elif MK.dtype != np.uint8 or np.max(MK) > 15 or np.min(MK) < 0:
            raise TypeError("The first input must be an integer matrix and each elements of it must be between 0 and 15.")
        else:
            RK = np.array([[0, 0],
                           [0, 0]], dtype = np.uint8)
            RK[0][0] = gf.NibXor(MK[0][0], SBox(MK[1][1]))
            RK[0][0] = gf.NibXor(RK[0][0], np.uint8(r))
            RK[1][0] = gf.NibXor(MK[1][0], RK[0][0])
            RK[0][1] = gf.NibXor(MK[0][1], RK[1][0])
            RK[1][1] = gf.NibXor(MK[1][1], RK[0][1])
            return RK.copy()

    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

###############################miniAES_Enc################################
#miniAES one-round encrption process.
def AES_Enc(P: np.uint8, MK: np.uint8, r: int):
    m, n = MK.shape
    p, q = P.shape
    try:
        if m != 2 or n != 2 or p != 2 or q != 2 or type(r) != int or r > 10 or r < 0:
            raise ValueError("The first and second inputs must be 2x2 matrices and the third input must be an integer between 0 and 10.")
        elif MK.dtype != np.uint8 or np.max(MK) > 15 or np.min(MK) < 0 or P.dtype != np.uint8 or np.max(P) > 15 or np.min(P) < 0:
            raise TypeError("The first and second inputs must be integer matrices and each elements of them must be between 0 and 15.")
        else:
            C = np.array([[0, 0],
                          [0, 0]], dtype = np.uint8)
            X = AddRoundKey(P, MK)
            RK = MK.copy()
            for i in range(1, r):
                Temp = KeySchdl(RK, i)
                RK = Temp.copy()
                X = RoundFunc(X, RK)
            Temp = KeySchdl(RK, r) 
            RK = Temp.copy()
            X = SubNibbles(X)
            X = ShiftRows(X)
            C = AddRoundKey(X, RK)
            return C

    except ValueError as e1:
        print("Error: Invalid input.", e1)

    except TypeError as e2:
        print("Error: Invalid input.", e2)
##########################################################################

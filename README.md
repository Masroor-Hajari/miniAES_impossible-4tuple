# A Novel Key-Recovery Method: Impossible 4-Tuple Cryptanalysis

This repository implements the *impossible 4-tuple cryptanalysis* technique on the 5-round miniAES algorithm. Using this method, it is possible to recover the secret key via two variants:

1. Typical impossible 4-tuple cryptanalysis  
2. Fast impossible 4-tuple cryptanalysis  

---

## Instructions for Key Recovery

To recover the master key of the 5-round miniAES algorithm, follow the steps below:

1. Place the package files in the directory where Python is installed  
   (e.g., `C:\Users\myAccount\AppData\Local\Programs\Python\Python310`).

2. Enter the secret key of the miniAES algorithm in the file `miniAES_Key.txt`.  
   Since the algorithm uses a 16-bit master key, the key must consist of **four lowercase hexadecimal characters** (e.g., `f345`).

3. To recover the key using the *typical version*, open the command prompt and run:
   ```bash
   python miniAES_Typical_Imp_4tuple.py

4. Also, to recover the key via the *fast version*, execute the following command: :
   ```bash
   python miniAES_Fast_Imp_4tuple.py

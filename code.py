from webbrowser import get
import streamlit as st
# Bai 1: Cac he ma co dien
# 1. Ma dao nguoc - Reverse Cipher
def encrypt (message):
    i = len(message) - 1
    translated = ''
    while i >= 0:
        translated = translated + message[i]
        i = i - 1
    return translated

def decrypt (translated):
    i = len(translated) - 1
    decrypted = ''
    while i >= 0:
        decrypted = decrypted + translated[i]
        i = i - 1
    return decrypted

# message = 'This is program to explain reverse cipher.'

# translated = encrypt (message)
# print("The cipher text is : ", translated)

# decrypted = decrypt (translated)
# print("The plain text is : ", decrypted)

#2.  Ma Caesar - Caesar Cipher
def encryptCaesar(text,k):
    text = text.replace(" ","")
    result = ""
    for i in range(len(text)):
        char = text[i]
        if (char.isupper()):
            result += chr((ord(char) + k - 65) % 26 + 65)
        else:
            result += chr((ord(char) + k - 97) % 26 + 97)
    return result
def decryptCaesar(text,k):
    text = text.replace(" ","")
    result = ""
    for i in range(len(text)):
        char = text[i]
        if (char.isupper()):
            result += chr((ord(char) - k - 65) % 26 + 65)
        else:
            result += chr((ord(char) - k - 97) % 26 + 97)
    return result
# text = "CEasER CIPHER DEMO"
# k = 4
# print ("Key = : " ,k)
# c = encryptCaesar(text,k)
# print ("Cipher text: ", c )
# print ("Plain text: ", decryptCaesar(c,k))
# 3. Ma doi cho
def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]
def encryptDc(plaintext, key):
    plaintext = plaintext.replace(" ","")
    order = {
        int(val): num for num, val in enumerate(key)
    }
    ciphertext = ''
    for index in sorted(order.keys()):
        for part in split_len(plaintext, len(key)):
            try:ciphertext += part[order[index]]
            except IndexError:
                continue
    return ciphertext
def decryptDc(ciphertext, key):
    ciphertext = ciphertext.replace(" ","")
    order = {
        int(val): num for num, val in enumerate(key)
    }
    plaintext = ''
    n = int(len(ciphertext)/len(key))
    for index in sorted(order.keys()):
        for part in split_len(ciphertext, n):
            try:plaintext += part[order[index]]
            except IndexError:
                continue
    return plaintext
# k = "12345"
# c = encryptDc('HELLOWORLDLOVES',k)
# print(c)
# print(decryptDc(c,k))
# 4. Ma thay the don
import random, sys
def encryptChange(message, key):
    translated = ''
    charsA = LETTERS
    charsB = key
    for symbol in message:
        if symbol.upper() in charsA:
            symIndex = charsA.find(symbol.upper())
            if symbol.isupper():
                translated += charsB[symIndex].upper()
            else:
                translated += charsB[symIndex].lower()
        else:
            translated += symbol
    return translated
def decryptChange(message, key):
    translated = ''
    charsB = LETTERS
    charsA = key
    for symbol in message:
        if symbol.upper() in charsA:
            symIndex = charsA.find(symbol.upper())
            if symbol.isupper():
                translated += charsB[symIndex].upper()
            else:
                translated += charsB[symIndex].lower()
        else:
            translated += symbol
    return translated
def getRandomKey():
    randomList = list(LETTERS)
    random.shuffle(randomList)
    return ''.join(randomList)

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
# message = 'defend the east wall of the castle'
# key = ''
# key = input("Enter 26 ALPHA key (blank for random key): ")
# if key == '':
#     key = getRandomKey()

# translated = encryptChange(message, key)
# print('Using key: %s' % (key))
# print('Cipher: ' + translated)
# print('Plain: ' + decryptChange(translated,key))
# Phien ban khac
# import random, sys
# LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
# def main():
#     message = ''
#     if len(sys.argv) > 1:
#         with open(sys.argv[1], 'r') as f:
#             message = f.read()
#     else:
#         message = input("Enter your message: ")
#         mode = input("E for Encrypt, D for Decrypt: ")
#         key = ''

#     while checkKey(key) is False:
#         key = input("Enter 26 ALPHA key (enter for random key): ")
#         if key == '':
#             key = getRandomKey()
#     if checkKey(key) is False:
#         print("There is an error in the key or symbol set.")
#         translated = translateMessage(message, key, mode)
#         print('Using key: %s' % (key))
#     if len(sys.argv) > 1:
#         fileOut = 'enc.' + sys.argv[1]
#         with open(fileOut, 'w') as f:
#             f.write(translated)
#         print('Success! File written to: %s' % (fileOut))
#     else: print('Result: ' + translated)

# def checkKey(key):
#     keyString = ''.join(sorted(list(key)))
#     return keyString == LETTERS

# def translateMessage(message, key, mode):
#     translated = ''
#     charsA = LETTERS
#     charsB = key
#     if mode == 'D':
#         charsA, charsB = charsB, charsA
#     for symbol in message:
#         if symbol.upper() in charsA:
#             symIndex = charsA.find(symbol.upper())
#             if symbol.isupper():
#                 translated += charsB[symIndex].upper()
#             else:
#                 translated += charsB[symIndex].lower()
#         else:
#             translated += symbol
#     return translated
# def getRandomKey():
#     randomList = list(LETTERS)
#     random.shuffle(randomList)
#     return ''.join(randomList)
# if __name__ == '__main__':
#     main()
# 5. Ma Affine
# def mod_inverse(x,m):
#     for n in range(m):
#         if (x * n) % m == 1:
#             return n
#             break
#         elif n == m - 1:
#             return "Null"
#         else:
#             continue

# class Affine(object):
#     DIE = 26
#     KEY = (9, 3, mod_inverse(9,26))
#     def __init__(self):
#         pass
#     def encryptChar(self, char):
#         K1, K2, kI = self.KEY
#         return chr((K1 * (ord(char)-65) + K2) % self.DIE + 65)
    
#     def encrypt(self, string):
#         return "".join(map(self.encryptChar, string))

#     def decryptChar(self, char):
#         K1, K2, KI = self.KEY
#         return chr(KI * ((ord(char)-65) - K2) % self.DIE + 65)

#     def decrypt(self, string):
#         return "".join(map(self.decryptChar, string))

# affine = Affine()
# p = 'ONAUGUST'
# c = affine.encrypt(p)
# print (affine.KEY)
# print (c)
# print(affine.decrypt(c))
# 6. Ma Vigenere
def encryptVigenere(plaintext, key):
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    ciphertext = ''
    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) % 26
        ciphertext += chr(value + 65)
    return ciphertext


def decryptVigenere(ciphertext, key):
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext_int = [ord(i) for i in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
        plaintext += chr(value + 65)
    return plaintext

# p = "THISCRYPTOSYSTEMISNOTSECURE"
# k = "CIPHER"
# c = encrypt(p,k)
# print (c)
# print (decrypt(c,k))
# 7. Ma Hill
import numpy as np


def encryptHill(msg,C):
    # Replace spaces with nothing
    msg = msg.replace(" ", "")
    # Ask for keyword and get encryption matrix
    # Append zero if the messsage isn't divisble by 2
    len_check = len(msg) % 2 == 0
    if not len_check:
        msg += "0"
    # Populate message matrix
    P = create_matrix_of_integers_from_string(msg)
    # Calculate length of the message
    msg_len = int(len(msg) / 2)
    # Calculate P * C
    encrypted_msg = ""
    for i in range(msg_len):
        # Dot product
        row_0 = P[0][i] * C[0][0] + P[1][i] * C[0][1]
        # Modulate and add 65 to get back to the A-Z range in ascii
        integer = int(row_0 % 26 + 65)
        # Change back to chr type and add to text
        encrypted_msg += chr(integer)
        # Repeat for the second column
        row_1 = P[0][i] * C[1][0] + P[1][i] * C[1][1]
        integer = int(row_1 % 26 + 65)
        encrypted_msg += chr(integer)
    return encrypted_msg

def decryptHill(encrypted_msg,C):
    # Ask for keyword and get encryption matrix
    # Inverse matrix
    determinant = C[0][0] * C[1][1] - C[0][1] * C[1][0]
    determinant = determinant % 26
    multiplicative_inverse = find_multiplicative_inverse(determinant)
    C_inverse = C
    # Swap a <-> d
    C_inverse[0][0], C_inverse[1][1] = C_inverse[1, 1], C_inverse[0, 0]
    # Replace
    C[0][1] *= -1
    C[1][0] *= -1
    for row in range(2):
        for column in range(2):
            C_inverse[row][column] *= multiplicative_inverse
            C_inverse[row][column] = C_inverse[row][column] % 26

    P = create_matrix_of_integers_from_string(encrypted_msg)
    msg_len = int(len(encrypted_msg) / 2)
    decrypted_msg = ""
    for i in range(msg_len):
        # Dot product
        column_0 = P[0][i] * C_inverse[0][0] + P[1][i] * C_inverse[0][1]
        # Modulate and add 65 to get back to the A-Z range in ascii
        integer = int(column_0 % 26 + 65)
        # Change back to chr type and add to text
        decrypted_msg += chr(integer)
        # Repeat for the second column
        column_1 = P[0][i] * C_inverse[1][0] + P[1][i] * C_inverse[1][1]
        integer = int(column_1 % 26 + 65)
        decrypted_msg += chr(integer)
    if decrypted_msg[-1] == "0":
        decrypted_msg = decrypted_msg[:-1]
    return decrypted_msg

def find_multiplicative_inverse(determinant):
    multiplicative_inverse = -1
    for i in range(26):
        inverse = determinant * i
        if inverse % 26 == 1:
            multiplicative_inverse = i
            break
    return multiplicative_inverse


def make_key(cipher):
     # Make sure cipher determinant is relatively prime to 26 and only a/A - z/Z are given
    determinant = 0
    C = None
    while True:
        C = create_matrix_of_integers_from_string(cipher)
        determinant = C[0][0] * C[1][1] - C[0][1] * C[1][0]
        determinant = determinant % 26
        inverse_element = find_multiplicative_inverse(determinant)
        if inverse_element == -1:
            st.warning('Determinant is not relatively prime to 26, uninvertible key')
            break
        elif np.amax(C) > 26 and np.amin(C) < 0:
            st.warning('Only a-z characters are accepted')
            print(np.amax(C), np.amin(C))
            st.warning(np.amax(C), np.amin(C))
            break
        else:
            break
    return C

def create_matrix_of_integers_from_string(string):
    # Map string to a list of integers a/A <-> 0, b/B <-> 1 ... z/Z <-> 25
    integers = [chr_to_int(c) for c in string]
    length = len(integers)
    M = np.zeros((2, int(length / 2)), dtype=np.int32)
    iterator = 0
    for column in range(int(length / 2)):
        for row in range(2):
            M[row][column] = integers[iterator]
            iterator += 1
    return M

def chr_to_int(char):
    # Uppercase the char to get into range 65-90 in ascii table
    char = char.upper()
    # Cast chr to int and subtract 65 to get 0-25
    integer = ord(char) - 65
    return integer

# if __name__ == "__main__":
#     msg = input("Message: ")
#     encrypted_msg = encrypt(msg)
#     print(encrypted_msg)
#     decrypted_msg = decrypt(encrypted_msg)
#     print(decrypted_msg)

# 8. Bai tap
# Bai 1: Viet chuong trinh ma hoa va giai ma cho he ROT13 
# def encrypt(text,k):
#     text = text.replace(" ","")
#     result = ""
#     for i in range(len(text)):
#         char = text[i]
#         if (char.isupper()):
#             result += chr((ord(char) + k - 65) % 26 + 65)
#         else:
#             result += chr((ord(char) + k - 97) % 26 + 97)
#     return result
# def decrypt(text,k):
#     text = text.replace(" ","")
#     result = ""
#     for i in range(len(text)):
#         char = text[i]
#         if (char.isupper()):
#             result += chr((ord(char) - k - 65) % 26 + 65)
#         else:
#             result += chr((ord(char) - k - 97) % 26 + 97)
#     return result
# text = "CEasER CIPHER DEMO"
# k = 13
# print ("Key = : " ,k)
# c = encrypt(text,k)
# print ("Cipher text: ", c )
# print ("Plain text: ", decrypt(c,k))
# Bài 2. Tìm hiểu module base64, sử dụng base64 để viết chương trình mã hóa và giải mã
# văn bản.
# import base64

# data = "rav"

# # Standard Base64 Encoding
# encodedBytes = base64.b64encode(data.encode("utf-8"))
# encodedStr = str(encodedBytes, "utf-8")
# decodedBytes = base64.b64decode(encodedStr).decode("utf-8")

# print(encodedStr)
# print(decodedBytes)
# Bài 3. Viết chương trình mã hóa và giải mã của hệ mã XOR (text, key):
# def repeated_key_xor(plain_text, key):
    
#     # returns plain text by repeatedly xoring it with key
#     pt = plain_text
#     len_key = len(key)
#     encoded = []
      
#     for i in range(0, len(pt)):
#         encoded.append( pt[i] ^ key[i % len_key] )
#     return bytes(encoded)
  
# # Driver Code
# def main():
#     # plain_text = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
#     # key = b'ICE'
#     plain_text = b'GOOD'
#     key = b'ABC'
      
#     print("Plain text: ", plain_text)
#     print("Encrypted as: ", repeated_key_xor(plain_text, key).hex())
  
# if __name__ == '__main__':
#     main()
# Program khác
from itertools import cycle
import base64

def xor_encrypt_string(data, key):
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data,
    cycle(key)))
    xored = xored.encode('ascii')

    xored = base64.encodebytes(xored).strip()
    return xored

def xor_decrypt_string(data, key):
    data = base64.decodebytes(data)
    data = data.decode('ascii')
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data,
    cycle(key)))
    return xored

# key = 'cipher'
# secret_data = "GoodLife"
# c = xor_encrypt_string(secret_data, key)
# print("The cipher text is")
# print (c)
# print("The plain text fetched")
# print (xor_decrypt_string(c,key))

# Bài 4. Viết chương trình mã hóa và giải mã cho hệ mã nhân
def mod_inverse(x,m):
    for n in range(m):
        if (int(x) * n) % m == 1:
            return n
            break
        elif n == m - 1:
            return st.warning("NULL")
        else:
            continue

def encryptChar(char, K1):
    return chr((int(K1) * (ord(char)-65) ) % 26 + 65)

def encryptNhan(string, KEY):
    return "".join(encryptChar(c,KEY) for c in string)

def decryptChar(char, KI):
    return chr(int(KI) * ((ord(char)-65) ) % 26 + 65)

def decryptNhan(string, KEY):
    KI = mod_inverse (KEY,26)
    return "".join(decryptChar(c,KI) for c in string)
    
# p = 'ONAUGUST'
# KEY = 7
# c = encryptNhan(p,KEY)
# print (c)
# print(decryptNhan(c,KEY))
# Bài 5. Sử dụng hàm Fernet trong thư viện cryptography, viết chương trình mã hóa và giải
# mã một chuỗi ký tự.
# from cryptography.fernet import Fernet
 
# message = "hello geeks"
# key = Fernet.generate_key()
# fernet = Fernet(key)
# encMessage = fernet.encrypt(message.encode())
 
# print("original string: ", message)
# print("encrypted string: ", encMessage)

# decMessage = fernet.decrypt(encMessage).decode()
 
# print("decrypted string: ", decMessage)


# Bài 6: Viết chương trình thám mã hệ mã Caesar
# message = 'GIEWIVrGMTLIVrHIQS' #encrypted message
# LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
# for key in range(len(LETTERS)):
#     translated = ''
#     for symbol in message:

#         if symbol in LETTERS:
#             num = LETTERS.find(symbol)
#             num = num - key
#             if num < 0:
#                 num = num + len(LETTERS)
#             translated = translated + LETTERS[num]
#         else:
#             translated = translated + symbol
# print('Hacking key #%s: %s' % (key, translated))

# Đổi Thập lục sang Nhị phân
def hex2bin(s):
    mp = {'0' : "0000",
        '1' : "0001",
        '2' : "0010",
        '3' : "0011",
        '4' : "0100",
        '5' : "0101",
        '6' : "0110",
        '7' : "0111",
        '8' : "1000",
        '9' : "1001",
        'A' : "1010",
        'B' : "1011",
        'C' : "1100",
        'D' : "1101",
        'E' : "1110",
        'F' : "1111" }
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin
# Đổi Nhị phân sang Thập lục
def bin2hex(s):
    mp = {"0000" : '0',
        "0001" : '1',
        "0010" : '2',
        "0011" : '3',
        "0100" : '4',

        "0101" : '5',
        "0110" : '6',
        "0111" : '7',
        "1000" : '8',
        "1001" : '9',
        "1010" : 'A',
        "1011" : 'B',
        "1100" : 'C',
        "1101" : 'D',
        "1110" : 'E',
        "1111" : 'F' }
    hex = ""
    for i in range(0,len(s),4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i + 1]
        ch = ch + s[i + 2]
        ch = ch + s[i + 3]
        hex = hex + mp[ch]
    return hex
# Đổi Nhị phân sang Thập phân
def bin2dec(binary):
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal
# Đổi Thập phân sang Nhị phân
def dec2bin(num):
    res = bin(num).replace("0b", "")
    if(len(res)%4 != 0):
        div = len(res) / 4
        div = int(div)
        counter =(4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res
# Hàm hoán vị
def permute(k, arr, n):
    permutation = ""
    for i in range(0, n):
        permutation = permutation + k[arr[i] - 1]
    return permutation

# Hàm dịch vòng trái
def shift_left(k, nth_shifts):
    s = ""

    for i in range(nth_shifts):
        for j in range(1,len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k

# Tính xor hai chuỗi nhị phân số a và b
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

# Bảng hoán vị đầu IP
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]
# Hàm mở rộng Expansion
exp_d = [32, 1 , 2 , 3 , 4 , 5 , 4 , 5,
        6 , 7 , 8 , 9 , 8 , 9 , 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1 ]

# Hoán vị P (của hàm Feistel)
per = [ 16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25 ]

# Bảng S-box
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],

        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ]],
        [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ]],
        [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14] ],
        [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ]],
        [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ],
        [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ],
        [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11] ] ]

# Bảng hoán vị cuối FP
final_perm = [ 40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25 ]

# def encryptDES(pt, rkb, rk):
#     pt = hex2bin(pt)

#     # # Hoán vị đầu
#     pt = permute(pt, initial_perm, 64)
#     print("Sau khi hoán vị ban đầu", bin2hex(pt))
#     # Phân chia thành nửa trái và nửa phải
#     left = pt[0:32]
#     right = pt[32:64]
#     for i in range(0, 16):
#         # Nửa phải qua hàm mở rộng (32 thành 48)
#         right_expanded = permute(right, exp_d, 48)

#         # XOR RoundKey[i] và right_expanded
#         xor_x = xor(right_expanded, rkb[i])
#         # Qua S-boxex
#         sbox_str = ""
#         for j in range(0, 8):
#             row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
#             col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] +
#             xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
#             val = sbox[j][row][col]
#             sbox_str = sbox_str + dec2bin(val)

#         # Hoán vị P
#         sbox_str = permute(sbox_str, per, 32)

#         # XOR left và sbox_str
#         result = xor(left, sbox_str)
#         left = result

#         # Đỗi chỗ (vòng lặp cuối)
#         if(i != 15):
#             left, right = right, left
#             print("Round ", i + 1, " ", bin2hex(left), " ",
#             bin2hex(right), " ", rk[i])

#     # Kết hợp nửa trái và nửa phải lại
#     combine = left + right
#     # Hoán vị cuối FP
#     cipher_text = permute(combine, final_perm, 64)
#     return cipher_text

pt = "0123456789ABCDEF"
key = "133457799BBCDFF0"
# pt = "0193245876ADBCEF"
# key = "1834475620ACFEDA"

# Sinh khóa
key = hex2bin(key)

# Bảng PC1
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4 ]

# Qua bảng PC1 lấy 56 bit từ 64 bit của khóa
key = permute(key, keyp, 56)

# Số lượng bit dịch vòng
shift_table = [1, 1, 2, 2,
                2, 2, 2, 2,

                1, 2, 2, 2,
                2, 2, 2, 1 ]

# Bảng PC2: Nén 56 bit thành 48 bit
key_comp = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32 ]

# Phân chia khóa thành nửa trái nửa phải
# left = key[0:28] # rkb for RoundKeys in binary
# right = key[28:56] # rk for RoundKeys in hexadecimal

# rkb = []
# rk = []

# for i in range(0, 16):
#     # Dịch vòng trái theo số lượng bit của vòng
#     left = shift_left(left, shift_table[i])
#     right = shift_left(right, shift_table[i])

#     # Kết hợp nủa trái và phải
#     combine_str = left + right

#     # Qua PC2: Nén 56 bit thành 48 bit
#     round_key = permute(combine_str, key_comp, 48)
#     rkb.append(round_key)
#     rk.append(bin2hex(round_key))

# print("Encryption")
# cipher_text = bin2hex(encryptDES(pt, rkb, rk))
# print("Cipher Text : ",cipher_text)

# print("Decryption")
# rkb_rev = rkb[::-1]
# rk_rev = rk[::-1]
# text = bin2hex(encryptDES(cipher_text, rkb_rev, rk_rev))
# print("Plain Text : ",text)

# import random
from math import pow

a=random.randint(2,10)

#To fing gcd of two numbers
def gcd(a,b):
    if a<b:
        return gcd(b,a)
    elif a%b==0:
        return b
    else:
        return gcd(b,a%b)

#For key generation i.e. large random number
def gen_key(q):
    key= random.randint(pow(10,20),q)
    while gcd(q,key)!=1:
        key=random.randint(pow(10,20),q)
    return key

def power(a,b,c):
    x=1
    y=a
    while b>0:
        if b%2==0:
            x=(x*y)%c;
        y=(y*y)%c
        b=int(b/2)
    return x%c

#For asymetric encryption
def encryption(msg,q,h,g):
    ct=[]
    k=gen_key(q)
    s=power(h,k,q)
    p=power(g,k,q)
    for i in range(0,len(msg)):
        ct.append(msg[i])
    print("g^k used= ",p)
    print("g^ak used= ",s)
    for i in range(0,len(ct)):
        ct[i]=s*ord(ct[i])
    return ct,p

#For decryption
def decryption(ct,p,key,q):
    pt=[]
    h=power(p,key,q)
    for i in range(0,len(ct)):
        pt.append(chr(int(ct[i]/h)))
    return pt



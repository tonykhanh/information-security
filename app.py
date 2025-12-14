from email import message
from os import sep
from numpy import size
from django.shortcuts import redirect
import streamlit as st
import code as cd
from code import permute,hex2bin,bin2hex,initial_perm,keyp,shift_left,key_comp,shift_table,xor,exp_d,bin2dec,dec2bin,per,sbox,final_perm
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from base64 import b64encode
import sys
from elgamal.elgamal import Elgamal

st.set_page_config(
    page_title="An toàn bảo mật Thông Tin", 
    page_icon=":shark:",
    layout="centered", 
    initial_sidebar_state="auto", 
    menu_items=None
)

st.header('Hệ mã cổ điển và hệ mã công khai')
choices = ["Vui lòng chọn hệ mã", "Mã đảo ngược", "Mã Caesar","Mã đổi chỗ","Mã thay thế đơn","Mã Affine","Mã Vigenere","Mã Hill","Base64","Hệ mã XOR","Mã nhân","Fernet chuỗi ký tự","Thám mã Ceasar","Mã DES","Mã RSA","Mã Elgamal"]
choice = st.selectbox("", choices, 0)


if choice == "Mã đảo ngược":
    message = st.text_input("Nhập vào mã muốn được mã hóa:")
    st.caption('VD: This is program to explain reverse cipher.')
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        # Mã hóa mã đảo ngược
        translated = cd.encrypt (message)
        st.markdown('**Kết quả đã được encrypt:**')
        st.text(translated)
        # Giải mã mã đảo ngược
        decrypted = cd.decrypt (translated)
        st.markdown('**Trả về kết quả decrypted:**')
        st.text(decrypted)
elif choice == "Mã Caesar":
    message = st.text_input("Nhập vào mã muốn được mã hóa:")  
    st.caption("VD: CEasER CIPHER DEMO và k = 4 hoặc 13")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        buff, col, buff2 = st.columns([1,3,4])
        k = col.text_input('Nhập k:')
        if k == "":
            st.warning('Vui lòng nhập k !!!')
        else:
            # Mã hóa mã Caesar
            translated = cd.encryptCaesar(message,int(k))
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(translated)
            # Giải mã mã Caesar
            decrypted = cd.decryptCaesar(translated,int(k))
            st.markdown('**Trả về kết quả decrypted:**')
            st.text(decrypted)
elif choice == "Mã đổi chỗ":
    message = st.text_input("Nhập vào mã muốn được mã hóa:")
    st.caption("VD: HELLOWORLDLOVES và k = 12345")  
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        buff, col, buff2 = st.columns([1,3,4])
        k = col.text_input('Nhập k:')
        if k == "":
            st.warning('Vui lòng nhập k !!!')
        else:
            # a = message.replace(" ","")
            # Mã hóa mã đổi chỗ
            translated = cd.encryptDc(message,k)
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(translated)
            # Giải mã mã đổi chỗ
            decrypted = cd.decryptDc(translated,k)
            st.markdown('**Trả về kết quả decrypted:**')
            st.text(decrypted)
elif choice == "Mã thay thế đơn":
    message = st.text_input("Nhập vào mã muốn được mã hóa:")
    st.caption("VD: defend the east wall of the castle và key = random ")
    st.caption("26 key APHABET: ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        buff, col, buff2 = st.columns([1,3,4])
        key = col.text_input('Nhập key:')  

        if key == "":
            key = cd.getRandomKey()
            # Mã hóa thay thế đơn
            translated = cd.encryptChange(message, key)
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(translated)
            # Giải mã thay thế đơn
            decrypted = cd.decryptChange(translated,key)
            st.markdown('**Trả về kết quả decrypted:**')
            st.text(decrypted)     
        elif len(key) < len(cd.LETTERS):
            st.warning('Vui lòng nhập đủ 26 khóa ALPHA !!!')
        else:
            # Mã hóa thay thế đơn
            translated = cd.encryptChange(message, key)
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(translated)
            # Giải mã thay thế đơn
            decrypted = cd.decryptChange(translated,key)
            st.markdown('**Trả về kết quả decrypted:**')
            st.text(decrypted)
elif choice == "Mã Affine":
    message = st.text_input("Nhập vào mã muốn được mã hóa:")
    st.caption("VD: ONAUGUST")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        buff, col, buff2 = st.columns([1,3,4])
        a = col.text_input('Nhập key a:')
        b = col.text_input('Nhập key b:') 
        if a == "":
            st.warning('Vui lòng nhập khóa a !!!')
        elif b == "":
            st.warning('Vui lòng nhập khóa b !!!')
        else:
            def mod_inverse(x,m):
                for n in range(m):
                    if (x * n) % m == 1:
                        return n
                        break
                    elif n == m - 1:
                        return "Null"
                    else:
                        continue

            class Affine(object):
                DIE = 26
                KEY = (int(a), int(b), mod_inverse(int(a),26))
                def __init__(self):
                    pass
                def encryptChar(self, char):
                    K1, K2, kI = self.KEY
                    return chr((K1 * (ord(char)-65) + K2) % self.DIE + 65)
                
                def encrypt(self, string):
                    return "".join(map(self.encryptChar, string))

                def decryptChar(self, char):
                    K1, K2, KI = self.KEY
                    return chr(KI * ((ord(char)-65) - K2) % self.DIE + 65)

                def decrypt(self, string):
                    return "".join(map(self.decryptChar, string))
                
            affine = Affine()
            # Mã hóa Affine
            translated = affine.encrypt(message)
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(translated)
            # Giải mã Affine
            decrypted = affine.decrypt(translated)
            st.markdown('**Trả về kết quả decrypted:**')
            st.text(decrypted)
elif choice == "Mã Vigenere":
    message = st.text_input("Nhập vào mã muốn được mã hóa:")
    st.caption("VD: THISCRYPTOSYSTEMISNOTSECURE và key: CIPHER ")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        buff, col, buff2 = st.columns([1,3,4])
        key = col.text_input('Nhập k:')
        if key == "":
            st.warning('Vui lòng nhập khóa !!!')
        else:
            # Mã hóa mã Vigenere
            translated = cd.encryptVigenere(message, key)
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(translated)    
            # Giải mã mã Vigenere 
            decrypted = cd.decryptVigenere(translated,key)
            st.markdown('**Trả về kết quả decrypted:**')
            st.text(decrypted)
elif choice == "Mã Hill":
    message = st.text_input("Nhập vào mã muốn được mã hóa:")
    st.caption("VD: HELP và key: D C D F ")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        buff, col, buff2 = st.columns([1,3,4])
        key = col.text_input('Nhập k:')
        if key == "":
            st.warning('Vui lòng nhập khóa !!!')
        else:
            k = cd.make_key(key)
            # Mã hóa mã Hill
            encrypted_msg = cd.encryptHill(message,k)
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(encrypted_msg)  
            # Giải mã mã Hill
            decrypted_msg = cd.decryptHill(encrypted_msg,k)
            st.markdown('**Trả về kết quả decrypted:**')
            st.text(decrypted_msg)
elif choice == "Base64":
    message = st.text_input("Nhập vào mã muốn được mã hóa:")
    st.caption("VD: rav ")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        encodedBytes = cd.base64.b64encode(message.encode("utf-8"))
        encodedStr = str(encodedBytes, "utf-8")
        decodedBytes = cd.base64.b64decode(encodedStr).decode("utf-8")
        st.markdown('**Kết quả đã được encrypt:**')
        st.text(encodedStr)
        st.markdown('**Trả về kết quả decrypted:**')
        st.text(decodedBytes)
elif choice == 'Hệ mã XOR':
    message = st.text_input("Nhập vào mã muốn được mã hóa: ")
    st.caption("VD: GoodLife && key = cipher ")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        buff, col, buff2 = st.columns([1,3,4])
        k = col.text_input('Nhập k:')
        if k == "":
            st.warning('Vui lòng nhập khóa !!!')
        else:
            c = cd.xor_encrypt_string(message, k)
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(c)
            st.markdown('**Trả về kết quả decrypted:**')
            d = cd.xor_decrypt_string(c,k)
            st.text(d)
elif choice == "Mã nhân":
    message = st.text_input("Nhập vào mã muốn được mã hóa: ")
    st.caption("VD: ONAUGUST && key = 7 ")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        a = message.replace(" ","")
        buff, col, buff2 = st.columns([1,3,4])
        k = col.text_input('Nhập k:')
        if k == "":
            st.warning('Vui lòng nhập khóa !!!')
        else:
            e = cd.encryptNhan(a,k)
            st.markdown('**Kết quả đã được encrypt:**')
            st.text(e)
            st.markdown('**Trả về kết quả decrypted:**')
            d = cd.decryptNhan(e,k)
            st.text(d)
elif choice == "Fernet chuỗi ký tự":
    message = st.text_input("Nhập vào mã muốn được mã hóa: ")
    st.caption("VD: hello geeks ")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encMessage = fernet.encrypt(message.encode())
        decMessage = fernet.decrypt(encMessage).decode()
        st.markdown('**Chuỗi gốc:**')
        st.text(message)
        st.markdown('**Kết quả đã được encrypt:**')
        st.text(encMessage)
        st.markdown('**Trả về kết quả decrypted:**')
        st.text(decMessage)
elif choice == "Thám mã Ceasar":
    message = st.text_input("Nhập vào mã muốn được mã hóa: ")
    st.caption("VD: GIEWIVrGMTLIVrHIQS -- #encrypted message ")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        for key in range(len(LETTERS)):
            translated = ''
            for symbol in message:

                if symbol in LETTERS:
                    num = LETTERS.find(symbol)
                    num = num - key
                    if num < 0:
                        num = num + len(LETTERS)
                    translated = translated + LETTERS[num]
                else:
                    translated = translated + symbol
        st.text('Hacking key #%s: %s' % (key, translated))
elif choice == "Mã DES":
    message = st.text_input("Nhập vào mã muốn được mã hóa: ")
    st.caption("VD: pt = '0123456789ABCDEF' && key = '133457799BBCDFF0'")
    if message == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        buff, col, buff2 = st.columns([1,3,4])
        key = col.text_input('Nhập key:')
        if key == "":
            st.warning('Vui lòng nhập khóa !!!')
        elif len(key) < len(message):
            st.warning('Vui lòng nhập lại khóa')
        else:
            pt = hex2bin(message)
            pt = permute(pt, initial_perm, 64)
            key = hex2bin(key)
            key = permute(key, keyp, 56)
            # Phân chia khóa thành nửa trái nửa phải
            left = key[0:28] # rkb for RoundKeys in binary
            right = key[28:56] # rk for RoundKeys in hexadecimal

            rkb = []
            rk = []

            for i in range(0, 16):
                # Dịch vòng trái theo số lượng bit của vòng
                left = shift_left(left, shift_table[i])
                right = shift_left(right, shift_table[i])

                # Kết hợp nủa trái và phải
                combine_str = left + right

                # Qua PC2: Nén 56 bit thành 48 bit
                round_key = permute(combine_str, key_comp, 48)
                rkb.append(round_key)
                rk.append(bin2hex(round_key))

            st.subheader('Encryption')
            st.write('**Sau khi hoán vị ban đầu:** ',bin2hex(pt))
            
            def encryptDES(pt, rkb, rk):
                left = pt[0:32]
                right = pt[32:64]
                for i in range(0, 16):
                    # Nửa phải qua hàm mở rộng (32 thành 48)
                    right_expanded = permute(right, exp_d, 48)

                    # XOR RoundKey[i] và right_expanded
                    xor_x = xor(right_expanded, rkb[i])
                    # Qua S-boxex
                    sbox_str = ""
                    for j in range(0, 8):
                        row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
                        col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] +
                        xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
                        val = sbox[int(j)][int(row)][int(col)]
                        sbox_str = sbox_str + dec2bin(val)

                    # Hoán vị P
                    sbox_str = permute(sbox_str, per, 32)

                    # XOR left và sbox_str
                    result = xor(left, sbox_str)
                    left = result

                    # Đỗi chỗ (vòng lặp cuối)
                    if(i != 15):
                        left, right = right, left
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.write("Round ", i+1)
                        with col2:
                            st.write(" ", bin2hex(left))
                        with col3:
                            st.write(" ", bin2hex(right))
                        with col4:
                            st.write(" ", rk[i])
                # Kết hợp nửa trái và nửa phải lại
                combine = left + right
                # Hoán vị cuối FP
                cipher_text = permute(combine, final_perm, 64)
                return cipher_text
                
            cipher_text = bin2hex(encryptDES(pt, rkb, rk))
            st.write('**Cipher text:** ',cipher_text)
            st.subheader('Decryption')
            rkb_rev = rkb[::-1]
            rk_rev = rk[::-1]
            pt1 = hex2bin(cipher_text)
            pt1 = permute(pt1, initial_perm, 64)
            st.write('**Sau khi hoán vị ban đầu:** ',bin2hex(pt1))
            text = bin2hex(encryptDES(pt1, rkb_rev, rk_rev))
            st.write('**Plain Text :** ',text)
elif choice == "Mã RSA":
    keyPair = RSA.generate(2048)
    pubKey = keyPair.publickey()
    # st.text(f"Public key:(n={hex(pubKey.n)}, e={hex(pubKey.e)})")
    pubKeyPEM = pubKey.exportKey()
    # st.text(pubKeyPEM.decode('ascii'))
    # st.text(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
    privKeyPEM = keyPair.exportKey()
    # st.text(privKeyPEM.decode('ascii'))

    msg = bytes(str(st.text_input("Nhập plain text: ")), 'utf-8')
    if msg == "":
        st.warning("Vui lòng nhập message")
    else:
        encryptor = PKCS1_OAEP.new(pubKey)
        encrypted = encryptor.encrypt(msg)
        st.write("Encrypted:", binascii.hexlify(encrypted))
        decryptor = PKCS1_OAEP.new(keyPair)
        decrypted = decryptor.decrypt(encrypted)
        st.write('Decrypted:', decrypted.decode('utf-8'))

        msg = st.text_input("Message:")
        if (len(sys.argv)>1):
            msg=str(sys.argv[1])

        key = RSA.generate(1024)

        binPrivKey = key.exportKey('PEM')
        binPubKey = key.publickey().exportKey('PEM') 
        # st.subheader ("====================Private key====================")

        # st.text (binPrivKey)
        # st.subheader ("====================Public key=====================")
        # st.text (binPubKey)
        privKeyObj = RSA.importKey(binPrivKey)
        pubKeyObj = RSA.importKey(binPubKey)
        cipher = PKCS1_OAEP.new(pubKeyObj)
        ciphertext = cipher.encrypt(msg.encode())
        st.subheader ("====================Ciphertext=====================")
        st.write (b64encode(ciphertext))
        cipher = PKCS1_OAEP.new(privKeyObj)
        message = cipher.decrypt(ciphertext)
        st.subheader ("====================Decrypted======================")
        st.write ("Message:",message)
elif choice == "Mã Elgamal":
    msg=st.text_input("Nhập message: ")
    if msg == "":
        st.warning('Vui lòng nhập thông tin cần thiết !!!')
    else:
        q=cd.random.randint(pow(10,20),pow(10,50))
        g=cd.random.randint(2,q)
        key=cd.gen_key(q)
        h=cd.power(g,key,q)
        st.write("g used=",g)
        st.write("g^a used=",h)
        ct,p=cd.encryption(msg,q,h,g)
        st.write("Original Message =",msg)
        st.write("Encrypted Maessage =",ct)
        pt=cd.decryption(ct,p,key,q)
        d_msg=''.join(pt)
        st.write("Decryted Message=",d_msg)

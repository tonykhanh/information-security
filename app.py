import streamlit as st
import code as cd
# Imports from code.py needed for local helpers (DES)
from code import permute, hex2bin, bin2hex, initial_perm, keyp, shift_left, key_comp, shift_table, xor, exp_d, bin2dec, dec2bin, per, sbox, final_perm
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from base64 import b64encode
import sys

# ==============================================================================
# CONFIG & STYLING
# ==============================================================================
# ==============================================================================
# CONFIG & STYLING
# ==============================================================================
st.set_page_config(
    page_title="Information Security - Cipher Collection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==============================================================================
# HELPER CLASSES & FUNCTIONS
# ==============================================================================

def mod_inverse_helper(x, m):
    """Calculates modular inverse."""
    for n in range(m):
        if (x * n) % m == 1:
            return n
    return None

class AffineHelper:
    DIE = 26
    def __init__(self, a, b):
        self.KEY = (int(a), int(b), mod_inverse_helper(int(a), 26))

    def encryptChar(self, char):
        K1, K2, kI = self.KEY
        if kI is None: return char # Handle case where inverse doesn't exist
        if not char.isalpha(): return char
        base = 65 if char.isupper() else 97
        return chr((K1 * (ord(char.upper()) - 65) + K2) % self.DIE + base)

    def encrypt(self, string):
        return "".join(map(self.encryptChar, string))

    def decryptChar(self, char):
        K1, K2, KI = self.KEY
        if KI is None or KI == "Null": return char # Safety check
        if not char.isalpha(): return char
        base = 65 if char.isupper() else 97
        val = KI * ((ord(char.upper()) - 65) - K2) % self.DIE
        return chr(val + base)

    def decrypt(self, string):
        return "".join(map(self.decryptChar, string))

def run_des_encryption(pt_hex, key_hex):
    """Helper to run DES encryption logic."""
    try:
        pt = hex2bin(pt_hex)
        pt = permute(pt, initial_perm, 64)
        key = hex2bin(key_hex)
        key = permute(key, keyp, 56)
        left = key[0:28]
        right = key[28:56]
        rkb = []
        rk = []
        
        for i in range(0, 16):
            left = shift_left(left, shift_table[i])
            right = shift_left(right, shift_table[i])
            combine_str = left + right
            round_key = permute(combine_str, key_comp, 48)
            rkb.append(round_key)
            rk.append(bin2hex(round_key))
            
        def encryptDES_core(pt, rkb):
            left = pt[0:32]
            right = pt[32:64]
            for i in range(0, 16):
                right_expanded = permute(right, exp_d, 48)
                xor_x = xor(right_expanded, rkb[i])
                sbox_str = ""
                for j in range(0, 8):
                    row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
                    col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
                    val = sbox[int(j)][int(row)][int(col)]
                    sbox_str = sbox_str + dec2bin(val)
                sbox_str = permute(sbox_str, per, 32)
                result = xor(left, sbox_str)
                left = result
                if(i != 15):
                    left, right = right, left
            combine = left + right
            return permute(combine, final_perm, 64)

        cipher_text_bin = encryptDES_core(pt, rkb)
        return bin2hex(cipher_text_bin), rkb, rk
    except Exception as e:
        return None, None, str(e)

def run_des_decryption(cipher_hex, rkb, rk):
    """Helper for DES decryption."""
    try:
        rkb_rev = rkb[::-1]
        rk_rev = rk[::-1] # Not strictly needed for logic but kept for consistency
        pt1 = hex2bin(cipher_hex)
        pt1 = permute(pt1, initial_perm, 64)
        
        # Re-use core logic? 
        # For simplicity, duplicating core loop logic inverse or implementing inverse calling is better. 
        # But app.py previously re-implemented it inline. Let's adapt logic.
        
        def encryptDES_core(pt, rkb_keys):
            left = pt[0:32]
            right = pt[32:64]
            for i in range(0, 16):
                right_expanded = permute(right, exp_d, 48)
                xor_x = xor(right_expanded, rkb_keys[i])
                sbox_str = ""
                for j in range(0, 8):
                    row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
                    col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
                    val = sbox[int(j)][int(row)][int(col)]
                    sbox_str = sbox_str + dec2bin(val)
                sbox_str = permute(sbox_str, per, 32)
                result = xor(left, sbox_str)
                left = result
                if(i != 15):
                    left, right = right, left
            combine = left + right
            return permute(combine, final_perm, 64)

        decrypted_bin = encryptDES_core(pt1, rkb_rev)
        return bin2hex(decrypted_bin)
    except Exception as e:
        return str(e)

# ==============================================================================
# PAGE RENDERERS
# ==============================================================================

def render_home():
    st.markdown("## 👋 Welcome to the Cipher Collection")
    st.markdown("""
    This application demonstrates various classical and modern cryptographic algorithms.
    
    👈 **Select a cipher from the sidebar** to get started.
    
    ### Available Categories:
    - **Classical**: Reverse, Caesar, Vigenere, Atbash (Substitute), etc.
    - **Modern**: DES, RSA, Elgamal, Fernet.
    - **Encoding**: Base64.
    """)
    st.image("https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5", caption="Information Security", use_container_width=True)

def render_reverse_cipher():
    st.header("🔄 Reverse Cipher (Mã Đảo Ngược)")
    st.info("The Reverse Cipher simply reverses the string. It is not secure but demonstrates simple obfuscation.")
    
    message = st.text_input("📝 Input Message")
    if message:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔒 Encrypt"):
                translated = cd.encrypt(message)
                st.session_state.reverse_enc = translated
        with col2:
            if st.button("🔓 Decrypt"):
                if 'reverse_enc' in st.session_state:
                    decrypted = cd.decrypt(st.session_state.reverse_enc)
                    st.session_state.reverse_dec = decrypted
                else:
                    st.warning("Encrypt something first!")

        if 'reverse_enc' in st.session_state:
            st.success(f"**Encrypted:** {st.session_state.reverse_enc}")
        if 'reverse_dec' in st.session_state:
            st.info(f"**Decrypted:** {st.session_state.reverse_dec}")

def render_caesar_cipher():
    st.header("🏛️ Caesar Cipher")
    with st.expander("📖 Theoretical Guide"):
        st.write("""
        The Caesar cipher is a simple substitution cipher that replaces each letter in a text by a letter a fixed number of positions down the alphabet. 
        **Key (k)**: The number of positions to shift.
        """)
    
    col1, col2 = st.columns([3, 1])
    message = col1.text_input("Input Message")
    k = col2.number_input("Shift Key (k)", min_value=1, max_value=25, value=3)
    
    if message:
        if st.button("Runs"):
            enc = cd.encryptCaesar(message, int(k))
            dec = cd.decryptCaesar(enc, int(k))
            
            st.subheader("Results")
            st.success(f"**Encrypted:** {enc}")
            st.info(f"**Decrypted Back:** {dec}")

def render_transposition_cipher(): # Mã đổi chỗ
    st.header("🔀 Transposition Cipher (Mã Đổi Chỗ)")
    st.info("Rearranges the characters of the plaintext according to a regular system.")
    
    message = st.text_input("Input Message", "HELLOWORLD")
    key = st.text_input("Numeric Key", "12345")
    
    if message and key:
        if st.button("Process"):
            try:
                enc = cd.encryptDc(message, key)
                dec = cd.decryptDc(enc, key)
                st.success(f"**Encrypted:** {enc}")
                st.info(f"**Decrypted:** {dec}")
            except Exception as e:
                st.error(f"Error: {e}")

def render_substitution_cipher(): # Mã thay thế đơn
    st.header("🔠 Simple Substitution Cipher")
    st.caption("Replaces each letter with another specific letter.")
    
    message = st.text_input("Input Message")
    key = st.text_input("Key (26 unique chars) - Leave empty for random", "")
    
    if st.button("Encrypt & Decrypt"):
        if not message:
            st.warning("Please enter a message.")
            return
            
        if not key:
            key = cd.getRandomKey()
            st.warning(f"Using Generated Key: {key}")
        
        if len(set(key)) != 26 or len(key) != 26:
             st.error("Key must be exactly 26 unique characters.")
        else:
            enc = cd.encryptChange(message, key)
            dec = cd.decryptChange(enc, key)
            st.success(f"**Ciphertext:** {enc}")
            st.info(f"**Plaintext:** {dec}")

def render_affine_cipher():
    st.header("✖️ Affine Cipher")
    with st.expander("Theory"):
        st.write("Affine cipher combines multiplication and addition: E(x) = (ax + b) mod 26.")
    
    message = st.text_input("Message")
    c1, c2 = st.columns(2)
    a = c1.number_input("Key a (must be coprime to 26)", 1, 25, 5)
    b = c2.number_input("Key b", 0, 25, 8)
    
    if st.button("Run Affine"):
        if not message:
            st.error("Input message required.")
            return
            
        if mod_inverse_helper(a, 26) is None:
            st.error(f"Error: 'a={a}' is not invertible modulo 26. Pick another 'a' (e.g. 1, 3, 5, 7, 9, 11...).")
        else:
            affine = AffineHelper(a, b)
            enc = affine.encrypt(message)
            dec = affine.decrypt(enc)
            st.success(f"**Encrypted:** {enc}")
            st.info(f"**Decrypted:** {dec}")

def render_vigenere_cipher():
    st.header("📜 Vigenère Cipher")
    st.caption("A polyalphabetic substitution using a keyword.")
    
    message = st.text_input("Message")
    key = st.text_input("Keyword", "CIPHER")
    
    if st.button("Run Vigenère") and message and key:
        enc = cd.encryptVigenere(message, key)
        dec = cd.decryptVigenere(enc, key)
        st.success(f"**Encrypted:** {enc}")
        st.info(f"**Decrypted:** {dec}")

def render_hill_cipher():
    st.header("⛰️ Hill Cipher")
    st.caption("Polygraphic substitution cipher based on linear algebra.")
    
    message = st.text_input("Message")
    key_str = st.text_input("Key String (e.g., 'DCDF' for 2x2 matrix)", "DCDF")
    
    if st.button("Run Hill") and message and key_str:
        try:
            k_matrix = cd.make_key(key_str)
            enc = cd.encryptHill(message, k_matrix)
            dec = cd.decryptHill(enc, k_matrix)
            st.success(f"**Encrypted:** {enc}")
            st.info(f"**Decrypted:** {dec}")
        except Exception as e:
            st.error(f"Error (Check key length vs message length/padding): {e}")

def render_base64():
    st.header("🧬 Base64 Encoding")
    message = st.text_input("Text to Encode")
    if  st.button("Encode/Decode") and message:
        encoded_bytes = cd.base64.b64encode(message.encode("utf-8"))
        encoded_str = str(encoded_bytes, "utf-8")
        decoded_bytes = cd.base64.b64decode(encoded_str).decode("utf-8")
        
        st.code(encoded_str, language="text")
        st.caption("Decoded back verify: " + decoded_bytes)

def render_xor_cipher():
    st.header("⊕ XOR Cipher")
    st.info("Simple encryption using bitwise XOR.")
    message = st.text_input("Message")
    key = st.text_input("Key")
    
    if st.button("Run XOR") and message and key:
        enc = cd.xor_encrypt_string(message, key)
        dec = cd.xor_decrypt_string(enc, key)
        st.success(f"**Encrypted (Hex):** {enc}")
        st.info(f"**Decrypted:** {dec}")

def render_multiplication_cipher(): # Mã nhân
    st.header("✖ Multiplication Cipher (Mã Nhân)")
    message = st.text_input("Message")
    key = st.number_input("Key", 1, 100, 7)
    
    if st.button("Execute") and message:
        # Note: encryptNhan expects string key in original, let's cast
        enc = cd.encryptNhan(message.replace(" ",""), str(key))
        dec = cd.decryptNhan(enc, str(key))
        st.success(f"Encrypted: {enc}")
        st.info(f"Decrypted: {dec}")

def render_fernet():
    st.header("🔑 Fernet (Symmetric Encryption)")
    st.caption("Secure implementation using cryptography library.")
    message = st.text_input("Message to encrypt")
    if st.button("Generate Key & Encrypt") and message:
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(message.encode())
        d_msg = f.decrypt(token).decode()
        
        st.subheader("Key")
        st.code(key.decode())
        st.subheader("Token")
        st.code(token.decode())
        st.subheader("Decrypted Verification")
        st.text(d_msg)

def render_caesar_breaker():
    st.header("🔓 Caesar Cipher Breaker (Brute Force)")
    message = st.text_input("Encrypted Message")
    if st.button("Hack It") and message:
        LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        st.write("Trying all 26 keys...")
        for key in range(len(LETTERS)):
            translated = ''
            for symbol in message:
                if symbol.upper() in LETTERS:
                    num = LETTERS.find(symbol.upper())
                    num = num - key
                    if num < 0: num += len(LETTERS)
                    translated += LETTERS[num]
                else:
                    translated += symbol
            st.text(f"Key #{key}: {translated}")

def render_des_cipher():
    st.header("🛡️ DATA ENCRYPTION STANDARD (DES)")
    st.warning("⚠️ For educational purpose. DES is no longer considered secure.")
    
    message = st.text_input("Hex Message (16 chars)", "0123456789ABCDEF")
    key = st.text_input("Hex Key (16 chars)", "133457799BBCDFF0")
    
    if st.button("Run DES"):
        if len(message) != 16 or len(key) != 16:
            st.error("Message and Key must be exactly 16 Hex characters.")
        else:
            enc, rkb, rk = run_des_encryption(message, key)
            if enc:
                st.success(f"**Ciphertext (Hex):** {enc}")
                with st.expander("View Round Keys"):
                    st.write(rk)
                
                dec = run_des_decryption(enc, rkb, rk)
                st.info(f"**Decrypted (Hex):** {dec}")
            else:
                st.error("Encryption failed. Check hex input.")

def render_rsa_cipher():
    st.header("🔐 RSA (Rivest–Shamir–Adleman)")
    
    mode = st.radio("Mode", ["Simple String", "Custom Key Demo"])
    
    if mode == "Simple String":
        msg = st.text_input("Message")
        if st.button("Encrypt/Decrypt"):
            keyPair = RSA.generate(2048)
            pubKey = keyPair.publickey()
            
            encryptor = PKCS1_OAEP.new(pubKey)
            encrypted = encryptor.encrypt(msg.encode())
            
            decryptor = PKCS1_OAEP.new(keyPair)
            decrypted = decryptor.decrypt(encrypted)
            
            st.write("Encrypted (Hex):", binascii.hexlify(encrypted))
            st.write("Decrypted:", decrypted.decode('utf-8'))
            
    else:
        # Custom small key demo
        msg = st.text_input("Message for Custom Key")
        if st.button("Run Custom RSA logic"):
            key = RSA.generate(1024)
            binPrivKey = key.exportKey('PEM')
            binPubKey = key.publickey().exportKey('PEM')
            
            privKeyObj = RSA.importKey(binPrivKey)
            pubKeyObj = RSA.importKey(binPubKey)
            
            cipher = PKCS1_OAEP.new(pubKeyObj)
            ciphertext = cipher.encrypt(msg.encode())
            
            st.subheader("Ciphertext (Base64)")
            st.write(b64encode(ciphertext).decode())
            
            cipher_dec = PKCS1_OAEP.new(privKeyObj)
            text = cipher_dec.decrypt(ciphertext)
            st.subheader("Decrypted")
            st.write(text.decode())

def render_elgamal_cipher():
    st.header("🔑 Elgamal Encryption")
    message = st.text_input("Message")
    
    if st.button("Run Elgamal") and message:
        # Using functions from code.py (cd)
        # Assuming cd has: gen_key(q), power(a,b,c), encryption(msg,q,h,g), decryption(ct,p,key,q)
        try:
            q = cd.random.randint(pow(10,20), pow(10,50)) # Large prime approximation
            g = cd.random.randint(2, q)
            key = cd.gen_key(q)
            h = cd.power(g, key, q)
            
            st.write(f"**Public Key elements:** q={q}, g={g}, h={h}")
            
            ct, p = cd.encryption(message, q, h, g)
            st.success(f"**Encrypted:** {ct}")
            
            pt = cd.decryption(ct, p, key, q)
            d_msg = ''.join(pt)
            st.info(f"**Decrypted:** {d_msg}")
        except Exception as e:
            st.error(f"Elgamal Error: {e}")

# ==============================================================================
# MAIN APP LOGIC
# ==============================================================================

def main():
    st.sidebar.title("MENU")
    
    # Mapping friendly names to functions
    PAGES = {
        "Home / Intro": render_home,
        "Mã Đảo Ngược (Reverse)": render_reverse_cipher,
        "Mã Caesar": render_caesar_cipher,
        "Mã Đổi Chỗ (Transposition)": render_transposition_cipher,
        "Mã Thay Thế Đơn (Substitution)": render_substitution_cipher,
        "Mã Affine": render_affine_cipher,
        "Mã Vigenere": render_vigenere_cipher,
        "Mã Hill": render_hill_cipher,
        "Base64 Encoding": render_base64,
        "Hệ mã XOR": render_xor_cipher,
        "Mã Nhân (Multiplication)": render_multiplication_cipher,
        "Fernet (Symmetric)": render_fernet,
        "Thám Mã Caesar (Brute Force)": render_caesar_breaker,
        "Mã DES": render_des_cipher,
        "Mã RSA": render_rsa_cipher,
        "Mã Elgamal": render_elgamal_cipher
    }
    
    selection = st.sidebar.radio("Choose Algorithm:", list(PAGES.keys()))
    
    st.sidebar.markdown("---")
    st.sidebar.info("Designed for Information Security Course.")
    
    # Execute the selected page function
    page_func = PAGES[selection]
    page_func()

if __name__ == "__main__":
    main()


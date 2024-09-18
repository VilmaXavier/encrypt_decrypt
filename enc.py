import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP, ARC4
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# AES encryption (CBC mode with padding)
def encrypt_aes(message, key):
    key = key.encode('utf-8')
    message = message.encode('utf-8')

    # Ensure the key is 16 bytes (AES-128)
    key = pad(key, 16)

    # Initialize the cipher with CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Initialization vector

    # Encrypt the message with padding
    encrypted_message = cipher.encrypt(pad(message, AES.block_size))

    # Encode as base64 for easy transmission
    encrypted_message_b64 = base64.b64encode(iv + encrypted_message).decode('utf-8')
    return encrypted_message_b64

# AES decryption (CBC mode with padding)
def decrypt_aes(encrypted_message_b64, key):
    key = key.encode('utf-8')
    key = pad(key, 16)

    # Decode the base64 message
    encrypted_message = base64.b64decode(encrypted_message_b64)

    # Extract IV and actual encrypted message
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]

    # Initialize the cipher with CBC mode and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the message with unpadding
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_message.decode('utf-8')

# RC4 encryption
def encrypt_rc4(message, key):
    key = key.encode('utf-8')
    message = message.encode('utf-8')

    # Initialize RC4 cipher
    cipher = ARC4.new(key)

    # Encrypt the message
    encrypted_message = cipher.encrypt(message)

    # Encode as base64 for easy transmission
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
    return encrypted_message_b64

# RC4 decryption
def decrypt_rc4(encrypted_message_b64, key):
    key = key.encode('utf-8')

    # Decode base64 message
    encrypted_message = base64.b64decode(encrypted_message_b64)

    # Initialize RC4 cipher
    cipher = ARC4.new(key)

    # Decrypt the message
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

# RSA encryption (for simplicity in demonstration)
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(message, public_key):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
    return encrypted_message_b64

def decrypt_rsa(encrypted_message_b64, private_key):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    encrypted_message = base64.b64decode(encrypted_message_b64)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

# Streamlit App Layout
def main():
    st.title("AES, Elliptic Curve (RSA Demo), and RC4 Encryption Tool")

    # Sidebar with names displayed vertically
    st.sidebar.title("Team Members")
    st.sidebar.write("1.Aayuti")
    st.sidebar.write("2.Alethea")
    st.sidebar.write("3.Archi")
    st.sidebar.write("4.Isha")
    st.sidebar.write("5.Kirti")
    st.sidebar.write("6.Vilma")

    # Select Encryption Method
    method = st.selectbox("Choose Encryption Method", ["AES", "Elliptic Curve (RSA)", "RC4"])

    if method == "AES":
        st.subheader("AES Encryption")
        message = st.text_input("Enter the message")
        key = st.text_input("Enter a key (16 bytes recommended)", type="password")

        if st.button("Encrypt"):
            if len(key) > 16:
                st.warning("Key must be 16 bytes long or shorter (it will be padded).")
            else:
                encrypted_message = encrypt_aes(message, key)
                st.write("Encrypted Message:", encrypted_message)

        if st.button("Decrypt"):
            encrypted_message = st.text_area("Enter the encrypted message")
            if len(key) > 16:
                st.warning("Key must be 16 bytes long or shorter (it will be padded).")
            else:
                decrypted_message = decrypt_aes(encrypted_message, key)
                st.write("Decrypted Message:", decrypted_message)

    elif method == "Elliptic Curve (RSA)":
        st.subheader("Elliptic Curve (RSA) Encryption")
        message = st.text_input("Enter the message")

        # Generate RSA keys
        if st.button("Generate RSA Keypair"):
            private_key, public_key = generate_rsa_keypair()
            st.session_state['private_key'] = private_key
            st.session_state['public_key'] = public_key
            st.write("Public Key:", public_key.decode('utf-8'))
            st.write("Private Key (Keep this safe):", private_key.decode('utf-8'))

        if 'private_key' in st.session_state and 'public_key' in st.session_state:
            public_key = st.session_state['public_key']
            private_key = st.session_state['private_key']

            if st.button("Encrypt"):
                encrypted_message = encrypt_rsa(message, public_key)
                st.write("Encrypted Message:", encrypted_message)

            if st.button("Decrypt"):
                encrypted_message = st.text_area("Enter the encrypted message")
                decrypted_message = decrypt_rsa(encrypted_message, private_key)
                st.write("Decrypted Message:", decrypted_message)

    elif method == "RC4":
        st.subheader("RC4 Encryption")
        message = st.text_input("Enter the message")
        key = st.text_input("Enter a key (at least 5 bytes)", type="password")

        if st.button("Encrypt"):
            if len(key) < 5:
                st.warning("Key must be at least 5 bytes long.")
            else:
                encrypted_message = encrypt_rc4(message, key)
                st.write("Encrypted Message:", encrypted_message)

        if st.button("Decrypt"):
            encrypted_message = st.text_area("Enter the encrypted message")
            if len(key) < 5:
                st.warning("Key must be at least 5 bytes long.")
            else:
                decrypted_message = decrypt_rc4(encrypted_message, key)
                st.write("Decrypted Message:", decrypted_message)

# Run the Streamlit app
if __name__ == "__main__":
    main()

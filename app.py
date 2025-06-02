import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ------------------- Encryption Setup -------------------

# Persist key & cipher
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.KEY)

cipher = st.session_state.cipher

# ------------------- Session Initialization -------------------

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False

# ------------------- Helper Functions -------------------

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# ------------------- UI -------------------

st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ------------------- Home -------------------
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Encrypt and securely store text using a passkey.")

# ------------------- Store Data -------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language='text')
        else:
            st.error("⚠️ Both fields are required!")

# ------------------- Retrieve Data -------------------
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    if st.session_state.failed_attempts >= 3 and not st.session_state.is_logged_in:
        st.warning("🔒 Too many failed attempts! Please log in again.")
        st.stop()

    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.is_logged_in = False
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

# ------------------- Login -------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.is_logged_in = True
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized! Redirecting to Retrieve...")
            st.rerun()
        else:
            st.error("❌ Incorrect password!")

import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCK_DURATION = 60


if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lock_timeout" not in st.session_state:
    st.session_state.lock_timeout = 0

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def generate_key(passkey):
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key[:32])

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    try:
        fernet = Fernet(generate_key(key))
        return fernet.encrypt(text.encode()).decode()
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")
        return None

def decrypt_text(encrypted_text, key):
    try:
        fernet = Fernet(generate_key(key))
        return fernet.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# Load data at startup
stored_data = load_data()

# UI Setup
st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒")

st.title("🔒 Secure Data Encryption System")
st.sidebar.title("Navigation")

menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.subheader("Welcome to the Secure Data Encryption System")
    st.markdown("""
    This application allows you to:
    - Register a secure account
    - Store encrypted data
    - Retrieve your data with your secret key
    """)
    
    if st.session_state.authenticated_user:
        st.success(f"Currently logged in as: {st.session_state.authenticated_user}")

elif choice == "Register":
    st.subheader("Create a New Account")
    with st.form("register_form"):
        username = st.text_input("Username", help="Choose a unique username")
        password = st.text_input("Password", type="password", help="Create a strong password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        if st.form_submit_button("Register"):
            if not username or not password:
                st.error("Username and password are required")
            elif password != confirm_password:
                st.error("Passwords do not match")
            elif username in stored_data:
                st.error("Username already exists")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("Registration successful! Please login.")

elif choice == "Login":
    st.subheader("User Login")
    
    if time.time() < st.session_state.lock_timeout:
        remaining = int(st.session_state.lock_timeout - time.time())
        st.error(f"Account locked. Please try again in {remaining} seconds.")
        st.stop()
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.form_submit_button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"Welcome {username}!")
                time.sleep(1)
                st.rerun()
            else:
                st.session_state.failed_attempts += 1
                remaining_attempts = 3 - st.session_state.failed_attempts
                
                if remaining_attempts > 0:
                    st.error(f"Invalid credentials. {remaining_attempts} attempts remaining.")
                else:
                    st.session_state.lock_timeout = time.time() + LOCK_DURATION
                    st.error("Too many failed attempts. Account locked for 60 seconds.")
                    time.sleep(1)
                    st.rerun()

elif choice == "Store Data":
    st.subheader("Store Encrypted Data")
    
    if not st.session_state.authenticated_user:
        st.warning("Please login first")
    else:
        with st.form("store_data_form"):
            data = st.text_area("Data to encrypt", height=150, 
                               help="Enter the sensitive data you want to encrypt")
            passkey = st.text_input("Encryption key", type="password", 
                                   help="This key will be required to decrypt the data")
            
            if st.form_submit_button("Encrypt and Save"):
                if not data or not passkey:
                    st.error("Both fields are required")
                else:
                    encrypted = encrypt_text(data, passkey)
                    if encrypted:
                        stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                        save_data(stored_data)
                        st.success("Data encrypted and saved successfully!")
                        st.code(encrypted, language="text")

elif choice == "Retrieve Data":
    st.subheader("Retrieve Your Data")
    
    if not st.session_state.authenticated_user:
        st.warning("Please login first")
    else:
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
        
        if not user_data:
            st.info("No encrypted data found for your account")
        else:
            st.write("### Your Encrypted Data Entries")
            for i, item in enumerate(user_data, 1):
                with st.expander(f"Encrypted Data #{i}"):
                    st.code(item, language="text")
            
            st.write("### Decrypt Data")
            with st.form("decrypt_form"):
                encrypted_input = st.text_area("Paste encrypted data here", height=100)
                passkey = st.text_input("Decryption key", type="password")
                
                if st.form_submit_button("Decrypt"):
                    if not encrypted_input or not passkey:
                        st.error("Both fields are required")
                    else:
                        decrypted = decrypt_text(encrypted_input, passkey)
                        if decrypted:
                            st.success("Decrypted successfully!")
                            st.text_area("Decrypted Data", value=decrypted, height=150)
                        else:
                            st.error("Decryption failed. Incorrect key or corrupted data.")


if st.session_state.authenticated_user:
    if st.sidebar.button("Logout"):
        st.session_state.authenticated_user = None
        st.success("Logged out successfully!")
        time.sleep(1)
        st.rerun()
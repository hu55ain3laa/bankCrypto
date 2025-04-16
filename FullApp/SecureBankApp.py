import uuid
import streamlit as st
from sqlmodel import Session, select
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import bcrypt
import jwt
import os
import base64
from datetime import datetime, timedelta
from init_db import engine, User, Transaction, create_db_and_tables, seed_initial_data

# Initialize database and seed data
@st.cache_resource
def init_database():
    try:
        if create_db_and_tables():
            pass
            if seed_initial_data():
                pass
            else:
                st.error("Failed to seed initial data")
                st.stop()
        else:
            st.error("Failed to create database tables")
            st.stop()
    except Exception as e:
        st.error(f"Error during initialization: {str(e)}")
        st.stop()

# Initialize database session
@st.cache_resource
def get_session():
    return Session(engine)

# Initialize the database when the app starts
init_database()
session = get_session()

# Encryption/Decryption functions
def get_encryption_key():
    key = st.secrets["encryption_key"].encode()
    key_length = len(key)
    if key_length == 16 or key_length == 24 or key_length == 32:
        return key
    else:
        raise ValueError(f"Invalid key size: {key_length}. AES key must be 16, 24, or 32 bytes.")

def encrypt_data(data: str, iv: bytes) -> str:
    cipher = Cipher(
        algorithms.AES(get_encryption_key()),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

def decrypt_data(encrypted_data: str, iv: bytes) -> str:
    cipher = Cipher(
        algorithms.AES(get_encryption_key()),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()


# Password hashing
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# JWT functions
def create_jwt(username: str) -> str:
    expiration = datetime.now() + timedelta(hours=1)
    payload = {
        "sub": username,
        "exp": expiration
    }
    return jwt.encode(payload, st.secrets["jwt_secret"], algorithm="HS256")

def verify_jwt(token: str) -> dict:
    try:
        payload = jwt.decode(token, st.secrets["jwt_secret"], algorithms=["HS256"])
        return payload
    except:
        return None

# User management
def create_user(username: str, password: str):
    try:
        iv = os.urandom(16)
        encrypted_balance = encrypt_data("1000", iv)
        
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            hashed_password=hash_password(password),
            iv=base64.b64encode(iv).decode(),
            balance=encrypted_balance
        )
        session.add(user)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        st.error(f"Error creating user: {str(e)}")
        return False

def get_user(username: str):
    return session.exec(select(User).where(User.username == username)).first()

# Transaction functions
def update_balance(username: str, amount: float):
    user = get_user(username)
    if user:
        iv = base64.b64decode(user.iv)
        current_balance = float(decrypt_data(user.balance, iv))
        new_balance = current_balance + amount
        user.balance = encrypt_data(str(new_balance), iv)
        session.commit()

def create_transaction(sender: str, receiver: str, amount: float):
    try:
        sender_user = get_user(sender)
        if not sender_user:
            st.error("Sender not found")
            return False
            
        receiver_user = get_user(receiver)
        if not receiver_user:
            st.error("Receiver not found")
            return False
            
        iv = base64.b64decode(sender_user.iv)
        
        transaction = Transaction(
            sender_id=sender_user.id,
            receiver_id=receiver_user.id,
            amount=encrypt_data(str(amount), iv),
            encrypted_sender=encrypt_data(sender, iv),
            encrypted_receiver=encrypt_data(receiver, iv),
            timestamp=datetime.now().isoformat()
        )
        session.add(transaction)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        st.error(f"Transaction failed: {str(e)}")
        return False

# Streamlit UI
def main():
    st.title("Secure Bank App")
    
    if "jwt" not in st.session_state:
        st.session_state.jwt = None
    
    # Login/Signup page
    if not st.session_state.jwt:
        tab1, tab2 = st.tabs(["Login", "Signup"])
        
        with tab1:
            with st.form("login"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                
                if st.form_submit_button("Login"):
                    user = get_user(username)
                    if user and check_password(password, user.hashed_password):
                        st.session_state.jwt = create_jwt(username)
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
        
        with tab2:
            with st.form("signup"):
                new_username = st.text_input("New Username")
                new_password = st.text_input("New Password", type="password")
                
                if st.form_submit_button("Create Account"):
                    if get_user(new_username):
                        st.error("Username already exists")
                    else:
                        create_user(new_username, new_password)
                        st.success("Account created successfully")
    
    # Main banking interface
    else:
        payload = verify_jwt(st.session_state.jwt)
        if not payload:
            st.error("Session expired")
            st.session_state.jwt = None
            st.rerun()
        
        username = payload["sub"]
        user = get_user(username)
        if not user:
            st.error("User not found")
            st.session_state.jwt = None
            st.rerun()
            
        iv = base64.b64decode(user.iv)
        balance = float(decrypt_data(user.balance, iv))
        
        st.subheader(f"Welcome {username}")
        st.write(f"Current Balance: ${balance:.2f}")
        
        with st.form("transfer"):
            receiver = st.text_input("Receiver Username")
            amount = st.number_input("Amount", min_value=0.01)
            
            if st.form_submit_button("Transfer"):
                if receiver == username:
                    st.error("Cannot transfer to yourself")
                elif amount > balance:
                    st.error("Insufficient funds")
                else:
                    receiver_user = get_user(receiver)
                    if not receiver_user:
                        st.error("Receiver not found")
                    else:
                        # Update balances
                        update_balance(username, -amount)
                        update_balance(receiver, amount)
                        
                        # Create transaction record
                        create_transaction(username, receiver, amount)
                        
                        st.success("Transfer successful")
                        st.rerun()
        
        if st.button("Logout"):
            st.session_state.jwt = None
            st.rerun()

if __name__ == "__main__":
    main()
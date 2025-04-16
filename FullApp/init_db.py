import os
import streamlit as st
from supabase import create_client
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import uuid

# Initialize Supabase client
@st.cache_resource
def init_supabase():
    return create_client(
        st.secrets["supabase"]["url"],
        st.secrets["supabase"]["key"]
    )

def get_encryption_key():
    key = st.secrets["encryption_key"].encode()
    if len(key) not in [16, 24, 32]:
        raise ValueError("Invalid key size")
    return key

def create_tables():
    supabase = init_supabase()

    # Create users table
    supabase.table('users').insert({
        'id': {'type': 'uuid', 'primary': True, 'default': {'function': 'uuid_generate_v4'}},
        'username': {'type': 'varchar', 'unique': True, 'null': False},
        'hashed_password': {'type': 'text', 'null': False},
        'iv': {'type': 'text', 'null': False},
        'balance': {'type': 'text', 'null': False},
        'created_at': {'type': 'timestamptz', 'default': {'function': 'now'}}
    }).execute()

    # Create transactions table
    supabase.table('transactions').insert({
        'id': {'type': 'uuid', 'primary': True, 'default': {'function': 'uuid_generate_v4'}},
        'sender_id': {'type': 'uuid', 'references': 'users(id)'},
        'receiver_id': {'type': 'uuid', 'references': 'users(id)'},
        'amount': {'type': 'text', 'null': False},
        'encrypted_sender': {'type': 'text', 'null': False},
        'encrypted_receiver': {'type': 'text', 'null': False},
        'timestamp': {'type': 'timestamptz', 'default': {'function': 'now'}}
    }).execute()

    print("Database tables created successfully")

if __name__ == "__main__":
    try:
        create_tables()
    except Exception as e:
        print(f"Error creating tables: {str(e)}")
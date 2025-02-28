from supabase import create_client, Client
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import bcrypt
import os
import base64

# Initialize Supabase
supabase: Client = create_client("https://cjsbrplczdmeifwvrhza.supabase.co", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNqc2JycGxjemRtZWlmd3ZyaHphIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzkyMTAwOTEsImV4cCI6MjA1NDc4NjA5MX0.kgB7mew35H1_Y_gTcEsIMDh_jnszmtzCnOyT0rbFZBI")

def get_encryption_key():
    key = b"kpxQmf1IuVBp9UPQQPsGZ5iXN0jE2ewZ"
    return key

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

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def create_user(username: str, password: str):
    iv = os.urandom(16)
    encrypted_balance = encrypt_data("1000", iv)
    user = {
        "username": username,
        "hashed_password": hash_password(password),
        "iv": base64.b64encode(iv).decode(),
        "balance": encrypted_balance
    }
    supabase.table("users").insert(user).execute()

def get_user(username: str):
    response = supabase.table("users").select("*").eq("username", username).execute()
    return response.data[0] if response.data else None

def update_balance(username: str, amount: float):
    user = get_user(username)
    iv = base64.b64decode(user["iv"])
    current_balance = float(decrypt_data(user["balance"], iv))
    new_balance = current_balance + amount
    encrypted_balance = encrypt_data(str(new_balance), iv)
    supabase.table("users").update({"balance": encrypted_balance}).eq("username", username).execute()

def create_transaction(sender: str, receiver: str, amount: float):
    sender_user = get_user(sender)
    iv = base64.b64decode(sender_user["iv"])
    transaction = {
        "sender": encrypt_data(sender, iv),
        "receiver": encrypt_data(receiver, iv),
        "amount": encrypt_data(str(amount), iv),
    }
    supabase.table("transactions").insert(transaction).execute()

def main():
    while True:
        print("1. Signup")
        print("2. Login")
        print("3. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            if get_user(username):
                print("Username already exists!")
            else:
                create_user(username, password)
                print("Account created successfully.")

        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            user = get_user(username)
            if user and check_password(password, user["hashed_password"]):
                iv = base64.b64decode(user["iv"])
                balance = float(decrypt_data(user["balance"], iv))
                print(f"Welcome {username}, Your balance: ${balance:.2f}")
                while True:
                    print("1. Transfer Money")
                    print("2. Logout")
                    option = input("Choose an option: ")
                    if option == "1":
                        receiver = input("Enter receiver username: ")
                        amount = float(input("Enter amount: "))
                        if amount > balance:
                            print("Insufficient funds!")
                        elif receiver == username:
                            print("Cannot transfer to yourself!")
                        else:
                            receiver_user = get_user(receiver)
                            if receiver_user:
                                update_balance(username, -amount)
                                update_balance(receiver, amount)
                                create_transaction(username, receiver, amount)
                                print("Transfer successful!")
                            else:
                                print("Receiver not found!")
                    elif option == "2":
                        break
            else:
                print("Invalid credentials!")

        elif choice == "3":
            break

if __name__ == "__main__":
    main()

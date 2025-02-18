from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import pandas as pd

def encrypt_data(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted_bytes).decode('utf-8')

# Load dataset
dataset_path = "bank_users_dataset.csv"  
df = pd.read_csv(dataset_path)

# Clean dataset
df.drop_duplicates(inplace=True)
df.dropna(inplace=True)
df.reset_index(drop=True, inplace=True)

# Generate encryption key and IV
encryption_key = os.urandom(32)  
iv = os.urandom(16)  

# Encrypt columns
df["Name"] = df["Name"].apply(lambda x: encrypt_data(x, encryption_key, iv))
df["Balance"] = df["Balance"].apply(lambda x: encrypt_data(str(x), encryption_key, iv))

# Save encrypted data
encrypted_file_path = "bank_users_dataset_encrypted.csv"
df.to_csv(encrypted_file_path, index=False)

# Save the encryption key and IV securely
with open("encryption_key.bin", "wb") as key_file:
    key_file.write(encryption_key)
with open("iv.bin", "wb") as iv_file:
    iv_file.write(iv)

print("Encryption complete. File saved as:", encrypted_file_path)
print("Encryption key and IV saved securely.")

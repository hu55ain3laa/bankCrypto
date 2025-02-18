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

def decrypt_data(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_bytes) + unpadder.finalize()
    return unpadded_data.decode('utf-8')

dataset_path = "bank_users_dataset.csv"  
df = pd.read_csv(dataset_path)

df.drop_duplicates(inplace=True)
df.dropna(inplace=True)
df.reset_index(drop=True, inplace=True)

encryption_key = os.urandom(32)  
iv = os.urandom(16)  

df["Name"] = df["Name"].apply(lambda x: encrypt_data(x, encryption_key, iv))
df["Balance"] = df["Balance"].apply(lambda x: encrypt_data(str(x), encryption_key, iv))

encrypted_file_path = "bank_users_dataset_encrypted.csv"
df.to_csv(encrypted_file_path, index=False)

print("Encryption complete. File saved as:", encrypted_file_path)

df_encrypted = pd.read_csv(encrypted_file_path)

df_encrypted["Name"] = df_encrypted["Name"].apply(lambda x: decrypt_data(x, encryption_key, iv))
df_encrypted["Balance"] = df_encrypted["Balance"].apply(lambda x: decrypt_data(x, encryption_key, iv))

decrypted_file_path = "bank_users_dataset_decrypted.csv"
df_encrypted.to_csv(decrypted_file_path, index=False)

print("Decryption complete. File saved as:", decrypted_file_path)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import pandas as pd

def decrypt_data(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_bytes) + unpadder.finalize()
    return unpadded_data.decode('utf-8')

# Load encryption key and IV
with open("encryption_key.bin", "rb") as key_file:
    encryption_key = key_file.read()
with open("iv.bin", "rb") as iv_file:
    iv = iv_file.read()

# Load encrypted dataset
encrypted_file_path = "bank_users_dataset_encrypted.csv"
df_encrypted = pd.read_csv(encrypted_file_path)

# Decrypt columns
df_encrypted["Name"] = df_encrypted["Name"].apply(lambda x: decrypt_data(x, encryption_key, iv))
df_encrypted["Balance"] = df_encrypted["Balance"].apply(lambda x: decrypt_data(x, encryption_key, iv))

# Save decrypted data
decrypted_file_path = "bank_users_dataset_decrypted.csv"
df_encrypted.to_csv(decrypted_file_path, index=False)

print("Decryption complete. File saved as:", decrypted_file_path)

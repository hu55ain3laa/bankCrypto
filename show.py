import pandas as pd

# Load the dataset
file_path = "./bank_users_dataset_encrypted.csv"
file_path = "./bank_users_dataset_decrypted.csv"
df = pd.read_csv(file_path)

# Display the first 10 rows
print(df.head(10))

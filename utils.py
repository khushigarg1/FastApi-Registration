import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import os
from dotenv import dotenv_values
env_values = dotenv_values('.env')
# Define the secret key

secret_key = env_values['SECRET_KEYAES'].encode()  # Replace with your own secret key

# Create an AES cipher with ECB mode using the secret key
cipher = Cipher(algorithms.AES(secret_key), modes.ECB())

def encrypt_api_key(plain_text: str) -> str:
    # Pad the plaintext to the block size of AES
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Encrypt the padded data
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the encrypted data as Base64
    encoded_data = base64.b64encode(encrypted_data).decode()

    return encoded_data

def decrypt_api_key(encrypted_data: bytes) -> str:
    # Decrypt the encrypted data
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode()

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import os

KEY_SIZE = 32  # 256 bits, 24 = 192 bits, 16 = 128 bits
SECRET_KEY_FILE_PATH = 'secretKey.ser'

def generate_key():
    try:
        return os.urandom(KEY_SIZE)
    except Exception as e:
        raise RuntimeError(e)

def save_secret_key(key, key_file_path):
    with open(key_file_path, 'wb') as key_file:
        key_file.write(key)

def load_secret_key(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        return key_file.read()

def encrypt(data, secret_key):
    try:
        # Generate a random 16 bytes nonce and create a cipher object
        cipher = Cipher(algorithms.AES(secret_key), modes.GCM(os.urandom(16)))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        print("Ciphertext length:", len(encrypted_data))
        print("Tag length:", len(tag))
        return b64encode(encrypted_data+tag).decode('utf-8')
    except Exception as e:
        raise RuntimeError(e)


def decrypt(encrypted_data, secret_key):
    try:
        # Decode encrypted data and authentication tag
        encrypted_data = b64decode(encrypted_data.encode('utf-8'))
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]
        print("Ciphertext length:", len(ciphertext))
        print("Tag length:", len(tag))
        cipher = Cipher(algorithms.AES(secret_key), modes.GCM(tag))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise RuntimeError(e)

    

if __name__ == '__main__':
    if os.path.exists(SECRET_KEY_FILE_PATH):
        secret_key = load_secret_key(SECRET_KEY_FILE_PATH)
    else:
        secret_key = generate_key()
        save_secret_key(secret_key, SECRET_KEY_FILE_PATH)

    original_data = "Hola, este es un mensaje secreto."
    encrypted_data = encrypt(original_data, secret_key)
    decrypted_data = decrypt(encrypted_data, secret_key)

    print("Texto original:", original_data)
    print("Texto cifrado:", encrypted_data)
    print("Texto descifrado:", decrypted_data)

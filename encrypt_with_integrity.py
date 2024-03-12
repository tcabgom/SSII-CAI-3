from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def encrypt_data(data, password):
    # Generar una clave secreta utilizando PBKDF2
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Cifrar los datos y calcular el código de autenticación
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(b"additional_data")  # Datos adicionales para autenticar

    # Aplicar relleno PKCS7
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Cifrar los datos con el relleno aplicado
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return salt, iv, encryptor.tag, encrypted_data

def decrypt_data(encrypted_data, tag, password, salt, iv):
    # Generar la clave secreta usando PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Descifrar los datos y verificar el código de autenticación
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(b"additional_data")  # Debe ser el mismo que se utilizó en el cifrado

    # Descifrar los datos
    decrypted_data_with_padding = decryptor.update(encrypted_data) + decryptor.finalize()

    # Eliminar el relleno
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_data_with_padding) + unpadder.finalize()

    return decrypted_data

# Ejemplo de uso
password = "mi_contraseña_secreta"
data = b"Datos sensibles que quiero cifrar."

# Cifrar los datos
salt, iv, tag, encrypted_data = encrypt_data(data, password)

# Mostrar los datos cifrados y el código de autenticación
print("Datos cifrados:", encrypted_data)
print("Código de autenticación:", tag)

# Descifrar los datos
decrypted_data = decrypt_data(encrypted_data, tag, password, salt, iv)

# Mostrar los datos descifrados
print("Datos descifrados:", decrypted_data.decode())

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import time

def encrypt_data(data, password, key_size):
    # Generar una clave secreta utilizando PBKDF2
    salt = os.urandom(key_size)
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


def run_cipher_benchmark(key_size, data_size):
    # Generar datos y contraseña para cifrar
    password = "mi_contraseña_secreta"
    data = os.urandom(1024*1024*data_size)
    print("\n#################################################",data_size, "MB #################################################")
    print("#################################################",key_size, "bits #################################################")

    # Medir el tiempo de cifrado
    start_time = time.time()
    salt, iv, tag, encrypted_data = encrypt_data(data, password, key_size)
    encryption_time = time.time() - start_time

    # Medir el tiempo de descifrado
    start_time = time.time()
    decrypted_data = decrypt_data(encrypted_data, tag, password, salt, iv)
    decryption_time = time.time() - start_time

    # Verificar la fortaleza contra ataques de fuerza bruta
    brute_force_strength = measure_brute_force_strength(key_size)

    # Mostrar resultados
    print(f"\n### RESULTADOS ###")
    print("Tiempo de cifrado:", encryption_time, "segundos")
    print("Tiempo de descifrado:", decryption_time, "segundos")
    print("Fortaleza contra ataques de fuerza bruta:", brute_force_strength)

def measure_brute_force_strength(key_size):
    # Generar datos y contraseña para cifrar
    password = "contraseña_de_prueba"
    data = os.urandom(1024 * 1024 * key_size)  # 1 MB de datos aleatorios

    # Generar clave secreta utilizando PBKDF2
    salt = os.urandom(key_size // 8)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size // 8,
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

    # Simular un ataque de fuerza bruta
    start_time = time.time()
    try:
        # Intentar descifrar los datos con una clave incorrecta
        incorrect_key = os.urandom(key_size // 8)
        cipher = Cipher(algorithms.AES(incorrect_key), modes.GCM(iv, encryptor.tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data_with_padding = decryptor.update(encrypted_data) + decryptor.finalize()

        # Eliminar el relleno
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_data_with_padding) + unpadder.finalize()
    except Exception as e:
        # Capturar cualquier excepción que indique un fallo en la descifrado
        elapsed_time = time.time() - start_time
        return f"No desencriptado ({elapsed_time} segundos)"

    elapsed_time = time.time() - start_time
    return f"Desencriptado (Tiempo: {elapsed_time} segundos)\n"

# Ejecutar pruebas para diferentes tamaños de clave
for data_size in [1, 64, 512]:
    run_cipher_benchmark(128, data_size)
    run_cipher_benchmark(192, data_size)
    run_cipher_benchmark(256, data_size)

import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def caesar_encrypt(text: str, shift: int) -> str:
    if not text:
        logging.warning("Цезарь: Передан пустой текст для шифрования!")
        return ""
    logging.info("Цезарь: Выполнение шифрования со сдвигом %d", shift)
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(encrypted_text: str, shift: int) -> str:
    logging.info("Цезарь: Выполнение расшифровки со сдвигом %d", shift)
    return caesar_encrypt(encrypted_text, -shift)

def vigenere_encrypt(text: str, key: str) -> str:
    if not text:
        logging.warning("Виженер: Передан пустой текст для шифрования!")
        return ""
    
    if not key:
        logging.error("Виженер: Ключ шифрования не может быть пустым.")
        raise ValueError("Ключ шифрования не может быть пустым")
    
    logging.info("Виженер: Выполнение шифрования")
    encrypted_text = ""
    key_index = 0
    key = key.lower()
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            ascii_offset = ord('a') if char.islower() else ord('A')
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted_text += encrypted_char
            key_index += 1
        else:
            encrypted_text += char
    return encrypted_text

def vigenere_decrypt(encrypted_text: str, key: str) -> str:
    if not key:
        logging.error("Виженер: Ключ для расшифровки не может быть пустым.")
        raise ValueError("Ключ шифрования не может быть пустым")
    logging.info("Виженер: Выполнение расшифровки")
    decrypted_text = ""
    key_index = 0
    key = key.lower()
    for char in encrypted_text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            ascii_offset = ord('a') if char.islower() else ord('A')
            decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            decrypted_text += decrypted_char
            key_index += 1
        else:
            decrypted_text += char
    return decrypted_text

def generate_rsa_keys():
    logging.info("RSA: Генерация пары ключей...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    logging.info("RSA: Ключи успешно сгенерированы.")
    return private_key, public_key

def rsa_encrypt(message: bytes, public_key) -> bytes:
    if not message:
        logging.warning("RSA: Пустое сообщение для шифрования!")
        return b""
    logging.info("RSA: Шифрование сообщения открытым ключом.")
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(encrypted_message: bytes, private_key) -> bytes:
    logging.info("RSA: Расшифровка сообщения закрытым ключом.")
    try:
        return private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        logging.error("RSA: Ошибка расшифровки! Детали: %s", e)
        raise ValueError("Ошибка расшифровки RSA") from e

def encrypt_file(input_filename: str, output_filename: str, key: bytes) -> None:
    logging.info("Fernet: Попытка шифрования файла %s -> %s", input_filename, output_filename)
    cipher_suite = Fernet(key)
    try:
        with open(input_filename, 'rb') as f:
            data = f.read()
        encrypted_data = cipher_suite.encrypt(data)
        with open(output_filename, 'wb') as f:
            f.write(encrypted_data)
        logging.info("Fernet: Файл успешно зашифрован.")
    except FileNotFoundError:
        logging.error("Fernet: Файл %s не найден!", input_filename)
        raise
    except Exception as e:
        logging.error("Fernet: Произошла ошибка при шифровании файла: %s", e)
        raise

def decrypt_file(input_filename: str, output_filename: str, key: bytes) -> None:
    logging.info("Fernet: Попытка расшифровки файла %s -> %s", input_filename, output_filename)
    cipher_suite = Fernet(key)
    try:
        with open(input_filename, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        with open(output_filename, 'wb') as f:
            f.write(decrypted_data)
        logging.info("Fernet: Файл успешно расшифрован.")
    except FileNotFoundError:
        logging.error("Fernet: Файл %s не найден!", input_filename)
        raise
    except Exception as e:
        logging.error("Fernet: Ошибка при расшифровке: %s", e)
        raise
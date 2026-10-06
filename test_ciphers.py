import unittest
from ciphers import (
    caesar_encrypt, caesar_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    generate_rsa_keys, rsa_encrypt, rsa_decrypt
)

class TestCiphers(unittest.TestCase):

    def test_caesar_cipher(self):
        text = "Hello World"
        shift = 3
        encrypted = caesar_encrypt(text, shift)
        decrypted = caesar_decrypt(encrypted, shift)
        self.assertEqual(decrypted, text)

    def test_vigenere_cipher(self):
        text = "Hello World"
        key = "key"
        encrypted = vigenere_encrypt(text, key)
        decrypted = vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    def test_vigenere_empty_key(self):
        # Этот тест проверяет, что программа правильно выдает ошибку (ValueError), 
        # если передать пустой ключ, а не падает с ошибкой деления на ноль.
        with self.assertRaises(ValueError):
            vigenere_encrypt("Test", "")

    def test_rsa_cipher(self):
        private_key, public_key = generate_rsa_keys()
        message = b"Secret Message"
        encrypted = rsa_encrypt(message, public_key)
        decrypted = rsa_decrypt(encrypted, private_key)
        self.assertEqual(decrypted, message)

if __name__ == '__main__':
    unittest.main()

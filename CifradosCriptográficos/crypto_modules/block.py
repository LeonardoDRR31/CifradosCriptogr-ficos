"""Aquí se muestran todos los algoritmos de cifrado en bloque"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES3
from Crypto.Cipher import Blowfish

def des_encrypt(key, plaintext):
    key = key.ljust(8, b'\0')[:8]  # DES key = 8 bytes
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
    return ciphertext

def des_decrypt(key, ciphertext):
    key = key.ljust(8, b'\0')[:8]
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return plaintext
from Crypto.Cipher import AES

def aes_encrypt(key, plaintext):
    key = key.ljust(16, b'\0')[:16]  # AES key = 16 bytes
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def aes_decrypt(key, ciphertext):
    key = key.ljust(16, b'\0')[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def triple_des_encrypt(key, plaintext):
    key = key.ljust(24, b'\0')[:24]  # Clave de 24 bytes
    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    return ciphertext

def triple_des_decrypt(key, ciphertext):
    key = key.ljust(24, b'\0')[:24]
    cipher = DES3.new(key, DES3.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return plaintext

def blowfish_encrypt(key, plaintext):
    key = key.ljust(16, b'\0')[:16]  # Clave de hasta 16 bytes
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, Blowfish.block_size))
    return ciphertext

def blowfish_decrypt(key, ciphertext):
    key = key.ljust(16, b'\0')[:16]
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    return plaintext
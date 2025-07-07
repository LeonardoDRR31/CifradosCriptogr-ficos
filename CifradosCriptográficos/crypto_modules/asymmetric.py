"""Aquí se muestran todos los algoritmos de cifrado asimétrico"""
from typing import List
from Crypto.PublicKey import RSA as pyRSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

#Cifrado Mochila#
def modinv(a, m):
    """Inverso modular"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('No existe inverso modular')
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

def generate_public_key(W: List[int], q: int, r: int) -> List[int]:
    return [(r * w) % q for w in W]

def encrypt(public_key: List[int], plaintext: bytes) -> List[int]:
    ciphertext = []
    for byte in plaintext:
        bits = [ (byte >> i) & 1 for i in reversed(range(8)) ]
        s = sum(b * pk for b, pk in zip(bits, public_key))
        ciphertext.append(s)
    return ciphertext

def decrypt(W: List[int], q: int, r: int, ciphertext: List[int]) -> bytes:
    r_inv = modinv(r, q)
    plaintext = []
    for s in ciphertext:
        c = (s * r_inv) % q
        bits = []
        for w in reversed(W):
            if w <= c:
                bits.insert(0, 1)
                c -= w
            else:
                bits.insert(0, 0)
        byte = sum(b << (7 - i) for i, b in enumerate(bits))
        plaintext.append(byte)
    return bytes(plaintext)

#Cifrado RSA#
def generate_rsa_keys():
    key = pyRSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key_pem: bytes, plaintext: bytes) -> bytes:
    recipient_key = pyRSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    ciphertext = cipher_rsa.encrypt(plaintext)
    return ciphertext

def rsa_decrypt(private_key_pem: bytes, ciphertext: bytes) -> bytes:
    private_key = pyRSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext

#Cifrado Deffie-man#
def diffie_hellman_generate_params():
    """Genera parámetros p y g"""
    p = 0xFFFFFFFB  # Primo grande de ejemplo
    g = 5           # Generador pequeño
    return p, g

def diffie_hellman_generate_private_key(p):
    """Genera clave privada"""
    return randint(2, p - 2)

def diffie_hellman_generate_public_key(p, g, private_key):
    """Genera clave pública"""
    return pow(g, private_key, p)

def diffie_hellman_compute_shared_secret(p, other_public, private_key):
    """Computa la clave compartida"""
    return pow(other_public, private_key, p)


#Cifrado ElGamal#
from Crypto.Util.number import getPrime, inverse

def elgamal_generate_keys(bits=256):
    """Genera parámetros p, g, x, y"""
    p = getPrime(bits)
    g = randint(2, p - 1)
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return p, g, x, y

def elgamal_encrypt(p, g, y, plaintext: bytes):
    """Cifra un mensaje"""
    m = int.from_bytes(plaintext, byteorder="big")
    k = randint(2, p - 2)
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    return c1, c2

def elgamal_decrypt(p, x, c1, c2):
    """Descifra un mensaje"""
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p
    plaintext = m.to_bytes((m.bit_length() + 7) // 8, byteorder="big")
    return plaintext

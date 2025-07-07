"""Aquí se muestran todos los algoritmos de cifrado hash + firma digital"""

import hashlib
from Crypto.PublicKey import RSA as pyRSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Util.number import getPrime, inverse, GCD
from random import randint

#Definimos hash_md5, hash_sha1 y hash_sha256 que permitirá que cualquier texto pueda ser transformado a #
# MD5 #
# sha-1 #
# sha-256 #
def hash_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def hash_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def hash_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def rsa_generate_keys():
    key = pyRSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_sign(private_key_pem: bytes, message: bytes) -> bytes:
    private_key = pyRSA.import_key(private_key_pem)
    h = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def rsa_verify(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
    public_key = pyRSA.import_key(public_key_pem)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
    
#Firmas digitales#
def dsa_generate_keys():
    key = DSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def dsa_sign(private_key_pem: bytes, message: bytes) -> bytes:
    private_key = DSA.import_key(private_key_pem)
    h = SHA256.new(message)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    return signature

def dsa_verify(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
    public_key = DSA.import_key(public_key_pem)
    h = SHA256.new(message)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

def elgamal_sign_generate_keys(bits=256):
    """Genera claves ElGamal para firma"""
    p = getPrime(bits)
    g = randint(2, p - 1)
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return p, g, x, y

def elgamal_sign(p, g, x, message: bytes):
    """Firma un mensaje (hash SHA-256)"""
    h = int.from_bytes(hashlib.sha256(message).digest(), byteorder="big")
    while True:
        k = randint(2, p - 2)
        if GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = inverse(k, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s

def elgamal_verify(p, g, y, message: bytes, r, s):
    """Verifica la firma"""
    if not (0 < r < p):
        return False
    h = int.from_bytes(hashlib.sha256(message).digest(), byteorder="big")
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2
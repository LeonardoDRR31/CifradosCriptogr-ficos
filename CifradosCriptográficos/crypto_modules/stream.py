"""Aquí se muestran todos los algoritmos de cifrado en flujo"""

from Crypto.Cipher import ARC4
import hashlib

def rc4_encrypt(key, plaintext):
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def rc4_decrypt(key, ciphertext):
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext
def lfsr_keystream(seed, taps, length):
    """
    Genera una secuencia de bits con LFSR.
    - seed: lista de bits iniciales
    - taps: posiciones de realimentación
    - length: longitud de la secuencia
    """
    sr = seed.copy()
    ks = []
    for _ in range(length * 8):
        next_bit = 0
        for t in taps:
            next_bit ^= sr[t]
        ks.append(sr[-1])
        sr = [next_bit] + sr[:-1]
    return ks

def lfsr_encrypt(seed, taps, plaintext):
    ks = lfsr_keystream(seed, taps, len(plaintext))
    pt_bits = ''.join(f'{b:08b}' for b in plaintext)
    ct_bits = ''.join(str(int(p)^k) for p,k in zip(pt_bits, ks))
    ciphertext = bytes(int(ct_bits[i:i+8], 2) for i in range(0, len(ct_bits),8))
    return ciphertext

def lfsr_decrypt(seed, taps, ciphertext):
    # Igual que cifrado
    return lfsr_encrypt(seed, taps, ciphertext)

def majority(x, y, z):
    return (x & y) | (x & z) | (y & z)

def a51_keystream(key, length):
    # Registros iniciales
    R1 = [int(b) for b in key[:19]]
    R2 = [int(b) for b in key[19:41]]
    R3 = [int(b) for b in key[41:64]]

    ks = []
    for _ in range(length * 8):
        m = majority(R1[8], R2[10], R3[10])
        if R1[8] == m:
            t = R1[13] ^ R1[16] ^ R1[17] ^ R1[18]
            R1 = [t] + R1[:-1]
        if R2[10] == m:
            t = R2[20] ^ R2[21]
            R2 = [t] + R2[:-1]
        if R3[10] == m:
            t = R3[7] ^ R3[20] ^ R3[21] ^ R3[22]
            R3 = [t] + R3[:-1]
        ks_bit = R1[-1] ^ R2[-1] ^ R3[-1]
        ks.append(ks_bit)
    return ks

def a51_encrypt(key, plaintext):
    ks = a51_keystream(key, len(plaintext))
    pt_bits = ''.join(f'{b:08b}' for b in plaintext)
    ct_bits = ''.join(str(int(p)^k) for p,k in zip(pt_bits, ks))
    ciphertext = bytes(int(ct_bits[i:i+8],2) for i in range(0,len(ct_bits),8))
    return ciphertext

def a51_decrypt(key, ciphertext):
    # Igual que cifrado
    return a51_encrypt(key, ciphertext)
def seal_keystream(key: bytes, length: int):
    keystream = b''
    counter = 0
    while len(keystream) < length:
        data = key + counter.to_bytes(4, 'big')
        hash_block = hashlib.sha256(data).digest()
        keystream += hash_block
        counter += 1
    return keystream[:length]

def seal_encrypt(key: bytes, plaintext: bytes):
    ks = seal_keystream(key, len(plaintext))
    return bytes([b ^ k for b, k in zip(plaintext, ks)])

def seal_decrypt(key: bytes, ciphertext: bytes):
    return seal_encrypt(key, ciphertext)
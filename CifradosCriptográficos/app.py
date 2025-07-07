"""Aquí se muestran todas las rutas de cifrado"""

from flask import Flask, render_template, request
from crypto_modules import stream
from crypto_modules import block
from crypto_modules import asymmetric as knapsack
from crypto_modules import asymmetric
from crypto_modules import hash_sign
from crypto_modules import certificates as certificates_module

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stream_ciphers", methods=["GET", "POST"])
def stream_ciphers():
    result = None
    if request.method == "POST":
        key = request.form["key"].encode()
        text = request.form["text"].encode()
        action = request.form["action"]

        if action == "Encrypt":
            cipher = stream.rc4_encrypt(key, text)
            result = cipher.hex()
        elif action == "Decrypt":
            ciphertext = bytes.fromhex(request.form["text"])
            plain = stream.rc4_decrypt(key, ciphertext)
            result = plain.decode(errors="ignore")
    return render_template("stream_ciphers.html", result=result)
@app.route("/block_ciphers", methods=["GET", "POST"])
def block_ciphers():
    result = None
    if request.method == "POST":
        key = request.form["key"].encode()
        text = request.form["text"].encode()
        action = request.form["action"]

        if action == "Encrypt":
            cipher = block.des_encrypt(key, text)
            result = cipher.hex()
        elif action == "Decrypt":
            ciphertext = bytes.fromhex(request.form["text"])
            plain = block.des_decrypt(key, ciphertext)
            result = plain.decode(errors="ignore")
    return render_template("block_ciphers.html", result=result)
#Cifrado AES#
@app.route("/aes_cipher", methods=["GET", "POST"])
def aes_cipher():
    result = None
    if request.method == "POST":
        key = request.form["key"].encode()
        text = request.form["text"].encode()
        action = request.form["action"]

        if action == "Encrypt":
            cipher = block.aes_encrypt(key, text)
            result = cipher.hex()
        elif action == "Decrypt":
            ciphertext = bytes.fromhex(request.form["text"])
            plain = block.aes_decrypt(key, ciphertext)
            result = plain.decode(errors="ignore")
    return render_template("aes_cipher.html", result=result)
#Cifrado LFSR#
@app.route("/lfsr_cipher", methods=["GET", "POST"])
def lfsr_cipher():
    result = None
    if request.method == "POST":
        seed_str = request.form["seed"]
        taps_str = request.form["taps"]
        text = request.form["text"].encode()
        action = request.form["action"]

        seed = [int(b) for b in seed_str]
        taps = [int(t) for t in taps_str.split(",")]

        if action == "Encrypt":
            cipher = stream.lfsr_encrypt(seed, taps, text)
            result = cipher.hex()
        elif action == "Decrypt":
            ciphertext = bytes.fromhex(request.form["text"])
            plain = stream.lfsr_decrypt(seed, taps, ciphertext)
            result = plain.decode(errors="ignore")
    return render_template("lfsr_cipher.html", result=result)
#Cifrado A5/1#
@app.route("/a51_cipher", methods=["GET", "POST"])
def a51_cipher():
    result = None
    if request.method == "POST":
        key = request.form["key"]
        text = request.form["text"].encode()
        action = request.form["action"]

        if len(key) < 64:
            error = "La clave debe tener al menos 64 bits en forma de cadena binaria."
            return render_template("a51_cipher.html", result=error)

        key_bits = [int(b) for b in key]

        if action == "Encrypt":
            cipher = stream.a51_encrypt(key_bits, text)
            result = cipher.hex()
        elif action == "Decrypt":
            ciphertext = bytes.fromhex(request.form["text"])
            plain = stream.a51_decrypt(key_bits, ciphertext)
            result = plain.decode(errors="ignore")
    return render_template("a51_cipher.html", result=result)
#Cifrado SEAL o similar#
@app.route("/seal_cipher", methods=["GET", "POST"])
def seal_cipher():
    result = None
    if request.method == "POST":
        key = request.form["key"].encode()
        text = request.form["text"]
        action = request.form["action"]

        if action == "Encrypt":
            encrypted = stream.seal_encrypt(key, text.encode())
            result = encrypted.hex()
        elif action == "Decrypt":
            ciphertext = bytes.fromhex(text)
            decrypted = stream.seal_decrypt(key, ciphertext)
            result = decrypted.decode(errors="ignore")
    return render_template("seal_cipher.html", result=result)

#Cifrado Triple DES#
@app.route("/triple_des_cipher", methods=["GET", "POST"])
def triple_des_cipher():
    result = None
    if request.method == "POST":
        key = request.form["key"].encode()
        text = request.form["text"].encode()
        action = request.form["action"]

        if action == "Encrypt":
            cipher = block.triple_des_encrypt(key, text)
            result = cipher.hex()
        elif action == "Decrypt":
            ciphertext = bytes.fromhex(request.form["text"])
            plain = block.triple_des_decrypt(key, ciphertext)
            result = plain.decode(errors="ignore")
    return render_template("triple_des_cipher.html", result=result)

#Cifrado blowfish#
@app.route("/blowfish_cipher", methods=["GET", "POST"])
def blowfish_cipher():
    result = None
    if request.method == "POST":
        key = request.form["key"].encode()
        text = request.form["text"]
        action = request.form["action"]

        if action == "Encrypt":
            encrypted = block.blowfish_encrypt(key, text.encode())
            result = encrypted.hex()
        elif action == "Decrypt":
            ciphertext = bytes.fromhex(text)
            decrypted = block.blowfish_decrypt(key, ciphertext)
            result = decrypted.decode(errors="ignore")
    return render_template("blowfish_cipher.html", result=result)

#Cifrado knapsack#
@app.route("/knapsack_cipher", methods=["GET", "POST"])
def knapsack_cipher():
    result = None
    if request.method == "POST":
        W_str = request.form["W"]
        q = int(request.form["q"])
        r = int(request.form["r"])
        text = request.form["text"]
        action = request.form["action"]

        W = [int(x) for x in W_str.split(",")]

        public_key = knapsack.generate_public_key(W, q, r)

        if action == "Encrypt":
            ciphertext = knapsack.encrypt(public_key, text.encode())
            result = ",".join(str(c) for c in ciphertext)
        elif action == "Decrypt":
            ciphertext = [int(c) for c in text.strip().split(",")]
            plaintext = knapsack.decrypt(W, q, r, ciphertext)
            result = plaintext.decode(errors="ignore")
    return render_template("knapsack_cipher.html", result=result)

#Cifrado RSA#
@app.route("/rsa_cipher", methods=["GET", "POST"])
def rsa_cipher():
    result = None
    generated_keys = None

    if request.method == "POST":
        action = request.form["action"]

        if action == "Generate":
            priv, pub = asymmetric.generate_rsa_keys()
            generated_keys = {
                "private": priv.decode(),
                "public": pub.decode()
            }

        else:
            text = request.form["text"]
            key_pem = request.form["key"].encode()

            if action == "Encrypt":
                encrypted = asymmetric.rsa_encrypt(key_pem, text.encode())
                result = encrypted.hex()

            elif action == "Decrypt":
                ciphertext = bytes.fromhex(text)
                decrypted = asymmetric.rsa_decrypt(key_pem, ciphertext)
                result = decrypted.decode(errors="ignore")

    return render_template("rsa_cipher.html", result=result, generated_keys=generated_keys)

#Cifrado diffie_hellman#
@app.route("/diffie_hellman", methods=["GET", "POST"])
def diffie_hellman():
    result = None
    generated = None

    if request.method == "POST":
        action = request.form["action"]

        if action == "Generate":
            p, g = asymmetric.diffie_hellman_generate_params()
            private_key = asymmetric.diffie_hellman_generate_private_key(p)
            public_key = asymmetric.diffie_hellman_generate_public_key(p, g, private_key)

            generated = {
                "p": str(p),
                "g": str(g),
                "private": str(private_key),
                "public": str(public_key)
            }

        elif action == "Compute":
            p = int(request.form["p"])
            other_public = int(request.form["other_public"])
            private_key = int(request.form["private_key"])

            shared = asymmetric.diffie_hellman_compute_shared_secret(p, other_public, private_key)
            result = str(shared)

    return render_template("diffie_hellman.html", generated=generated, result=result)

#Cifrado ElGamal#
@app.route("/elgamal_cipher", methods=["GET", "POST"])
def elgamal_cipher():
    result = None
    generated = None

    if request.method == "POST":
        action = request.form["action"]

        if action == "Generate":
            p, g, x, y = asymmetric.elgamal_generate_keys()
            generated = {
                "p": str(p),
                "g": str(g),
                "x": str(x),
                "y": str(y)
            }

        elif action == "Encrypt":
            p = int(request.form["p"])
            g = int(request.form["g"])
            y = int(request.form["y"])
            text = request.form["text"].encode()

            c1, c2 = asymmetric.elgamal_encrypt(p, g, y, text)
            result = f"{c1},{c2}"

        elif action == "Decrypt":
            p = int(request.form["p"])
            x = int(request.form["x"])
            c1, c2 = [int(v) for v in request.form["text"].split(",")]
            plaintext = asymmetric.elgamal_decrypt(p, x, c1, c2)
            result = plaintext.decode(errors="ignore")

    return render_template("elgamal_cipher.html", generated=generated, result=result)


#Ruta de hashing#
@app.route("/hash", methods=["GET", "POST"])
def hash_page():
    result = None
    if request.method == "POST":
        text = request.form["text"].encode()
        algo = request.form["algorithm"]

        if algo == "MD5":
            result = hash_sign.hash_md5(text)
        elif algo == "SHA1":
            result = hash_sign.hash_sha1(text)
        elif algo == "SHA256":
            result = hash_sign.hash_sha256(text)

    return render_template("hash.html", result=result)

#Ruta de firma con RSA#
@app.route("/rsa_signature", methods=["GET", "POST"])
def rsa_signature():
    generated = None
    result = None
    if request.method == "POST":
        action = request.form["action"]
        if action == "Generate":
            priv, pub = hash_sign.rsa_generate_keys()
            generated = {
                "private": priv.decode(),
                "public": pub.decode()
            }
        elif action == "Sign":
            priv = request.form["private"].encode()
            text = request.form["text"].encode()
            signature = hash_sign.rsa_sign(priv, text)
            result = signature.hex()
        elif action == "Verify":
            pub = request.form["public"].encode()
            text = request.form["text"].encode()
            signature = bytes.fromhex(request.form["signature"])
            valid = hash_sign.rsa_verify(pub, text, signature)
            result = "Válida" if valid else "No válida"
    return render_template("rsa_signature.html", generated=generated, result=result)

#Ruta de firma con DSA#
@app.route("/dsa_signature", methods=["GET", "POST"])
def dsa_signature():
    generated = None
    result = None
    if request.method == "POST":
        action = request.form["action"]
        if action == "Generate":
            priv, pub = hash_sign.dsa_generate_keys()
            generated = {
                "private": priv.decode(),
                "public": pub.decode()
            }
        elif action == "Sign":
            priv = request.form["private"].encode()
            text = request.form["text"].encode()
            signature = hash_sign.dsa_sign(priv, text)
            result = signature.hex()
        elif action == "Verify":
            pub = request.form["public"].encode()
            text = request.form["text"].encode()
            signature = bytes.fromhex(request.form["signature"])
            valid = hash_sign.dsa_verify(pub, text, signature)
            result = "Válida" if valid else "No válida"
    return render_template("dsa_signature.html", generated=generated, result=result)

#Ruta de firma con ElGamal#
@app.route("/elgamal_signature", methods=["GET", "POST"])
def elgamal_signature():
    generated = None
    result = None
    if request.method == "POST":
        action = request.form["action"]
        if action == "Generate":
            p, g, x, y = hash_sign.elgamal_sign_generate_keys()
            generated = {
                "p": str(p),
                "g": str(g),
                "x": str(x),
                "y": str(y)
            }
        elif action == "Sign":
            p = int(request.form["p"])
            g = int(request.form["g"])
            x = int(request.form["x"])
            text = request.form["text"].encode()
            r, s = hash_sign.elgamal_sign(p, g, x, text)
            result = f"{r},{s}"
        elif action == "Verify":
            p = int(request.form["p"])
            g = int(request.form["g"])
            y = int(request.form["y"])
            text = request.form["text"].encode()
            r, s = [int(v) for v in request.form["signature"].split(",")]
            valid = hash_sign.elgamal_verify(p, g, y, text, r, s)
            result = "Válida" if valid else "No válida"
    return render_template("elgamal_signature.html", generated=generated, result=result)

#Certificados#
@app.route("/certificates", methods=["GET", "POST"])
def certificates():
    result = None
    if request.method == "POST":
        common_name = request.form["common_name"]
        days_valid = int(request.form["days_valid"])
        private_pem, cert_pem = certificates_module.generate_self_signed_cert(common_name, days_valid)
        result = {
            "private": private_pem,
            "cert": cert_pem
        }
    return render_template("certificates.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)

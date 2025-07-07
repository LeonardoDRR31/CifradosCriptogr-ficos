from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def generate_self_signed_cert(common_name: str, days_valid: int = 365):
    # 1. Generar clave privada
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # 2. Datos del sujeto
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lima"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lima"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiAppSegura"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # 3. Crear certificado
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # 4. Exportar como PEM
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return private_pem.decode(), cert_pem.decode()

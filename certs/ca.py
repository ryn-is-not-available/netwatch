from cryptography.hazmat.primitives import serialization , hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from pathlib import Path
import datetime
import os

def generate_private_key(key_size=2048):
    """
    Generates a private RSA key.
    
    :param key_size: Size of the RSA key in bits (default is 2048).
    :return A private RSA key object.
    """
    key =rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    with open(Path(__file__).resolve().parent / "ca.key", "wb") as key_file:
        key_file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
        )
    )
    os.chmod(Path(__file__).resolve().parent / "ca.key", 0o600)
    return key

def generate_certification():
    """
    Generates a self-signed certificate using the private key.
    :return A self-signed certificate object.

    """
    if  Path.exists(Path(__file__).resolve().parent / "ca.crt") or Path.exists(Path(__file__).resolve().parent / "ca.key"):
        print("CA files already exist; delete them explicitly to regenerate.")
        return

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tunis"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"netWatch"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"netwatch.com"),
    ])
    
    key = generate_private_key()

    cert = x509.CertificateBuilder().subject_name(
        subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True,
                crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False
            ),
            critical=True
        ).sign(
            key,
            algorithm=hashes.SHA256()
        )

    
    with open(Path(__file__).resolve().parent / "ca.crt", "wb") as cert_file:
        cert_file.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )
    os.chmod(Path(__file__).resolve().parent / "ca.crt", 0o644)


if __name__ == "__main__":
    generate_certification()
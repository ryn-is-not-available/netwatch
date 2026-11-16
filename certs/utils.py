from cryptography import x509
from cryptography.hazmat.primitives import serialization 

def load_private_key_from_file(file_path):
    """
    Loads a private RSA key from a PEM file.
    
    :param file_path: Path to the PEM file containing the private key.
    :return A private RSA key object.
    """
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key


def load_certificate_from_file(file_path):
    """
    Loads a certificate from a PEM file.
    
    :param file_path: Path to the PEM file containing the certificate.
    :return A certificate object.
    """
    with open(file_path, "rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read())
    return certificate

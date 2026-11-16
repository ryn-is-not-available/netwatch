from cryptography.hazmat.primitives import serialization , hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pathlib import Path
import datetime
import os
import ipaddress

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



def generate_private_key(key_size=2048,name="server"):
    """
    Generates a private RSA key.
    
    :param key_size: Size of the RSA key in bits (default is 2048).
    :return A private RSA key object.
    """
    key =rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    with open(Path(__file__).resolve().parent / f"{name}.key", "wb") as key_file:
        key_file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
        )
    )
    os.chmod(Path(__file__).resolve().parent / f"{name}.key", 0o600)
    return key

def generate_server_cert(service_name: str, dns_names: list[str], ip_addrs: list[str], days: int = 365):
    """
    Generates a server certificate signed by the CA.
    
    :param service_name: Common Name (CN) for the server certificate.
    :param dns_names: List of DNS names to include in the SAN extension.
    :param ip_addrs: List of IP addresses to include in the SAN extension.
    :param days: Number of days the certificate is valid for (default is 365).
    :return A server certificate object.
    """
    if  Path.exists(Path(__file__).resolve().parent / f"{service_name}.key") or Path.exists(Path(__file__).resolve().parent / f"{service_name}.crt"):
        print("Server certificate files already exist; delete them explicitly to regenerate.")
        return

    key = generate_private_key(name=service_name)
    ca_key = load_private_key_from_file(Path(__file__).resolve().parent / "ca.key")
    ca_cert = load_certificate_from_file(Path(__file__).resolve().parent / "ca.crt")

    issuer = ca_cert.subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, service_name),
    ])

    san_list = []
    for dns in dns_names:
        san_list.append(x509.DNSName(dns))
    for ip in ip_addrs:
        san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))

    cert_builder = x509.CertificateBuilder().subject_name(
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
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        ).add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )

    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    with open(Path(__file__).resolve().parent / f"{service_name}.crt", "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    
    os.chmod(Path(__file__).resolve().parent / f"{service_name}.crt", 0o644)
    
    return cert


if __name__ == "__main__":
    generate_server_cert(
        service_name="control-plane",
        dns_names=["control-plane", "localhost"],
        ip_addrs=["127.0.0.1"],
        days=365)

    generate_server_cert(
        service_name="nats",
        dns_names=["nats", "localhost"],
        ip_addrs=["127.0.0.1"],
        days=365)
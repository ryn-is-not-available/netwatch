from cryptography import x509
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization , hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path
from certs.utils import load_certificate_from_file,load_private_key_from_file
import os
import datetime


def create_node_csr(node_id: str):
    """
    Create a CSR for a node with the given node_id.
    :param node_id: The unique identifier for the node.
    """

    if Path.exists(Path(__file__).resolve().parent / f"{node_id}.key") or Path.exists(Path(__file__).resolve().parent / f"{node_id}.csr"):
        print("Node files already exist; delete them explicitly to regenerate.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    subject  = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tunis"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"netWatch"),
        x509.NameAttribute(NameOID.COMMON_NAME, node_id),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256())

    with open(Path(__file__).resolve().parent / f"{node_id}.key","wb") as key_file :
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(Path(__file__).resolve().parent / f"{node_id}.csr","wb") as csr_file :
        csr_file.write(
            csr.public_bytes(encoding=serialization.Encoding.PEM)
        )

    os.chmod(Path(__file__).resolve().parent / f"{node_id}.key", 0o600)
    os.chmod(Path(__file__).resolve().parent / f"{node_id}.csr", 0o644)

    return (csr.public_bytes(encoding=serialization.Encoding.PEM) , node_id)


def sign_client_csr(csr_pem: bytes, node_id: str, hours: int = 24 ) -> bytes:
    csr= x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("Invalid CSR signature")

    ca_key = load_private_key_from_file(Path(__file__).resolve().parent / "ca.key")
    ca_cert = load_certificate_from_file(Path(__file__).resolve().parent / "ca.crt")

    subject = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME,
        node_id
    )])


    signed_cert = x509.CertificateBuilder(
    ).subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).serial_number(
        x509.random_serial_number()
    ).public_key(
        csr.public_key()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
    ).add_extension(
        x509.BasicConstraints(
            ca=False,
            path_length=None
        ),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CLIENT_AUTH]
        ),
        critical=False
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            key_cert_sign=False, crl_sign=False, 
            content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False,
            decipher_only=False 
        ),
        critical=True
    ).sign(ca_key,hashes.SHA256())


    return signed_cert.public_bytes(serialization.Encoding.PEM)


if __name__ == "__main__" :
    csr_pem , id = create_node_csr("node-1")
    cert = sign_client_csr(csr_pem,"node-1")
    if (cert != None) :
        with open(Path(__file__).resolve().parent / "node-1.crt","wb") as node_1_cert :
            node_1_cert.write(
                cert
            )
        os.chmod(Path(__file__).resolve().parent / "node-1.crt",0o644)
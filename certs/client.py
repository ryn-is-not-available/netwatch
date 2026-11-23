import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from certs.utils import load_certificate_from_file, load_private_key_from_file


def generate_node_key_and_csr(node_id: str) -> tuple[bytes, bytes]:
    """Generate an RSA-2048 private key and CSR PEM in memory without touching disk."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tunis"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Tunis"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "netWatch"),
        x509.NameAttribute(NameOID.COMMON_NAME, node_id),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
    return key_pem, csr_pem


def sign_client_csr(
    csr_pem: bytes,
    node_id: str,
    hours: int = 24,
    ca_dir: Path | None = None,
) -> bytes:
    """Validate a node CSR and sign a short-lived CLIENT_AUTH certificate."""
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("Invalid CSR signature")

    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs or cn_attrs[0].value != node_id:
        raise ValueError("CSR Common Name does not match node_id")

    base_dir = ca_dir or Path(__file__).resolve().parent
    ca_key = load_private_key_from_file(base_dir / "ca.key")
    ca_cert = load_certificate_from_file(base_dir / "ca.crt")

    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])

    signed_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .serial_number(x509.random_serial_number())
        .public_key(csr.public_key())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=hours))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return signed_cert.public_bytes(serialization.Encoding.PEM)
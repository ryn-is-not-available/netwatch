"""Telemetry transport security shared by agents, the worker and the control plane.

- tls_context(): client TLS for NATS, trusting the NetWatch Root CA.
- sign_payload()/verify_payload(): per-message authenticity. Agents share one NATS user,
  so NATS alone cannot stop a node from publishing as another node. Each agent signs the
  exact payload bytes with the private key behind its enrolled client certificate, and the
  worker verifies against the certificate the control plane stored at enrollment.
"""
import base64
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SIGNATURE_HEADER = "Netwatch-Sig"


def tls_context(ca_path: str | Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(ca_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def load_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("NetWatch agent keys are RSA")
    return key


def public_key_from_cert_pem(pem: bytes | str) -> rsa.RSAPublicKey:
    raw = pem.encode() if isinstance(pem, str) else pem
    key = x509.load_pem_x509_certificate(raw).public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("NetWatch node certificates carry RSA keys")
    return key


def sign_payload(private_key: rsa.RSAPrivateKey, payload: bytes) -> str:
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")


def verify_payload(public_key: rsa.RSAPublicKey, payload: bytes, signature_b64: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64, validate=True), payload, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

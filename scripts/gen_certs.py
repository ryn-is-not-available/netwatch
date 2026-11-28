"""Generates the NetWatch PKI. Safe to run repeatedly: existing files are kept.

Writes into certs/:
  ca.key, ca.crt                      Root CA (ca.key stays on the control plane only)
  control-plane.key, control-plane.crt
  nats.key, nats.crt
  public/ca.crt                       Copy of the CA certificate, the only PKI file nodes mount

Run from anywhere:  python scripts/gen_certs.py
docker-compose runs it automatically in the one-shot `cert-init` service.
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from certs import ca, servers  # noqa: E402

CERTS_DIR = ROOT / "certs"
PUBLIC_DIR = CERTS_DIR / "public"


def _check_pair(name: str) -> None:
    key, crt = CERTS_DIR / f"{name}.key", CERTS_DIR / f"{name}.crt"
    if key.exists() != crt.exists():
        present, missing = (key, crt) if key.exists() else (crt, key)
        raise SystemExit(
            f"Inconsistent PKI state: {present.name} exists but {missing.name} does not. "
            f"Delete {present.name} to regenerate it."
        )


def main() -> None:
    for name in ("ca", "control-plane", "nats"):
        _check_pair(name)

    ca.generate_certification()
    servers.generate_default_server_certs()

    PUBLIC_DIR.mkdir(exist_ok=True)
    shutil.copyfile(CERTS_DIR / "ca.crt", PUBLIC_DIR / "ca.crt")
    print(f"PKI ready in {CERTS_DIR} (public CA copy: {PUBLIC_DIR / 'ca.crt'})")


if __name__ == "__main__":
    main()

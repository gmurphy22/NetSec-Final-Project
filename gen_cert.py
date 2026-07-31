"""
makes a self signed tls cert for localhost.

run it once:

    python gen_cert.py

the server calls generate() on startup too, so you only need to run this by
hand if you want to. it spits out cert.pem and key.pem. the cert has a
subjectaltname for localhost and 127.0.0.1 so the client can actually verify
the server instead of just trusting whatever answers.

key.pem is the private key, don't commit it. cert.pem is fine to hand out.
"""

import os
import ipaddress
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import config


def generate(cert_path=config.CERT_FILE, key_path=config.KEY_FILE, force=False):
    if os.path.exists(cert_path) and os.path.exists(key_path) and not force:
        return False  # already there, nothing to do

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)  # lock down the private key
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return True


if __name__ == "__main__":
    created = generate()
    print("Generated cert.pem and key.pem" if created else "Certificate already exists")

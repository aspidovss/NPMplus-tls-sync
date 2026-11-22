"""Разбор и проверка PEM-файлов сертификата."""
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization


@dataclass
class CertFiles:
    fullchain: bytes
    privkey: bytes
    domains: list[str]
    not_after: datetime
    sha: str

    @property
    def expired(self) -> bool:
        return self.not_after <= datetime.now(timezone.utc)


def _spki(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def load(fullchain: bytes, privkey: bytes) -> CertFiles:
    if b"BEGIN CERTIFICATE" not in fullchain:
        raise ValueError("fullchain не содержит сертификата")
    if b"PRIVATE KEY" not in privkey:
        raise ValueError("privkey не содержит закрытого ключа")
    cert = x509.load_pem_x509_certificate(fullchain)  # первый сертификат цепочки
    key = serialization.load_pem_private_key(privkey, password=None)
    if _spki(cert.public_key()) != _spki(key.public_key()):
        raise ValueError("закрытый ключ не соответствует сертификату")
    domains: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        domains = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    if not domains:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        domains = [cn[0].value] if cn else []
    sha = hashlib.sha256(fullchain + b"\0" + privkey).hexdigest()
    return CertFiles(fullchain, privkey, list(domains), cert.not_valid_after_utc, sha)


def covers(cert_domains: list[str], host: str) -> bool:
    """Покрывает ли сертификат имя хоста (с учётом wildcard)."""
    host = host.lower().rstrip(".")
    for d in cert_domains:
        d = d.lower().rstrip(".")
        if d == host:
            return True
        if d.startswith("*.") and host.count(".") == d.count(".") and host.endswith(d[1:]):
            return True
    return False

"""Шифрование паролей и SSH-ключей в БД ключом, производным от APP_SECRET."""
import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

_fernet: Fernet | None = None


def app_secret() -> str:
    return os.environ.get("APP_SECRET", "")


def _f() -> Fernet:
    global _fernet
    if _fernet is None:
        key = hashlib.sha256(("nmpsync-db:" + app_secret()).encode()).digest()
        _fernet = Fernet(base64.urlsafe_b64encode(key))
    return _fernet


def encrypt(value: str) -> str:
    return _f().encrypt(value.encode()).decode() if value else ""


def decrypt(value: str) -> str:
    if not value:
        return ""
    try:
        return _f().decrypt(value.encode()).decode()
    except InvalidToken as e:
        raise RuntimeError("Не удалось расшифровать секрет: APP_SECRET изменился?") from e

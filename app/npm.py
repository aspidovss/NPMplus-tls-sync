"""Клиент API Nginx Proxy Manager / NPMplus."""
import io
import zipfile

import requests
import urllib3

from .i18n import message

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 30


class NPMError(Exception):
    pass


class NPMAuthError(NPMError):
    pass


class NPMClient:
    def __init__(self, url: str, username: str, password: str, verify_tls: bool = True):
        base = url.rstrip("/")
        if not base.endswith("/api"):
            base += "/api"
        self.base = base
        self.username = username
        self.password = password
        self.s = requests.Session()
        self.s.verify = verify_tls
        self.s.headers["User-Agent"] = "nmp-sync"
        self._logged_in = False

    # --- низкий уровень -------------------------------------------------
    def _req(self, method: str, path: str, **kw) -> requests.Response:
        if not self._logged_in:
            self.login()
        try:
            r = self.s.request(method, self.base + path, timeout=TIMEOUT, **kw)
        except requests.RequestException as e:
            raise NPMError(f"{method} {path}: {e.__class__.__name__}: {e}") from e
        if r.status_code >= 400:
            raise NPMError(f"{method} {path}: HTTP {r.status_code} {r.text[:200]}")
        return r

    def login(self) -> None:
        """NPM отдаёт token в JSON (Bearer), NPMplus — в cookie. Поддерживаем оба."""
        try:
            r = self.s.post(self.base + "/tokens", timeout=TIMEOUT,
                            json={"identity": self.username, "secret": self.password, "scope": "user"})
        except requests.RequestException as e:
            raise NPMAuthError(message("вход: {type}: {error}", type=e.__class__.__name__, error=e)) from e
        if r.status_code != 200:
            raise NPMAuthError(message("вход не удался: HTTP {status} {response}", status=r.status_code, response=r.text[:200]))
        try:
            data = r.json()
        except ValueError:
            data = {}
        token = data.get("token") if isinstance(data, dict) else None
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"
        elif not self.s.cookies:
            raise NPMAuthError(message("вход: сервер не вернул ни token, ни cookie"))
        self._logged_in = True

    # --- сертификаты ----------------------------------------------------
    def list_certificates(self) -> list[dict]:
        return self._req("GET", "/nginx/certificates").json()

    def download_certificate(self, cert_id: int) -> tuple[bytes, bytes]:
        """Zip с файлами certbot (имена вида fullchain.pem или fullchain1.pem)."""
        r = self._req("GET", f"/nginx/certificates/{cert_id}/download")
        try:
            z = zipfile.ZipFile(io.BytesIO(r.content))
        except zipfile.BadZipFile as e:
            raise NPMError(message("download {id}: ответ не zip", id=cert_id)) from e
        full = key = None
        for info in z.infolist():
            base = info.filename.rsplit("/", 1)[-1].lower()
            if info.file_size > 1_000_000:
                continue
            if base.startswith("fullchain") and base.endswith(".pem"):
                full = z.read(info)
            elif base.startswith("privkey") and base.endswith(".pem"):
                key = z.read(info)
        if not full or not key:
            raise NPMError(message("download {id}: в архиве нет fullchain/privkey", id=cert_id))
        return full, key

    def create_custom_certificate(self, nice_name: str) -> int:
        data = self._req("POST", "/nginx/certificates",
                         json={"provider": "other", "nice_name": nice_name}).json()
        cid = data.get("id") if isinstance(data, dict) else None
        if not isinstance(cid, int):
            raise NPMError(message("создание сертификата: неожиданный ответ {response}", response=str(data)[:200]))
        return cid

    def upload_certificate(self, cert_id: int, fullchain: bytes, privkey: bytes) -> None:
        self._req("POST", f"/nginx/certificates/{cert_id}/upload", files={
            "certificate": ("fullchain.pem", fullchain, "application/x-pem-file"),
            "certificate_key": ("privkey.pem", privkey, "application/x-pem-file"),
        })

    # --- прокси-хосты ---------------------------------------------------
    def list_proxy_hosts(self) -> list[dict]:
        return self._req("GET", "/nginx/proxy-hosts").json()

    def set_proxy_host_certificate(self, host_id: int, cert_id: int) -> None:
        self._req("PUT", f"/nginx/proxy-hosts/{host_id}", json={"certificate_id": cert_id})

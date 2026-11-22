"""Запасной источник: SSH на мастер с принудительной командой cert-export.

На мастере в authorized_keys:
  restrict,command="/usr/local/bin/cert-export" ssh-ed25519 AAAA... nmp-sync
cert-export понимает "list" и "npm-N" (см. README).
"""
import io
import os
import re
import subprocess
import tarfile
import tempfile

KNOWN_HOSTS = os.path.join(os.path.dirname(os.environ.get("DB_PATH", "/data/nmpsync.db")), "known_hosts")


class SSHError(Exception):
    pass


def _run(host: str, port: int, user: str, key_pem: str, command: str, timeout: int = 60) -> bytes:
    if not host or not key_pem:
        raise SSHError("SSH не настроен: нет хоста или ключа")
    key = key_pem.replace("\r\n", "\n").strip() + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        kf = os.path.join(tmp, "id")
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        cmd = ["ssh", "-i", kf, "-p", str(port),
               "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
               "-o", "IdentitiesOnly=yes",
               "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
               "-o", "StrictHostKeyChecking=accept-new",
               f"{user}@{host}", command]
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        except FileNotFoundError as e:
            raise SSHError("нет ssh-клиента в контейнере") from e
        except subprocess.TimeoutExpired as e:
            raise SSHError(f"ssh {command}: таймаут") from e
    if p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip()[-300:]
        raise SSHError(f"ssh {command}: код {p.returncode}: {err}")
    return p.stdout


def list_certs(host, port, user, key_pem) -> list[int]:
    out = _run(host, port, user, key_pem, "list").decode(errors="replace")
    ids = []
    for line in out.splitlines():
        m = re.match(r"^npm-(\d+)\b", line.strip())
        if m:
            ids.append(int(m.group(1)))
    return ids


def fetch(host, port, user, key_pem, cert_id: int) -> tuple[bytes, bytes]:
    data = _run(host, port, user, key_pem, f"npm-{int(cert_id)}")
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            for m in t.getmembers():
                name = m.name.rsplit("/", 1)[-1]
                if m.isfile() and name in ("fullchain.pem", "privkey.pem") and m.size < 1_000_000:
                    files[name] = t.extractfile(m).read()
    except tarfile.TarError as e:
        raise SSHError(f"npm-{cert_id}: некорректный tar") from e
    if "fullchain.pem" not in files or "privkey.pem" not in files:
        raise SSHError(f"npm-{cert_id}: в архиве нет fullchain.pem/privkey.pem")
    return files["fullchain.pem"], files["privkey.pem"]

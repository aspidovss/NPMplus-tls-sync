"""Движок синхронизации: мастер -> ноды."""
import logging
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import db, pem, sshsrc, vault
from .i18n import current_language, language, message
from .npm import NPMAuthError, NPMClient, NPMError

log = logging.getLogger("nmp-sync")
_run_lock = threading.Lock()
NICE_PREFIX = "sync: "


def is_running() -> bool:
    return _run_lock.locked()


@contextmanager
def pause_sync():
    acquired = _run_lock.acquire(blocking=False)
    try:
        yield acquired
    finally:
        if acquired:
            _run_lock.release()


@dataclass
class Ref:
    cert_id: int
    domains: list[str] = field(default_factory=list)
    provider: str = ""


class Run:
    def __init__(self, trigger: str):
        self.id = db.execute("INSERT INTO runs(started_at,trigger,status) VALUES(?,?,?)",
                             (db.now_iso(), trigger, "running"))
        self.errors = 0
        self.uploaded = 0
        self.assigned = 0

    def ev(self, level: str, msg: str) -> None:
        if level == "error":
            self.errors += 1
        getattr(log, "error" if level == "error" else "info")(msg)
        db.execute("INSERT INTO events(run_id,ts,level,message) VALUES(?,?,?,?)",
                   (self.id, db.now_iso(), level, msg))

    def finish(self, fatal: str | None = None) -> None:
        if fatal:
            self.ev("error", fatal)
            status = "failed"
        else:
            status = "partial" if self.errors else "ok"
        summary = message("загружено: {uploaded}, привязано: {assigned}, ошибок: {errors}",
                          uploaded=self.uploaded, assigned=self.assigned, errors=self.errors)
        db.execute("UPDATE runs SET finished_at=?, status=?, summary=? WHERE id=?",
                   (db.now_iso(), status, summary, self.id))
        keep = int(db.get_setting("keep_runs") or 300)
        db.execute("DELETE FROM events WHERE run_id IN (SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET ?)", (keep,))
        db.execute("DELETE FROM runs WHERE id IN (SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET ?)", (keep,))


def client_for(server: dict) -> NPMClient:
    return NPMClient(server["url"], server["username"], vault.decrypt(server["password_enc"]),
                     bool(server["verify_tls"]))


def _ssh_args(m: dict):
    return (m["ssh_host"], int(m["ssh_port"] or 22), m["ssh_user"] or "root", vault.decrypt(m["ssh_key_enc"]))


def _ssh_ready(m: dict) -> bool:
    return bool(m["ssh_host"] and m["ssh_key_enc"])


# --- мастер --------------------------------------------------------------
class Source:
    def __init__(self, m: dict):
        self.m = m
        self.mode = m["fetch_mode"]
        self.api = client_for(m) if self.mode in ("api", "auto") else None

    def list(self, run: Run) -> list[Ref]:
        if self.api:
            try:
                return [Ref(int(c["id"]), list(c.get("domain_names") or []), str(c.get("provider") or ""))
                        for c in self.api.list_certificates()]
            except NPMError as e:
                if self.mode != "auto" or not _ssh_ready(self.m):
                    raise
                run.ev("warn", message("мастер: список через API не получен ({error}), пробую SSH", error=e))
        return [Ref(i) for i in sshsrc.list_certs(*_ssh_args(self.m))]

    def fetch(self, ref: Ref, run: Run) -> tuple[bytes, bytes]:
        if self.api:
            try:
                return self.api.download_certificate(ref.cert_id)
            except NPMError as e:
                if self.mode != "auto" or not _ssh_ready(self.m):
                    raise
                run.ev("warn", message("npm-{id}: API download не удался ({error}), беру по SSH", id=ref.cert_id, error=e))
        return sshsrc.fetch(*_ssh_args(self.m), ref.cert_id)


# --- ноды ----------------------------------------------------------------
class Node:
    def __init__(self, server: dict):
        self.s = server
        self.name = server["name"]
        self.c = client_for(server)
        self._certs: dict[int, dict] | None = None
        self._hosts: list[dict] | None = None

    def certs(self) -> dict[int, dict]:
        if self._certs is None:
            self._certs = {int(c["id"]): c for c in self.c.list_certificates()}
        return self._certs

    def hosts(self) -> list[dict]:
        if self._hosts is None:
            self._hosts = self.c.list_proxy_hosts()
        return self._hosts

    def find_by_name(self, nice: str) -> int | None:
        for cid, c in self.certs().items():
            if c.get("provider") == "other" and c.get("nice_name") == nice:
                return cid
        return None


def _parse_dt(v) -> datetime | None:
    if not v:
        return None
    s = str(v).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s[:19], fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _set_state(node_id, cert_id, **kw):
    cur = db.one("SELECT * FROM sync_state WHERE node_id=? AND cert_id=?", (node_id, cert_id))
    if not cur:
        db.execute("INSERT INTO sync_state(node_id,cert_id) VALUES(?,?)", (node_id, cert_id))
    cols = ", ".join(f"{k}=?" for k in kw)
    db.execute(f"UPDATE sync_state SET {cols} WHERE node_id=? AND cert_id=?", (*kw.values(), node_id, cert_id))


def _sync_to_node(node: Node, cert_id: int, cf: pem.CertFiles, force: bool, run: Run) -> None:
    nid = node.s["id"]
    nice = NICE_PREFIX + cf.domains[0]
    state = db.one("SELECT * FROM sync_state WHERE node_id=? AND cert_id=?", (nid, cert_id)) or {}
    saved_id = state.get("node_cert_id")
    node_cert = saved_id
    saved_cert = node.certs().get(saved_id, {})
    if saved_cert.get("provider") != "other" or saved_cert.get("nice_name") != nice:
        node_cert = node.find_by_name(nice)  # подхватываем ранее созданные (в т.ч. старым certsync)
    need = force or not node_cert or node_cert != saved_id or state.get("sha") != cf.sha
    if not need:
        exp = _parse_dt(node.certs()[node_cert].get("expires_on"))
        if exp and abs((exp - cf.not_after).total_seconds()) > 86400:
            need = True  # на ноде лежит другой сертификат
    if need:
        if not node_cert:
            node_cert = node.c.create_custom_certificate(nice)
            node.certs()[node_cert] = {"id": node_cert, "provider": "other", "nice_name": nice}
            run.ev("info", message("{name}: создан сертификат #{id} «{label}»", name=node.name, id=node_cert, label=nice))
        node.c.upload_certificate(node_cert, cf.fullchain, cf.privkey)
        run.uploaded += 1
        run.ev("info", message("{name}: загружен {domain} -> #{id} (до {expires:%Y-%m-%d %H:%M} UTC)", name=node.name, domain=cf.domains[0], id=node_cert, expires=cf.not_after))
        _set_state(nid, cert_id, node_cert_id=node_cert, sha=cf.sha, synced_at=db.now_iso())
    if node.s["auto_assign"]:
        for h in node.hosts():
            names = h.get("domain_names") or []
            if names and all(pem.covers(cf.domains, n) for n in names) and h.get("certificate_id") != node_cert:
                node.c.set_proxy_host_certificate(int(h["id"]), node_cert)
                h["certificate_id"] = node_cert
                run.assigned += 1
                run.ev("info", message("{name}: прокси-хост #{host_id} ({domains}) -> сертификат #{cert_id}", name=node.name, host_id=h['id'], domains=', '.join(names), cert_id=node_cert))
    _set_state(nid, cert_id, node_cert_id=node_cert, expires_at=cf.not_after.isoformat(),
               status="ok", message="")


def run_sync(trigger: str = "manual", force: bool = False) -> int | None:
    """Возвращает id запуска или None, если синхронизация уже идёт."""
    locale = language()
    if not _run_lock.acquire(blocking=False):
        return None
    token = current_language.set(locale)
    run = None
    try:
        run = Run(message(trigger) + (message(" (принудительно)") if force else ""))
        m = db.master()
        if not m:
            run.finish(message("мастер-сервер не настроен"))
            return run.id
        if not m["enabled"]:
            run.finish(message("мастер «{name}» выключен", name=m['name']))
            return run.id
        node_rows = db.nodes(only_enabled=True)
        if not node_rows:
            run.finish(message("нет включённых нод"))
            return run.id
        try:
            src = Source(m)
            refs = src.list(run)
        except Exception as e:
            run.finish(message("мастер «{name}»: {error}", name=m['name'], error=e))
            return run.id

        auto_new = db.get_setting("auto_include_new") == "1"
        known = {r["cert_id"]: r for r in db.query("SELECT * FROM certs")}
        seen = set()
        nodes = [Node(n) for n in node_rows]
        broken_nodes: dict[int, str] = {}

        for ref in sorted(refs, key=lambda r: r.cert_id):
            seen.add(ref.cert_id)
            row = known.get(ref.cert_id)
            domains = ref.domains or (row["domains"].split(",") if row and row["domains"] else [f"npm-{ref.cert_id}"])
            if not row:
                enabled = 1 if (auto_new and ref.provider != "other") else 0
                db.execute("INSERT INTO certs(cert_id,domains,provider,enabled,seen_at) VALUES(?,?,?,?,?)",
                           (ref.cert_id, ",".join(domains), ref.provider, enabled, db.now_iso()))
                run.ev("info", message("найден новый сертификат npm-{id} ({domains})", id=ref.cert_id, domains=', '.join(domains))
                               + ("" if enabled else message(" — не включён для синхронизации")))
            else:
                enabled = row["enabled"]
                db.execute("UPDATE certs SET domains=?, provider=?, seen_at=? WHERE cert_id=?",
                           (",".join(domains), ref.provider or row["provider"], db.now_iso(), ref.cert_id))
            if not enabled:
                continue

            try:
                full, key = src.fetch(ref, run)
                cf = pem.load(full, key)
            except Exception as e:
                run.ev("error", message("npm-{id} ({domain}): не удалось получить с мастера: {error}", id=ref.cert_id, domain=domains[0], error=e))
                db.execute("UPDATE certs SET status='error', message=? WHERE cert_id=?", (str(e)[:300], ref.cert_id))
                continue
            db.execute("UPDATE certs SET domains=?, expires_at=?, status=?, message='' WHERE cert_id=?",
                       (",".join(cf.domains), cf.not_after.isoformat(),
                        "expired" if cf.expired else "ok", ref.cert_id))
            if cf.expired:
                run.ev("warn", message("npm-{id} ({domain}): истёк {expires:%Y-%m-%d}, пропущен", id=ref.cert_id, domain=cf.domains[0], expires=cf.not_after))
                continue

            for node in nodes:
                nid = node.s["id"]
                if nid in broken_nodes:
                    _set_state(nid, ref.cert_id, status="error", message=broken_nodes[nid])
                    continue
                try:
                    _sync_to_node(node, ref.cert_id, cf, force, run)
                except NPMError as e:
                    msg = str(e)
                    if isinstance(e, NPMAuthError):
                        broken_nodes[nid] = msg
                    run.ev("error", f"{node.name}: {cf.domains[0]}: {msg}")
                    _set_state(nid, ref.cert_id, status="error", message=msg[:300])
                except Exception as e:
                    run.ev("error", f"{node.name}: {cf.domains[0]}: {e.__class__.__name__}: {e}")
                    _set_state(nid, ref.cert_id, status="error", message=str(e)[:300])

        for cid in set(known) - seen:
            db.execute("DELETE FROM certs WHERE cert_id=?", (cid,))
            db.execute("DELETE FROM sync_state WHERE cert_id=?", (cid,))
            run.ev("info", message("npm-{id} больше нет на мастере, убран из списка (на нодах не удаляется)", id=cid))
        run.finish()
        return run.id
    except Exception as e:  # защита от непредвиденного
        log.exception("sync crashed")
        if run:
            run.finish(message("внутренняя ошибка: {type}: {error}", type=e.__class__.__name__, error=e))
        return run.id if run else None
    finally:
        current_language.reset(token)
        _run_lock.release()


def start_background(trigger: str, force: bool = False) -> bool:
    if is_running():
        return False
    threading.Thread(target=run_sync, args=(trigger, force), daemon=True).start()
    return True

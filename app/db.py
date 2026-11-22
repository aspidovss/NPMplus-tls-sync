"""SQLite-хранилище настроек, состояния синхронизации и журнала."""
import os
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.environ.get("DB_PATH", "/data/nmpsync.db")
_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers(
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT NOT NULL,
  url          TEXT NOT NULL,
  username     TEXT NOT NULL DEFAULT '',
  password_enc TEXT NOT NULL DEFAULT '',
  verify_tls   INTEGER NOT NULL DEFAULT 1,
  role         TEXT NOT NULL CHECK(role IN ('master','node')),
  enabled      INTEGER NOT NULL DEFAULT 1,
  auto_assign  INTEGER NOT NULL DEFAULT 0,
  fetch_mode   TEXT NOT NULL DEFAULT 'api' CHECK(fetch_mode IN ('api','auto','ssh')),
  ssh_host     TEXT NOT NULL DEFAULT '',
  ssh_port     INTEGER NOT NULL DEFAULT 22,
  ssh_user     TEXT NOT NULL DEFAULT 'root',
  ssh_key_enc  TEXT NOT NULL DEFAULT ''
);
-- сертификаты, найденные на мастере
CREATE TABLE IF NOT EXISTS certs(
  cert_id    INTEGER PRIMARY KEY,
  domains    TEXT NOT NULL,
  provider   TEXT NOT NULL DEFAULT '',
  expires_at TEXT,
  enabled    INTEGER NOT NULL,
  seen_at    TEXT,
  status     TEXT NOT NULL DEFAULT '',
  message    TEXT NOT NULL DEFAULT ''
);
-- состояние сертификата на каждой ноде
CREATE TABLE IF NOT EXISTS sync_state(
  node_id      INTEGER NOT NULL,
  cert_id      INTEGER NOT NULL,
  node_cert_id INTEGER,
  sha          TEXT,
  expires_at   TEXT,
  synced_at    TEXT,
  status       TEXT NOT NULL DEFAULT '',
  message      TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(node_id, cert_id)
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT, finished_at TEXT, trigger TEXT, status TEXT, summary TEXT
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER, ts TEXT, level TEXT, message TEXT
);
CREATE INDEX IF NOT EXISTS events_run ON events(run_id);
"""

DEFAULT_SETTINGS = {
    "interval_minutes": "60",
    "auto_include_new": "1",
    "keep_runs": "300",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


def init() -> None:
    with _lock:
        c = _db()
        c.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        c.commit()
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def query(sql: str, args=()) -> list[dict]:
    with _lock:
        return [dict(r) for r in _db().execute(sql, args).fetchall()]


def one(sql: str, args=()) -> dict | None:
    rows = query(sql, args)
    return rows[0] if rows else None


def execute(sql: str, args=()) -> int:
    with _lock:
        c = _db()
        cur = c.execute(sql, args)
        c.commit()
        return cur.lastrowid


def get_setting(key: str) -> str:
    row = one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else DEFAULT_SETTINGS.get(key, "")


def set_setting(key: str, value: str) -> None:
    execute("INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def master() -> dict | None:
    return one("SELECT * FROM servers WHERE role='master'")


def nodes(only_enabled: bool = False) -> list[dict]:
    sql = "SELECT * FROM servers WHERE role='node'"
    if only_enabled:
        sql += " AND enabled=1"
    return query(sql + " ORDER BY name")


def reset_master_state() -> None:
    """Сменился мастер: ID сертификатов больше не валидны."""
    execute("DELETE FROM certs")
    execute("DELETE FROM sync_state")

"""Веб-интерфейс NMP Sync (Starlette + Jinja2)."""
import asyncio
import contextlib
import hmac
import logging
import os
import secrets as pysecrets
import time
from datetime import datetime, timezone

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from . import db, sshsrc, sync, vault
from .npm import NPMError

VERSION = "0.1.0"
BASE = os.path.dirname(__file__)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("nmp-sync")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
STATUS_TOKEN = os.environ.get("STATUS_TOKEN", "")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"

templates = Jinja2Templates(directory=os.path.join(BASE, "templates"))


# --- форматирование ---------------------------------------------------------
def _dt(v):
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def fmt_dt(v) -> str:
    d = _dt(v)
    return d.astimezone().strftime("%d.%m.%Y %H:%M") if d else "—"


def days_left(v):
    d = _dt(v)
    return None if not d else (d - datetime.now(timezone.utc)).total_seconds() / 86400


templates.env.filters["dt"] = fmt_dt
templates.env.globals["days_left"] = days_left
templates.env.globals["version"] = VERSION


# --- сессия, CSRF, flash ---------------------------------------------------
def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = request.session["csrf"] = pysecrets.token_urlsafe(32)
    return tok


def flash(request: Request, msg: str, kind: str = "ok") -> None:
    request.session.setdefault("flash", []).append([kind, msg])


def render(request: Request, name: str, **ctx):
    msgs = request.session.pop("flash", [])
    return templates.TemplateResponse(request, name, {
        "csrf": csrf_token(request), "flashes": msgs, "user": request.session.get("user"),
        "running": sync.is_running(), "path": request.url.path, **ctx})


async def form_checked(request: Request):
    form = await request.form()
    sent = form.get("csrf", "")
    if not sent or not hmac.compare_digest(str(sent), request.session.get("csrf", "")):
        return None
    return form


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


PUBLIC = ("/login", "/static", "/health", "/api/status")


class AuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not scope["path"].startswith(PUBLIC):
            if not scope.get("session", {}).get("user"):
                await RedirectResponse("/login", status_code=303)(scope, receive, send)
                return
        await self.app(scope, receive, send)


# --- вход -----------------------------------------------------------------
async def login(request: Request):
    if request.method == "GET":
        return render(request, "login.html")
    form = await form_checked(request)
    if form is None:
        flash(request, "Сессия устарела, попробуйте ещё раз", "err")
        return redirect("/login")
    user_ok = hmac.compare_digest(str(form.get("username", "")), ADMIN_USER)
    pass_ok = hmac.compare_digest(str(form.get("password", "")).encode(), ADMIN_PASSWORD.encode())
    if user_ok and pass_ok:
        request.session.clear()
        request.session["user"] = ADMIN_USER
        return redirect("/")
    await asyncio.sleep(1.5)
    log.warning("неудачный вход для %r с %s", form.get("username"), request.client.host if request.client else "?")
    flash(request, "Неверный логин или пароль", "err")
    return redirect("/login")


async def logout(request: Request):
    request.session.clear()
    return redirect("/login")


# --- обзор ----------------------------------------------------------------
def _overview():
    certs = db.query("SELECT * FROM certs ORDER BY enabled DESC, domains")
    nodes = db.nodes()
    states = {(s["node_id"], s["cert_id"]): s for s in db.query("SELECT * FROM sync_state")}
    return certs, nodes, states


async def index(request: Request):
    certs, nodes, states = _overview()
    last = db.one("SELECT * FROM runs ORDER BY id DESC LIMIT 1")
    return render(request, "index.html", master=db.master(), nodes=nodes, certs=certs,
                  states=states, last=last, next_run=SCHED.get("next"))


async def sync_now(request: Request):
    form = await form_checked(request)
    if form is None:
        return redirect("/")
    force = form.get("force") == "1"
    if sync.start_background("вручную", force=force):
        flash(request, "Синхронизация запущена" + (" (принудительная перезагрузка всех сертификатов)" if force else ""))
    else:
        flash(request, "Синхронизация уже выполняется", "warn")
    return redirect("/")


# --- серверы --------------------------------------------------------------
async def servers(request: Request):
    return render(request, "servers.html", servers=db.query("SELECT * FROM servers ORDER BY role, name"))


EMPTY_SERVER = {"id": None, "name": "", "url": "https://", "username": "", "password_enc": "",
                "verify_tls": 0, "role": "node", "enabled": 1, "auto_assign": 0, "fetch_mode": "api",
                "ssh_host": "", "ssh_port": 22, "ssh_user": "root", "ssh_key_enc": ""}


async def server_edit(request: Request):
    sid = request.path_params.get("sid")
    srv = db.one("SELECT * FROM servers WHERE id=?", (sid,)) if sid else dict(EMPTY_SERVER)
    if srv is None:
        return redirect("/servers")
    if request.method == "GET":
        return render(request, "server_form.html", s=srv, errors=[])

    form = await form_checked(request)
    if form is None:
        return redirect("/servers")
    f = {k: str(form.get(k, "")).strip() for k in
         ("name", "url", "username", "password", "role", "fetch_mode", "ssh_host", "ssh_port", "ssh_user")}
    f["ssh_key"] = str(form.get("ssh_key", "")).strip()
    checks = {k: 1 if form.get(k) else 0 for k in ("verify_tls", "enabled", "auto_assign")}
    errors = []
    if not f["name"]:
        errors.append("Укажите название")
    if not f["url"].startswith(("http://", "https://")) or len(f["url"]) < 10:
        errors.append("Адрес должен начинаться с http:// или https://")
    if f["role"] not in ("master", "node"):
        errors.append("Неверная роль")
    if f["role"] == "node" or f["fetch_mode"] not in ("api", "auto", "ssh"):
        f["fetch_mode"] = "api"
    needs_api = f["role"] == "node" or f["fetch_mode"] in ("api", "auto")
    has_pass = bool(f["password"] or srv["password_enc"])
    if needs_api and (not f["username"] or not has_pass):
        errors.append("Для API нужны логин (email) и пароль администратора NPMplus")
    if f["role"] == "master":
        other = db.one("SELECT id,name FROM servers WHERE role='master' AND id IS NOT ?", (srv["id"],))
        if other:
            errors.append(f"Мастер уже назначен: «{other['name']}». Сначала переведите его в ноды.")
        if f["fetch_mode"] in ("auto", "ssh"):
            if not f["ssh_host"]:
                errors.append("Для SSH укажите хост")
            if not (f["ssh_key"] or srv["ssh_key_enc"]):
                errors.append("Для SSH вставьте закрытый ключ")
            if f["ssh_key"] and "PRIVATE KEY" not in f["ssh_key"]:
                errors.append("Ключ SSH должен быть в формате OpenSSH/PEM (-----BEGIN ... PRIVATE KEY-----)")
    try:
        port = int(f["ssh_port"] or 22)
        assert 1 <= port <= 65535
    except (ValueError, AssertionError):
        errors.append("Неверный порт SSH")
        port = 22
    if errors:
        srv.update({k: v for k, v in f.items() if k in srv}, **checks, ssh_port=f["ssh_port"])
        return render(request, "server_form.html", s=srv, errors=errors)

    pw_enc = vault.encrypt(f["password"]) if f["password"] else srv["password_enc"]
    key_enc = vault.encrypt(f["ssh_key"]) if f["ssh_key"] else srv["ssh_key_enc"]
    vals = (f["name"], f["url"].rstrip("/"), f["username"], pw_enc, checks["verify_tls"], f["role"],
            checks["enabled"], checks["auto_assign"], f["fetch_mode"], f["ssh_host"], port,
            f["ssh_user"] or "root", key_enc)
    becomes_master = f["role"] == "master" and (srv["role"] != "master" or srv["url"] != f["url"].rstrip("/"))
    stops_master = srv["id"] and srv["role"] == "master" and f["role"] != "master"
    if srv["id"]:
        node_url_changed = srv["role"] == f["role"] == "node" and srv["url"] != vals[1]
        guard = sync.pause_sync() if node_url_changed else contextlib.nullcontext(True)
        with guard as can_update:
            if not can_update:
                flash(request, "Дождитесь завершения синхронизации перед сменой адреса ноды", "warn")
                return redirect(f"/servers/{srv['id']}")
            db.update_server(srv["id"], vals, node_url_changed)
    else:
        db.execute("INSERT INTO servers(name,url,username,password_enc,verify_tls,role,enabled,auto_assign,"
                   "fetch_mode,ssh_host,ssh_port,ssh_user,ssh_key_enc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", vals)
    if becomes_master or stops_master:
        db.reset_master_state()
    flash(request, f"Сервер «{f['name']}» сохранён")
    return redirect("/servers")


async def server_delete(request: Request):
    form = await form_checked(request)
    sid = request.path_params["sid"]
    srv = db.one("SELECT * FROM servers WHERE id=?", (sid,))
    if form is not None and srv:
        db.execute("DELETE FROM servers WHERE id=?", (sid,))
        db.execute("DELETE FROM sync_state WHERE node_id=?", (sid,))
        if srv["role"] == "master":
            db.reset_master_state()
        flash(request, f"Сервер «{srv['name']}» удалён. Сертификаты на самом сервере не тронуты.")
    return redirect("/servers")


def _test_server(srv: dict) -> tuple[bool, str]:
    parts = []
    ok = True
    if srv["role"] == "node" or srv["fetch_mode"] in ("api", "auto"):
        try:
            c = sync.client_for(srv)
            certs = c.list_certificates()
            parts.append(f"API: вход выполнен, сертификатов {len(certs)}")
            if srv["role"] == "master":
                acme = [x for x in certs if x.get("provider") != "other"]
                if acme:
                    c.download_certificate(int(acme[0]["id"]))
                    parts.append(f"скачивание npm-{acme[0]['id']} работает")
            else:
                parts.append(f"прокси-хостов {len(c.list_proxy_hosts())}")
        except Exception as e:
            ok = srv["fetch_mode"] == "auto" and srv["role"] == "master"
            parts.append(f"API: {e}")
    if srv["role"] == "master" and srv["fetch_mode"] in ("auto", "ssh"):
        try:
            ids = sshsrc.list_certs(*sync._ssh_args(srv))
            parts.append(f"SSH: cert-export list вернул {len(ids)} сертификатов")
        except Exception as e:
            ok = False
            parts.append(f"SSH: {e}")
    return ok, "; ".join(parts)


async def server_test(request: Request):
    form = await form_checked(request)
    srv = db.one("SELECT * FROM servers WHERE id=?", (request.path_params["sid"],))
    if form is not None and srv:
        ok, msg = await asyncio.to_thread(_test_server, srv)
        flash(request, f"«{srv['name']}»: {msg}", "ok" if ok else "err")
    return redirect("/servers")


# --- сертификаты ----------------------------------------------------------
async def certs(request: Request):
    if request.method == "POST":
        form = await form_checked(request)
        if form is not None:
            ids = {int(x) for x in form.getlist("enabled")}
            for c in db.query("SELECT cert_id FROM certs"):
                db.execute("UPDATE certs SET enabled=? WHERE cert_id=?", (1 if c["cert_id"] in ids else 0, c["cert_id"]))
            flash(request, "Выбор сертификатов сохранён")
        return redirect("/certs")
    return render(request, "certs.html", certs=db.query("SELECT * FROM certs ORDER BY domains"), master=db.master())


# --- журнал ---------------------------------------------------------------
async def logs(request: Request):
    runs = db.query("SELECT * FROM runs ORDER BY id DESC LIMIT 30")
    rid = request.query_params.get("run")
    run = db.one("SELECT * FROM runs WHERE id=?", (rid,)) if rid else (runs[0] if runs else None)
    events = db.query("SELECT * FROM events WHERE run_id=? ORDER BY id", (run["id"],)) if run else []
    return render(request, "logs.html", runs=runs, run=run, events=events)


# --- настройки ------------------------------------------------------------
async def settings(request: Request):
    if request.method == "POST":
        form = await form_checked(request)
        if form is not None:
            try:
                iv = max(5, min(1440, int(form.get("interval_minutes", 60))))
            except ValueError:
                iv = 60
            db.set_setting("interval_minutes", str(iv))
            db.set_setting("auto_include_new", "1" if form.get("auto_include_new") else "0")
            SCHED["next"] = time.time() + iv * 60 if SCHED.get("next") else None
            flash(request, "Настройки сохранены")
        return redirect("/settings")
    return render(request, "settings.html", interval=db.get_setting("interval_minutes"),
                  auto_new=db.get_setting("auto_include_new") == "1",
                  status_token=bool(STATUS_TOKEN))


# --- служебное ------------------------------------------------------------
async def health(request: Request):
    return PlainTextResponse("ok")


async def api_status(request: Request):
    """JSON для мониторинга (Zabbix HTTP agent). Токен: заголовок X-Token или ?token=."""
    tok = request.headers.get("x-token") or request.query_params.get("token", "")
    if not (STATUS_TOKEN and hmac.compare_digest(tok, STATUS_TOKEN)) and not request.session.get("user"):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    certs, nodes, states = _overview()
    last = db.one("SELECT * FROM runs WHERE status!='running' ORDER BY id DESC LIMIT 1")
    out = []
    for c in certs:
        if not c["enabled"]:
            continue
        dl = days_left(c["expires_at"])
        out.append({
            "cert_id": c["cert_id"], "domains": c["domains"].split(","), "status": c["status"] or "unknown",
            "expires_at": c["expires_at"], "days_left": round(dl, 2) if dl is not None else None,
            "nodes": {n["name"]: (states.get((n["id"], c["cert_id"])) or {}).get("status") or "pending"
                      for n in nodes if n["enabled"]},
        })
    errors = sum(1 for c in out for s in c["nodes"].values() if s == "error") + sum(1 for c in out if c["status"] == "error")
    min_days = min((c["days_left"] for c in out if c["days_left"] is not None and c["status"] != "expired"), default=None)
    return JSONResponse({
        "version": VERSION, "running": sync.is_running(),
        "last_run": last and {k: last[k] for k in ("id", "started_at", "finished_at", "status", "summary")},
        "errors": errors, "min_days_left": min_days, "certs": out})


# --- планировщик ----------------------------------------------------------
SCHED: dict = {"next": None}


async def scheduler():
    SCHED["next"] = time.time() + 60  # первый запуск через минуту после старта
    while True:
        await asyncio.sleep(15)
        if SCHED["next"] and time.time() >= SCHED["next"]:
            iv = int(db.get_setting("interval_minutes") or 60)
            SCHED["next"] = time.time() + iv * 60
            await asyncio.to_thread(sync.run_sync, "по расписанию")


@contextlib.asynccontextmanager
async def lifespan(app):
    db.init()
    db.execute("UPDATE runs SET status='failed', summary='прервано перезапуском' WHERE status='running'")
    task = asyncio.create_task(scheduler())
    log.info("NMP Sync %s запущен", VERSION)
    yield
    task.cancel()


def _check_env():
    problems = []
    if len(vault.app_secret()) < 16:
        problems.append("APP_SECRET не задан или короче 16 символов")
    if len(ADMIN_PASSWORD) < 8:
        problems.append("ADMIN_PASSWORD не задан или короче 8 символов")
    if problems:
        raise SystemExit("Ошибка конфигурации: " + "; ".join(problems))


_check_env()

routes = [
    Route("/", index),
    Route("/login", login, methods=["GET", "POST"]),
    Route("/logout", logout, methods=["POST"]),
    Route("/sync", sync_now, methods=["POST"]),
    Route("/servers", servers),
    Route("/servers/new", server_edit, methods=["GET", "POST"]),
    Route("/servers/{sid:int}", server_edit, methods=["GET", "POST"]),
    Route("/servers/{sid:int}/delete", server_delete, methods=["POST"]),
    Route("/servers/{sid:int}/test", server_test, methods=["POST"]),
    Route("/certs", certs, methods=["GET", "POST"]),
    Route("/logs", logs),
    Route("/settings", settings, methods=["GET", "POST"]),
    Route("/health", health),
    Route("/api/status", api_status),
    Mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static"),
]

app = Starlette(
    routes=routes,
    lifespan=lifespan,
    middleware=[
        Middleware(SessionMiddleware, secret_key="nmpsync-session:" + vault.app_secret(),
                   session_cookie="nmpsync", max_age=12 * 3600, same_site="strict", https_only=COOKIE_SECURE),
        Middleware(AuthMiddleware),
    ],
)

"""Сквозная проверка против dev/mock_npm.py (мастер :9001 cookie, нода :9002 bearer, приложение :8080)."""
import re
import sys
import time

import requests

APP = "http://127.0.0.1:8080"
s = requests.Session()
fails = 0


def check(cond, msg):
    global fails
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        fails += 1


def csrf(path="/"):
    html = s.get(APP + path).text
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def post(path, data, page=None):
    data = {**data, "csrf": csrf(page or path)}
    return s.post(APP + path, data=data, allow_redirects=True)


def wait_sync():
    for _ in range(100):
        time.sleep(0.2)
        st = s.get(APP + "/api/status").json()
        if not st["running"]:
            return st
    raise SystemExit("sync hang")


def node():
    return requests.get("http://127.0.0.1:9002/_debug").json()


# вход
r = post("/login", {"username": "admin", "password": "wrong"}, "/login")
check("Неверный логин" in r.text, "неверный пароль отклонён")
r = post("/login", {"username": "admin", "password": "adminpass1"}, "/login")
check("Обзор" in r.text, "вход выполнен")
check(s.post(APP + "/sync", data={"csrf": "bad"}).url.endswith("/"), "POST без CSRF не запускает синхронизацию")

# серверы
r = post("/servers/new", {"name": "VM", "role": "master", "url": "http://127.0.0.1:9001",
                          "username": "admin@example.com", "password": "secret123", "fetch_mode": "api",
                          "enabled": "on", "ssh_port": "22", "ssh_user": "root"}, "/servers/new")
check("сохранён" in r.text, "мастер добавлен")
r = post("/servers/new", {"name": "VM2", "role": "master", "url": "http://127.0.0.1:9003",
                          "username": "x", "password": "y", "fetch_mode": "api", "enabled": "on",
                          "ssh_port": "22"}, "/servers/new")
check("Мастер уже назначен" in r.text, "второй мастер запрещён")
r = post("/servers/new", {"name": "DietPi", "role": "node", "url": "http://127.0.0.1:9002",
                          "username": "admin@example.com", "password": "secret123", "enabled": "on",
                          "auto_assign": "on", "ssh_port": "22"}, "/servers/new")
check("сохранён" in r.text, "нода добавлена")
r = post("/servers/1/test", {}, "/servers")
check("скачивание npm-2 работает" in r.text, "проверка мастера: " + re.search(r'class="flash[^"]*">([^<]+)', r.text).group(1))
r = post("/servers/2/test", {}, "/servers")
check("прокси-хостов 4" in r.text, "проверка ноды: " + re.search(r'class="flash[^"]*">([^<]+)', r.text).group(1))

# 1-я синхронизация
post("/sync", {}, "/")
st = wait_sync()
print("   run:", st["last_run"]["summary"], st["last_run"]["status"])
n = node()
syncs = {c["nice_name"]: c for c in n["certs"] if c["nice_name"].startswith("sync: ")}
check(set(syncs) == {"sync: cloud.example.ru", "sync: c.example.ru", "sync: git.example.ru", "sync: *.wild.example.ru"},
      f"на ноде созданы sync-сертификаты: {sorted(syncs)}")
check(syncs["sync: c.example.ru"]["id"] == 4, "старый сертификат «sync: c.example.ru» (#4) подхвачен, а не продублирован")
check(not any("old.example.ru" in c["nice_name"] for c in n["certs"]), "просроченный old.example.ru не загружен")
check(not any("m.example.ru" in c["nice_name"] for c in n["certs"]), "Custom-сертификат мастера не включён по умолчанию")
hosts = {h["id"]: h["certificate_id"] for h in n["hosts"]}
check(hosts[1] == syncs["sync: cloud.example.ru"]["id"], "хост cloud привязан")
check(hosts[2] == syncs["sync: git.example.ru"]["id"], "хост git (2 домена) перепривязан")
check(hosts[3] == syncs["sync: *.wild.example.ru"]["id"], "хост под wildcard привязан")
check(hosts[4] == 0, "чужой хост не тронут")
check(st["errors"] == 0 and st["last_run"]["status"] == "ok", "без ошибок")

# 2-я синхронизация — без изменений
before = {c["id"]: c["uploads"] for c in node()["certs"]}
post("/sync", {}, "/")
st = wait_sync()
after = {c["id"]: c["uploads"] for c in node()["certs"]}
check(before == after, "повторный запуск ничего не загружает")

# ротация сертификата на мастере
requests.post("http://127.0.0.1:9001/_debug", json={"cid": 2, "days": 6})
post("/sync", {}, "/")
st = wait_sync()
after2 = {c["id"]: c["uploads"] for c in node()["certs"]}
changed = [k for k in after2 if after2[k] != after.get(k)]
check(changed == [syncs["sync: cloud.example.ru"]["id"]], f"после обновления на мастере загружен только cloud: {changed}")

# отключение сертификата
html = s.get(APP + "/certs").text
ids = re.findall(r'name="enabled" value="(\d+)" checked', html)
keep = [i for i in ids if i != "4"]
post("/certs", {"enabled": keep}, "/certs")
html = s.get(APP + "/certs").text
check('value="4" checked' not in html and 'value="2" checked' in html, "выбор сертификатов сохраняется")

# принудительная
post("/sync", {"force": "1"}, "/")
st = wait_sync()
print("   force:", st["last_run"]["summary"])
check("загружено: 3" in st["last_run"]["summary"], "принудительный запуск перезагрузил 3 включённых действующих")

# статус для мониторинга
st = s.get(APP + "/api/status").json()
check(st["min_days_left"] is not None and len(st["certs"]) == 4 and any(c["status"] == "expired" for c in st["certs"]), f"api/status: min_days_left={st['min_days_left']}")
check(requests.get(APP + "/api/status").status_code == 401, "api/status без входа/токена закрыт")

# страницы рендерятся
for p in ("/", "/servers", "/servers/1", "/servers/2", "/certs", "/logs", "/settings"):
    check(s.get(APP + p).status_code == 200, f"страница {p}")

# неверный пароль ноды -> ошибка в статусе, мастер не ломается
post("/servers/2", {"name": "DietPi", "role": "node", "url": "http://127.0.0.1:9002",
                    "username": "admin@example.com", "password": "WRONG", "enabled": "on", "ssh_port": "22"}, "/servers/2")
requests.post("http://127.0.0.1:9001/_debug", json={"cid": 11, "days": 6})
post("/sync", {}, "/")
st = wait_sync()
check(st["last_run"]["status"] == "partial" and st["errors"] >= 1, f"ошибка входа на ноду видна: {st['last_run']['summary']}")

print("\nИТОГО:", "все проверки пройдены" if not fails else f"провалено {fails}")
sys.exit(1 if fails else 0)

"""Минимальный mock API NPMplus для локальной проверки.

  python -m dev.mock_npm --port 9001 --role master --auth cookie
  python -m dev.mock_npm --port 9002 --role node   --auth bearer
"""
import argparse
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

USER, PASSWORD = "admin@example.com", "secret123"


def make_cert(domains, days):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    nb = now - timedelta(days=7) if days > 0 else now + timedelta(days=days - 90)
    na = now + timedelta(days=days)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([])).issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "mock CA")]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
            .sign(key, hashes.SHA256()))
    full = cert.public_bytes(serialization.Encoding.PEM) * 2
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return full, priv, na


def build(role, auth):
    state = {"certs": {}, "hosts": [], "next": 1}
    if role == "master":
        for cid, doms, days in [(2, ["cloud.example.ru"], 3.5), (4, ["c.example.ru"], 3), (7, ["old.example.ru"], -150),
                                (11, ["git.example.ru", "www.git.example.ru"], 6), (12, ["*.wild.example.ru"], 5)]:
            full, priv, na = make_cert(doms, days)
            state["certs"][cid] = {"id": cid, "provider": "letsencrypt", "nice_name": doms[0], "domain_names": doms,
                                   "expires_on": na.strftime("%Y-%m-%d %H:%M:%S"), "_full": full, "_key": priv}
        state["certs"][20] = {"id": 20, "provider": "other", "nice_name": "manual", "domain_names": ["m.example.ru"],
                              "expires_on": None, "_full": b"", "_key": b""}
    else:
        state["next"] = 5
        state["hosts"] = [
            {"id": 1, "domain_names": ["cloud.example.ru"], "certificate_id": 0},
            {"id": 2, "domain_names": ["git.example.ru", "www.git.example.ru"], "certificate_id": 3},
            {"id": 3, "domain_names": ["a.wild.example.ru"], "certificate_id": 0},
            {"id": 4, "domain_names": ["other.example.com"], "certificate_id": 0},
        ]
        # сертификат, созданный старым certsync — должен быть подхвачен по имени
        state["certs"][4] = {"id": 4, "provider": "other", "nice_name": "sync: c.example.ru", "domain_names": [], "expires_on": None}

    def authed(req: Request):
        if auth == "cookie":
            return req.cookies.get("token") == "tok"
        return req.headers.get("authorization") == "Bearer tok"

    def pub(c):
        return {k: v for k, v in c.items() if not k.startswith("_")}

    async def tokens(req: Request):
        d = await req.json()
        if d.get("identity") != USER or d.get("secret") != PASSWORD:
            return JSONResponse({"error": {"message": "Invalid email or password"}}, 401)
        if auth == "cookie":
            r = JSONResponse({"expires": "2099-01-01"})
            r.set_cookie("token", "tok", httponly=True)
            return r
        return JSONResponse({"token": "tok", "expires": "2099-01-01"})

    async def certs(req: Request):
        if not authed(req):
            return JSONResponse({"error": "auth"}, 401)
        if req.method == "GET":
            return JSONResponse([pub(c) for c in state["certs"].values()])
        d = await req.json()
        cid = state["next"]; state["next"] += 1
        state["certs"][cid] = {"id": cid, "provider": d["provider"], "nice_name": d["nice_name"], "domain_names": [], "expires_on": None}
        return JSONResponse(pub(state["certs"][cid]), 201)

    async def download(req: Request):
        if not authed(req):
            return JSONResponse({"error": "auth"}, 401)
        c = state["certs"].get(req.path_params["cid"])
        if not c or c["provider"] == "other":
            return JSONResponse({"error": {"message": "Only Let'sEncrypt certificates can be downloaded"}}, 400)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            n = c["id"]
            z.writestr(f"fullchain{n}.pem", c["_full"]); z.writestr(f"privkey{n}.pem", c["_key"])
            z.writestr(f"cert{n}.pem", c["_full"])
        return Response(buf.getvalue(), media_type="application/zip")

    async def upload(req: Request):
        if not authed(req):
            return JSONResponse({"error": "auth"}, 401)
        c = state["certs"].get(req.path_params["cid"])
        if not c:
            return JSONResponse({"error": "not found"}, 404)
        form = await req.form()
        full = await form["certificate"].read(); key = await form["certificate_key"].read()
        cert = x509.load_pem_x509_certificate(full)
        c["expires_on"] = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
        c["domain_names"] = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        c["_uploads"] = c.get("_uploads", 0) + 1
        return JSONResponse({"certificate": "ok"})

    async def hosts(req: Request):
        if not authed(req):
            return JSONResponse({"error": "auth"}, 401)
        return JSONResponse(state["hosts"])

    async def host_put(req: Request):
        if not authed(req):
            return JSONResponse({"error": "auth"}, 401)
        d = await req.json()
        for h in state["hosts"]:
            if h["id"] == req.path_params["hid"]:
                h["certificate_id"] = d["certificate_id"]
                return JSONResponse(h)
        return JSONResponse({"error": "not found"}, 404)

    async def debug(req: Request):  # для теста: состояние и ротация сертификата мастера
        if req.method == "POST":
            d = await req.json()
            c = state["certs"][d["cid"]]
            c["_full"], c["_key"], na = make_cert(c["domain_names"], d.get("days", 6))
            c["expires_on"] = na.strftime("%Y-%m-%d %H:%M:%S")
        return JSONResponse({"certs": [{**pub(c), "uploads": c.get("_uploads", 0)} for c in state["certs"].values()],
                             "hosts": state["hosts"]})

    return Starlette(routes=[
        Route("/api/tokens", tokens, methods=["POST"]),
        Route("/api/nginx/certificates", certs, methods=["GET", "POST"]),
        Route("/api/nginx/certificates/{cid:int}/download", download),
        Route("/api/nginx/certificates/{cid:int}/upload", upload, methods=["POST"]),
        Route("/api/nginx/proxy-hosts", hosts),
        Route("/api/nginx/proxy-hosts/{hid:int}", host_put, methods=["PUT"]),
        Route("/_debug", debug, methods=["GET", "POST"]),
    ])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--role", choices=["master", "node"], required=True)
    ap.add_argument("--auth", choices=["cookie", "bearer"], default="bearer")
    a = ap.parse_args()
    uvicorn.run(build(a.role, a.auth), host="127.0.0.1", port=a.port, log_level="warning")

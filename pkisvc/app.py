"""
pkisvc/app.py -- service PKI post-quantique du simulateur (v2).

Un seul conteneur porte la PKI de l'architecture (figure 3.2 du memoire) :
  * l'autorite de certification (CA racine, un seul niveau), dont la cle
    privee ne quitte jamais ce conteneur ;
  * l'inscription des composants (POST /enroll) : chaque composant envoie sa
    CSR avec un jeton qui lui est propre ; la CA impose le CN et le SAN ;
  * la base des certificats (index.txt au format OpenSSL) et la revocation
    (POST /revoke, reservee a l'administrateur ou au PA) ;
  * le repondeur OCSP : `openssl ocsp` (signature CROSS ou RSA selon le mode)
    ecoute en local ; il est expose aux autres composants derriere TLS 1.3
    post-quantique (POST /ocsp), comme tout lien du plan de controle (ES2).

Le certificat de la CA est publie dans /trust (volume partage en lecture
seule) : c'est l'ancre de confiance distribuee a tous les composants.
"""

import datetime
import logging
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

import requests
from flask import Flask, Response, jsonify, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [pki] %(message)s")
log = logging.getLogger("pki")

DATA = os.environ.get("PKI_DATA", "/pki-data")
TRUST = os.environ.get("PKI_TRUST_DIR", "/trust")
KEY_ALG = os.environ.get("PKI_KEY_ALG", "CROSSrsdp128balanced")
CA_DAYS = int(os.environ.get("CA_DAYS", "1095"))          # 3 ans (SP 800-57)
CERT_DAYS = int(os.environ.get("CERT_DAYS", "2"))         # identifiants courts
OCSP_DAYS = int(os.environ.get("OCSP_DAYS", "30"))
OCSP_NMIN = os.environ.get("OCSP_NEXT_UPDATE_MIN", "5")
DOMAIN = os.environ.get("ZT_DOMAIN", "ztpqc.lab")
PORT = int(os.environ.get("PKI_PORT", "8447"))
PUBLIC_URL = os.environ.get("PKI_PUBLIC_URL", "https://pki.%s:%d" % (DOMAIN, PORT))
ADMIN_TOKEN = os.environ.get("PKI_ADMIN_TOKEN", "")
# "idp:jeton1,pep:jeton2,..." : un jeton d'inscription par composant.
TOKENS = dict(p.split(":", 1) for p in os.environ.get("ENROLL_TOKENS", "").split(",") if ":" in p)

CA_KEY = os.path.join(DATA, "ca.key")
CA_CRT = os.path.join(DATA, "ca.cert.pem")
INDEX = os.path.join(DATA, "index.txt")

_lock = threading.Lock()
_stats = {"enrolled": 0, "revoked": 0, "ocsp_requests": 0, "ocsp_bytes_out": 0}


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, **kw)


def genkey(path):
    if KEY_ALG.lower().startswith("rsa:"):
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
             "rsa_keygen_bits:" + KEY_ALG.split(":", 1)[1], "-out", path])
    else:
        run(["openssl", "genpkey", "-algorithm", KEY_ALG, "-out", path])
    os.chmod(path, 0o600)


# --------------------------------------------------------------- CA -------

def init_ca():
    os.makedirs(DATA, exist_ok=True)
    if not os.path.exists(CA_CRT):
        log.info("creation de la CA racine (%s, %d jours)", KEY_ALG, CA_DAYS)
        genkey(CA_KEY)
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as f:
            f.write("[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=v3\n"
                    "[dn]\nC=SN\nO=PQC-ZeroTrust-Thesis\nCN=ca.%s\n"
                    "[v3]\nbasicConstraints=critical,CA:true\n"
                    "keyUsage=critical,keyCertSign,cRLSign\n"
                    "subjectKeyIdentifier=hash\n" % DOMAIN)
            cnf = f.name
        run(["openssl", "req", "-new", "-x509", "-key", CA_KEY, "-out", CA_CRT,
             "-days", str(CA_DAYS), "-config", cnf])
        os.unlink(cnf)
        open(INDEX, "w").close()
    # Publication atomique de l'ancre de confiance.
    os.makedirs(TRUST, exist_ok=True)
    tmp = os.path.join(TRUST, ".ca.tmp")
    shutil.copyfile(CA_CRT, tmp)
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(TRUST, "ca.cert.pem"))


def _index_date(openssl_date: str) -> str:
    d = datetime.datetime.strptime(openssl_date.strip(), "%b %d %H:%M:%S %Y %Z")
    return d.strftime("%y%m%d%H%M%SZ")


def sign_csr(name: str, csr_pem: str, profile: str = "entity", days: int = None) -> str:
    """Signe une CSR. Le CN et le SAN sont imposes par la CA."""
    days = days or CERT_DAYS
    with tempfile.TemporaryDirectory() as d:
        csr = os.path.join(d, "req.csr")
        crt = os.path.join(d, "out.crt")
        ext = os.path.join(d, "ext.cnf")
        with open(csr, "w") as f:
            f.write(csr_pem)
        # La CSR doit etre auto-signee (preuve de possession de la cle).
        run(["openssl", "req", "-in", csr, "-verify", "-noout"])
        subj = run(["openssl", "req", "-in", csr, "-noout", "-subject", "-nameopt", "compat"]
                   ).stdout.decode().strip()
        if subj not in ("subject=/CN=%s" % name, "subject=CN=%s" % name):
            raise ValueError("CN de la CSR inattendu : %s" % subj)
        lines = ["basicConstraints=critical,CA:false",
                 "subjectKeyIdentifier=hash",
                 "authorityKeyIdentifier=keyid"]
        if profile == "ocsp":
            lines += ["keyUsage=critical,digitalSignature",
                      "extendedKeyUsage=critical,OCSPSigning",
                      "noCheck=ignored"]
        else:
            lines += ["keyUsage=critical,digitalSignature",
                      "extendedKeyUsage=serverAuth,clientAuth",
                      "subjectAltName=DNS:%s.%s" % (name, DOMAIN),
                      "authorityInfoAccess=OCSP;URI:%s/ocsp" % PUBLIC_URL]
        with open(ext, "w") as f:
            f.write("\n".join(lines) + "\n")
        serial = "0x" + secrets.token_hex(15)
        with _lock:
            run(["openssl", "x509", "-req", "-in", csr, "-CA", CA_CRT, "-CAkey", CA_KEY,
                 "-set_serial", serial, "-days", str(days), "-extfile", ext, "-out", crt])
            ser = run(["openssl", "x509", "-in", crt, "-noout", "-serial"]).stdout.decode()
            ser = ser.strip().split("=", 1)[1].upper()
            end = run(["openssl", "x509", "-in", crt, "-noout", "-enddate"]).stdout.decode()
            end = _index_date(end.strip().split("=", 1)[1])
            with open(INDEX, "a") as f:
                f.write("V\t%s\t\t%s\tunknown\t/CN=%s\n" % (end, ser, name))
        with open(crt) as f:
            return f.read()


def issue_local(name: str, profile: str, days: int):
    """Certificats propres au service PKI (TLS et signature OCSP)."""
    key = os.path.join(DATA, name + ".key")
    crt = os.path.join(DATA, name + ".crt")
    if not os.path.exists(crt):
        genkey(key)
        csr = run(["openssl", "req", "-new", "-key", key, "-subj", "/CN=" + name]).stdout.decode()
        with open(crt, "w") as f:
            f.write(sign_csr(name, csr, profile, days))
    return crt, key


# ------------------------------------------------------ repondeur OCSP ----
# Chaque requete OCSP est traitee par un appel a `openssl ocsp -reqin/-respout`
# (meme code que le serveur `openssl ocsp -port`, qui se bloque avec des
# clients HTTP/1.1 et ne relit pas index.txt). L'index est relu a chaque appel :
# une revocation est visible des la requete suivante.

def ocsp_respond(req_der: bytes) -> bytes:
    ocsp_crt, ocsp_key = os.path.join(DATA, "ocsp.crt"), os.path.join(DATA, "ocsp.key")
    with tempfile.TemporaryDirectory() as d:
        rq, rs = os.path.join(d, "req.der"), os.path.join(d, "resp.der")
        with open(rq, "wb") as f:
            f.write(req_der)
        with _lock:                      # lecture coherente de l'index
            run(["openssl", "ocsp", "-index", INDEX, "-reqin", rq, "-respout", rs,
                 "-rsigner", ocsp_crt, "-rkey", ocsp_key, "-CA", CA_CRT,
                 "-nmin", OCSP_NMIN], timeout=20)
        with open(rs, "rb") as f:
            return f.read()


def revoke(name: str = None, serial: str = None) -> list:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%y%m%d%H%M%SZ")
    done = []
    with _lock:
        out = []
        with open(INDEX) as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if p[0] == "V" and ((serial and p[3] == serial.upper()) or
                                    (name and p[5] == "/CN=" + name)):
                    p[0], p[2] = "R", now
                    done.append(p[3])
                out.append("\t".join(p) + "\n")
        with open(INDEX, "w") as f:
            f.writelines(out)
    return done


# ------------------------------------------------------------- API -------

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "pki", "alg": KEY_ALG, **_stats})


@app.get("/ca.pem")
def ca_pem():
    with open(CA_CRT) as f:
        return Response(f.read(), mimetype="application/x-pem-file")


@app.post("/enroll")
def enroll():
    body = request.get_json(silent=True) or {}
    name, token, csr = body.get("name"), body.get("token"), body.get("csr")
    if not name or name not in TOKENS or not secrets.compare_digest(TOKENS[name], token or ""):
        log.warning("inscription refusee pour %r", name)
        return jsonify({"error": "enrollment_denied"}), 403
    try:
        cert = sign_csr(name, csr)
    except (ValueError, subprocess.CalledProcessError) as exc:
        return jsonify({"error": "bad_csr", "detail": str(exc)}), 400
    _stats["enrolled"] += 1
    log.info("certificat emis pour %s", name)
    return jsonify({"certificate": cert})


@app.post("/revoke")
def revoke_route():
    body = request.get_json(silent=True) or {}
    if not ADMIN_TOKEN or not secrets.compare_digest(ADMIN_TOKEN, body.get("token") or ""):
        return jsonify({"error": "forbidden"}), 403
    serials = revoke(body.get("name"), body.get("serial"))
    _stats["revoked"] += len(serials)
    log.info("revocation : %s", serials)
    return jsonify({"revoked": serials})


@app.post("/ocsp")
def ocsp():
    t0 = time.perf_counter()
    try:
        resp = ocsp_respond(request.get_data())
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        log.warning("OCSP : %s", exc)
        return jsonify({"error": "ocsp_failed"}), 500
    _stats["ocsp_requests"] += 1
    _stats["ocsp_bytes_out"] += len(resp)
    _stats["ocsp_sign_ms_total"] = _stats.get("ocsp_sign_ms_total", 0.0) + (time.perf_counter() - t0) * 1000
    return Response(resp, mimetype="application/ocsp-response")


def build_ssl_context(crt, key):
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    return ctx


if __name__ == "__main__":
    init_ca()
    tls_crt, tls_key = issue_local("pki", "entity", CA_DAYS)
    issue_local("ocsp", "ocsp", OCSP_DAYS)
    log.info("PKI prete : CA=%s, API %s", KEY_ALG, PUBLIC_URL)
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from common import keepalive_server
    keepalive_server.serve(app, "0.0.0.0", PORT, build_ssl_context(tls_crt, tls_key),
                           conn_log=os.environ.get("ZT_DEBUG_CONNS") == "1")

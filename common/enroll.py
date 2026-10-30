"""
enroll.py -- inscription d'un composant aupres du service PKI (v2).

Chaque composant genere SA paire de cles localement (la cle privee ne quitte
jamais le conteneur), construit une demande de certificat (CSR) et l'envoie
au service PKI avec un jeton d'inscription qui lui est propre. La PKI choisit
elle-meme le nom (CN) et le SAN du certificat a partir de l'identite associee
au jeton : un composant ne peut pas demander un certificat au nom d'un autre.

Seul le certificat de l'autorite (ancre de confiance) est partage entre les
conteneurs, en lecture seule.
"""

import json
import logging
import os
import subprocess
import time
import urllib.request
import ssl

logger = logging.getLogger("enroll")

PKI_URL = os.environ.get("PKI_URL", "https://pki.ztpqc.lab:8447")
CA_CERT = os.environ.get("CA_CERT", "/trust/ca.cert.pem")
KEY_ALG = os.environ.get("PKI_KEY_ALG", "CROSSrsdp128balanced")
OUT_DIR = os.environ.get("ZT_CRED_DIR", "/run/zt")


def _genkey(path: str):
    if KEY_ALG.lower().startswith("rsa:"):
        bits = KEY_ALG.split(":", 1)[1]
        cmd = ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:" + bits]
    else:
        cmd = ["openssl", "genpkey", "-algorithm", KEY_ALG]
    subprocess.run(cmd + ["-out", path], check=True, capture_output=True)
    os.chmod(path, 0o600)


def _wait_for_ca(timeout: float):
    t0 = time.time()
    while not os.path.exists(CA_CERT):
        if time.time() - t0 > timeout:
            raise RuntimeError("ancre de confiance absente : %s" % CA_CERT)
        time.sleep(0.5)


def enroll(name: str, token: str = None, timeout: float = 120.0) -> tuple:
    """Retourne (chemin_certificat, chemin_cle) pour le composant `name`."""
    token = token or os.environ.get("ENROLL_TOKEN", "")
    os.makedirs(OUT_DIR, exist_ok=True)
    key = os.path.join(OUT_DIR, name + ".key")
    crt = os.path.join(OUT_DIR, name + ".crt")
    _wait_for_ca(timeout)

    _genkey(key)
    csr = subprocess.run(
        ["openssl", "req", "-new", "-key", key, "-subj", "/CN=" + name],
        check=True, capture_output=True).stdout.decode()

    ctx = ssl.create_default_context(cafile=CA_CERT)
    body = json.dumps({"name": name, "token": token, "csr": csr}).encode()
    t0 = time.time()
    while True:
        try:
            req = urllib.request.Request(PKI_URL + "/enroll", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
                cert_pem = json.loads(r.read())["certificate"]
            break
        except Exception as exc:  # PKI pas encore prete : on reessaie
            if time.time() - t0 > timeout:
                raise RuntimeError("inscription impossible aupres de %s : %s" % (PKI_URL, exc))
            time.sleep(1)

    with open(crt, "w") as f:
        f.write(cert_pem)
    logger.info("certificat obtenu aupres de la PKI pour %s (%d o PEM)", name, len(cert_pem))
    return crt, key

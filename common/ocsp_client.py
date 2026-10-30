"""
ocsp_client.py -- verification du statut de revocation par OCSP (v2).

Utilise par le PEP pour chaque sujet authentifie par certificat (mTLS).

Etapes, toutes obligatoires (refus par defaut) :
  1. construire une requete OCSP (CertID SHA-1 : hash du nom et de la cle de
     l'emetteur, numero de serie) ;
  2. l'envoyer au repondeur de la PKI, sur TLS 1.3 post-quantique ;
  3. verifier la reponse : certificat du repondeur emis par la CA et reserve
     a la signature OCSP, signature de la reponse, CertID, fraicheur
     (thisUpdate / nextUpdate) ;
  4. conserver le statut en cache pendant min(OCSP_CACHE_TTL, nextUpdate).

Le delai maximal de prise en compte d'une revocation est donc borne par
OCSP_CACHE_TTL (chapitre 2, verification continue).
"""

import datetime
import hashlib
import os
import threading
import time

import requests
from asn1crypto import ocsp

from common import x509util

OCSP_URL = os.environ.get("OCSP_URL", "https://pki.ztpqc.lab:8447/ocsp")
OCSP_ENABLED = os.environ.get("OCSP_ENABLED", "1") == "1"
OCSP_CACHE_TTL = float(os.environ.get("OCSP_CACHE_TTL", "60"))
OCSP_TIMEOUT = float(os.environ.get("OCSP_TIMEOUT", "3.0"))
CLOCK_SKEW = datetime.timedelta(seconds=60)


class RevocationError(Exception):
    """Certificat revoque, inconnu, ou statut impossible a etablir."""


class OCSPChecker:
    def __init__(self, ca_cert_path: str, client_cert=None, verify=None):
        self.ca = x509util.load_cert_file(ca_cert_path)
        self.ca_name_hash = hashlib.sha1(x509util.subject_der(self.ca)).digest()
        self.ca_key_hash = x509util.key_hash_sha1(self.ca)
        self.session = requests.Session()
        self.session.verify = verify or ca_cert_path
        if client_cert:
            self.session.cert = client_cert
        self._cache = {}            # serial -> (status, expires_at)
        self._lock = threading.Lock()
        self._trusted_responders = {}   # empreinte DER -> True
        self.stats = {"checks": 0, "cache_hits": 0, "fetches": 0,
                      "fetch_ms_total": 0.0, "bytes_total": 0, "last_size": 0}

    # ------------------------------------------------------------------
    def check(self, cert_der: bytes) -> str:
        """Retourne 'good' ou leve RevocationError."""
        if not OCSP_ENABLED:
            return "disabled"
        cert = x509util.load_cert(cert_der)
        serial = cert.serial_number
        now = time.time()
        with self._lock:
            self.stats["checks"] += 1
            hit = self._cache.get(serial)
            if hit and hit[1] > now:
                self.stats["cache_hits"] += 1
                status = hit[0]
                if status != "good":
                    raise RevocationError("certificat %s : %s (cache)" % (hex(serial), status))
                return status

        status, next_update = self._fetch(cert)
        expires = now + OCSP_CACHE_TTL
        if next_update is not None:
            expires = min(expires, next_update.timestamp())
        with self._lock:
            self._cache[serial] = (status, expires)
        if status != "good":
            raise RevocationError("certificat %s : %s" % (hex(serial), status))
        return status

    # ------------------------------------------------------------------
    def _fetch(self, cert):
        req = ocsp.OCSPRequest({"tbs_request": {"request_list": [{"req_cert": {
            "hash_algorithm": {"algorithm": "sha1"},
            "issuer_name_hash": self.ca_name_hash,
            "issuer_key_hash": self.ca_key_hash,
            "serial_number": cert.serial_number}}]}})
        t0 = time.perf_counter()
        try:
            r = self.session.post(OCSP_URL, data=req.dump(), timeout=OCSP_TIMEOUT,
                                  headers={"Content-Type": "application/ocsp-request"})
            r.raise_for_status()
        except requests.RequestException as exc:
            raise RevocationError("repondeur OCSP injoignable : %s" % exc)
        elapsed = (time.perf_counter() - t0) * 1000
        with self._lock:
            self.stats["fetches"] += 1
            self.stats["fetch_ms_total"] += elapsed
            self.stats["bytes_total"] += len(r.content)
            self.stats["last_size"] = len(r.content)
        return self._verify(r.content, cert.serial_number)

    def _verify(self, der: bytes, serial: int):
        try:
            resp = ocsp.OCSPResponse.load(der)
            if resp["response_status"].native != "successful":
                raise RevocationError("reponse OCSP : %s" % resp["response_status"].native)
            basic = resp["response_bytes"]["response"].parsed
            tbs = basic["tbs_response_data"]

            # Repondeur delegue : certificat emis par la CA et reserve a OCSP.
            certs = basic["certs"]
            if not certs:
                raise RevocationError("reponse OCSP sans certificat de repondeur")
            responder = certs[0]
            fp = hashlib.sha256(responder.dump()).digest()
            if fp not in self._trusted_responders:
                if not x509util.verify_cert_issued_by(responder, self.ca):
                    raise RevocationError("certificat du repondeur non emis par la CA")
                eku = responder.extended_key_usage_value
                if eku is None or "ocsp_signing" not in eku.native:
                    raise RevocationError("certificat du repondeur sans usage OCSPSigning")
                self._trusted_responders[fp] = True

            if not x509util.verify_signature(tbs.dump(), basic["signature"].native,
                                             basic["signature_algorithm"], responder):
                raise RevocationError("signature de la reponse OCSP invalide")

            single = tbs["responses"][0]
            cid = single["cert_id"]
            if (cid["serial_number"].native != serial
                    or cid["issuer_name_hash"].native != self.ca_name_hash
                    or cid["issuer_key_hash"].native != self.ca_key_hash):
                raise RevocationError("CertID de la reponse different de la requete")

            now = datetime.datetime.now(datetime.timezone.utc)
            this_update = single["this_update"].native
            next_update = single["next_update"].native
            if this_update > now + CLOCK_SKEW:
                raise RevocationError("reponse OCSP datee du futur")
            if next_update is not None and next_update < now - CLOCK_SKEW:
                raise RevocationError("reponse OCSP perimee")
            return single["cert_status"].name, next_update
        except RevocationError:
            raise
        except Exception as exc:  # reponse mal formee
            raise RevocationError("reponse OCSP illisible : %s" % exc)

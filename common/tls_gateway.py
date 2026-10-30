"""
tls_gateway.py -- passerelle mTLS post-quantique devant le PDP (v2).

OPA est ecrit en Go : sa pile TLS ne connait ni HQC ni CROSS. Pour proteger
le lien PEP -> PDP comme les autres liens du plan de controle (exigence ES2,
scenario S6), OPA n'ecoute plus qu'en local (127.0.0.1:8181, dans le meme
conteneur) et cette passerelle expose l'API de decision en TLS 1.3
post-quantique avec authentification mutuelle :
  * le certificat de la passerelle est obtenu aupres de la PKI (inscription) ;
  * seul un client presentant un certificat de la CA dont le CN figure dans
    GATEWAY_ALLOWED_CN (par defaut : pep) est servi ;
  * la decision d'OPA est relayee sans modification.
"""

import logging
import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from flask import Flask, Response, jsonify, request

from common import enroll, keepalive_server, tlsopt  # noqa: F401

logging.basicConfig(level=logging.INFO, format="%(asctime)s [pdp-gw] %(message)s")
log = logging.getLogger("pdp-gw")

NAME = os.environ.get("GATEWAY_NAME", "pdp")
UPSTREAM = os.environ.get("GATEWAY_UPSTREAM", "http://127.0.0.1:8181")
PORT = int(os.environ.get("GATEWAY_PORT", "8182"))
ALLOWED = set(os.environ.get("GATEWAY_ALLOWED_CN", "pep").split(","))

app = Flask(__name__)
_up = requests.Session()


@app.route("/<path:sub>", methods=["GET", "POST"])
def relay(sub):
    cn = request.environ.get("SSL_CLIENT_CN")
    if cn not in ALLOWED:
        log.warning("client refuse : CN=%r", cn)
        return jsonify({"error": "forbidden"}), 403
    r = _up.request(request.method, UPSTREAM + "/" + sub, data=request.get_data(),
                    headers={"Content-Type": request.headers.get("Content-Type", "application/json")},
                    timeout=5)
    return Response(r.content, status=r.status_code,
                    content_type=r.headers.get("Content-Type", "application/json"))


if __name__ == "__main__":
    crt, key = enroll.enroll(NAME)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.load_verify_locations(enroll.CA_CERT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    log.info("passerelle PDP en mTLS sur :%d -> %s (clients autorises : %s)", PORT, UPSTREAM, ALLOWED)
    keepalive_server.serve(app, "0.0.0.0", PORT, ctx,
                           conn_log=os.environ.get("ZT_DEBUG_CONNS") == "1")

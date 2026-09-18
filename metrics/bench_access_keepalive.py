"""
bench_access_keepalive.py -- CONNECTION_REUSE / KEEP_ALIVE : mesure de la
latence d'acces bout en bout sur UNE connexion TLS persistante.

Meme chemin applicatif que bench_access.py (Client -> PEP -> PDP -> Ressource
-> Client) : GET /api/data via le PEP avec un JWT obtenu au prealable (HORS
chronometrage). Differences du scenario CONNECTION_REUSE :

  1. une SEULE connexion TCP/TLS au PEP est etablie une fois (session
     requests persistante) et sert a toutes les requetes d'acces ;
  2. le cout d'ETABLISSEMENT (handshake TLS PQC + premiere requete) est
     mesure SEPAREMENT (establishment_ms) ;
  3. les N iterations suivantes sont mesurees individuellement SUR la
     connexion deja etablie ;
  4. la reutilisation reelle est attestee par les compteurs urllib3
     (num_connections / num_requests) et reportee dans le JSON.

Les legs PEP -> PDP et PEP -> Ressource realises en PRODUCTION par le PEP
(pdp_client._pdp_session et _resource_session) sont des sessions persistantes
deja en place cote serveur : ce benchmark ne change rien a l'architecture,
il reutilise la connection du CLIENT vers le PEP (le point du flux qui, en
reference, ouvrait une nouvelle connexion HTTPS a chaque iteration).

Regles identiques a bench_access.py : time.perf_counter(), GET /api/data avec
Bearer JWT, N iterations independantes (le JWT est partage, l'acces est
re-evalue a chaque requete).

Usage (phase PQC, backend = zt-keepalive) :
    venv/bin/python metrics/bench_access_keepalive.py --n 50 \
        --ca-cert pki-pqc/ca/certs/ca.cert.pem
"""

import argparse
import json
import sys
import time
from pathlib import Path

import _keepalive_lib as kal

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CONNECTION_REUSE : mesure de la latence d'acces bout en bout "
                    "sur connexion TLS persistante, en millisecondes"
    )
    parser.add_argument("--pep-url", default="https://pep.ztpqc.lab:8443",
                        help="URL du PEP (endpoint d'acces)")
    parser.add_argument("--idp-url", default="https://idp.ztpqc.lab:8444",
                        help="URL de l'IdP (POST /authenticate pour obtenir le JWT, HORS chronometrage)")
    parser.add_argument("--ca-cert", default=str(BASE_DIR / "pki" / "ca" / "certs" / "ca.cert.pem"),
                        help="certificat de la CA pour la verification TLS")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="demo123")
    parser.add_argument("--n", type=int, default=50,
                        help="nombre d'acces sur la connexion etablie (N)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


def get_access_token(idp_url: str, ca_cert: str, username: str, password: str,
                     timeout: float) -> str:
    """JWT via POST /authenticate (phase d'authentification INITIALE), HORS
    chronometrage -- meme approche que bench_access.py."""
    import requests
    response = requests.post(
        idp_url.rstrip("/") + "/authenticate",
        json={"username": username, "password": password},
        verify=ca_cert,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def run(args: argparse.Namespace) -> dict:
    token = get_access_token(args.idp_url, args.ca_cert, args.username, args.password, args.timeout)

    session = kal.make_session(args.ca_cert)
    url = args.pep_url.rstrip("/") + "/api/data"
    headers = {"Authorization": f"Bearer {token}"}

    # --- 1. ETABLISSEMENT de la connexion TLS PQC (mesure separee) ---------
    t0 = time.perf_counter()
    response = session.get(url, headers=headers, timeout=args.timeout)
    t1 = time.perf_counter()
    response.raise_for_status()
    establishment_ms = (t1 - t0) * 1000
    print(f"[establishment] connexion TLS + 1er acces = {establishment_ms:.3f} ms",
          file=sys.stderr)

    # --- 2. N acces SUR la connexion etablie -------------------------------
    samples_ms = []
    for i in range(1, args.n + 1):
        t_debut_acces = time.perf_counter()
        response = session.get(url, headers=headers, timeout=args.timeout)
        t_fin_acces = time.perf_counter()
        response.raise_for_status()

        latence_ms = (t_fin_acces - t_debut_acces) * 1000
        samples_ms.append(latence_ms)
        print(f"[{i}/{args.n}] L = {latence_ms:.3f} ms", file=sys.stderr)

    # --- 3. Attestation de la reutilisation reelle de la connexion ---------
    stats = kal.pool_stats(session)
    reuse_ok = kal.reuse_is_respected(stats)

    return kal.summarize(
        "latence_acces_bout_en_bout",
        samples_ms,
        unit="ms",
        extra={
            "scenario": "CONNECTION_REUSE/KEEP_ALIVE",
            "backend": "zt-keepalive",
            "establishment_ms": round(establishment_ms, 3),
            "reuse_verified": reuse_ok,
            "reuse_details": stats,
        },
    )


if __name__ == "__main__":
    args = parse_args()
    if args.n < 1:
        raise ValueError("--n doit etre >= 1")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))
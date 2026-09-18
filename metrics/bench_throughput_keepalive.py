"""
bench_throughput_keepalive.py -- CONNECTION_REUSE / KEEP_ALIVE : mesure du
DEBIT (3e metrique experimentale) sur connexions TLS persistantes.

Definition stricte et immuable, identique a bench_throughput.py :

    D = N / T_total            (requetes par seconde)

avec N = nombre de requetes executees et T_total = duree entre le debut de la
premiere requete et la fin de la derniere (time.perf_counter()).

Differences du scenario CONNECTION_REUSE (uniquement le transport) :
  1. une SEULE connexion est etablie par chemin (auth : une connexion vers
     l'IdP pour POST /authenticate et GET /jwks ; access : une connexion vers
     le PEP) puis REUTILISEE pour les N requetes chronometrees ;
  2. l'ETABLISSEMENT (une requete incluant le handshake TLS PQC) est mesure
     separement et exclu du T_total -- le debit rend donc compte des requetes
     sequentielles sur connexion TIEDE (exactement l'effet du keep-alive que
     ce scenario cherche a caracteriser) ;
  3. la reutilisation reelle est attestee par les compteurs urllib3.

Chemins applicatifs IDENTIQUES a bench_throughput.py :
  1. Debit d'authentification : POST /authenticate (IdP) puis validation par
     le code du PEP (JWKS via la session persistante + verification de
     signature), cache JWKS vide a chaque iteration ;
  2. Debit d'acces : GET /api/data via le PEP (Client -> PEP -> PDP ->
     Ressource), JWT obtenu au prealable (hors chronometrage).

Usage (phase PQC, backend = zt-keepalive) :
    venv/bin/python metrics/bench_throughput_keepalive.py --n 50 \
        --ca-cert pki-pqc/ca/certs/ca.cert.pem \
        --expected-alg cross-rsdp-128-balanced
"""

import argparse
import json
import sys
import time
from pathlib import Path

import _keepalive_lib as kal

BASE_DIR = Path(__file__).resolve().parent.parent
PEP_DIR = BASE_DIR / "pep"
if str(PEP_DIR) not in sys.path:
    sys.path.insert(0, str(PEP_DIR))

import config  # pep/config.py -- configuration du PEP (reused telle quelle)
import jwt_signer  # pep/jwt_signer.py -- fonctions JWS du simulateur
import jwks_client  # pep/jwks_client.py -- recuperation de la cle publique


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CONNECTION_REUSE : mesure du debit (req/s) sur connexions persistantes, D = N / T_total"
    )
    parser.add_argument("--n", type=int, default=50,
                        help="nombre de requetes executees (N)")
    parser.add_argument("--ca-cert", default=str(BASE_DIR / "pki" / "ca" / "certs" / "ca.cert.pem"),
                        help="certificat de la CA pour la verification TLS")
    parser.add_argument("--expected-alg", default=None,
                        help="algorithme attendu cote PEP (defaut : EXPECTED_JWT_ALG du config PEP)")
    parser.add_argument("--idp-url", default="https://idp.ztpqc.lab:8444",
                        help="URL de l'IdP (endpoints /authenticate et /jwks)")
    parser.add_argument("--pep-url", default="https://pep.ztpqc.lab:8443",
                        help="URL du PEP (endpoint d'acces)")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="demo123")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


def align_pep_config(args: argparse.Namespace) -> None:
    if args.idp_url:
        jwks_url = args.idp_url.rstrip("/") + "/jwks"
        config.ISSUER_JWKS_ENDPOINTS = {iss: jwks_url for iss in config.ISSUER_JWKS_ENDPOINTS}
        config.TRUSTED_ISSUERS = list(config.ISSUER_JWKS_ENDPOINTS.keys())
    if args.expected_alg:
        config.EXPECTED_JWT_ALG = args.expected_alg
    if args.ca_cert:
        config.CA_CERT = args.ca_cert


def one_full_auth(idp_url: str, session, username: str, password: str) -> None:
    response = session.post(
        idp_url.rstrip("/") + "/authenticate",
        json={"username": username, "password": password},
    )
    response.raise_for_status()
    token = response.json()["access_token"]

    decoded = jwt_signer.decode_unverified(token)
    issuer = decoded.payload.get("iss")
    kid = decoded.header.get("kid")
    alg = decoded.header.get("alg")

    if alg != config.EXPECTED_JWT_ALG:
        raise ValueError(f"Algorithme non autorise : {alg!r}")
    if issuer not in config.TRUSTED_ISSUERS:
        raise ValueError(f"Issuer non approuve : {issuer!r}")

    public_key, jwks_alg = jwks_client.get_verification_key(issuer, kid)
    if jwks_alg != alg:
        raise ValueError(f"Incoherence d'algorithme entre le token ({alg!r}) et le JWKS ({jwks_alg!r})")

    jwt_signer.verify_jwt(token, public_key, alg)


def get_access_token(idp_url: str, ca_cert: str, username: str, password: str,
                     timeout: float) -> str:
    import requests
    response = requests.post(
        idp_url.rstrip("/") + "/authenticate",
        json={"username": username, "password": password},
        verify=ca_cert,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def measure_auth_throughput(args: argparse.Namespace, session) -> dict:
    """Débit d'authentification : la connexion vers l'IdP est etablie une
    fois (hors T_total), puis N authentifications sequentielles sur ladite
    connexion ; D = N / T_total."""
    successful = 0
    failed = 0

    # ETABLISSEMENT (hors chronometrage) : 1ere authentification sur la
    # connexion fraiche, handshake TLS PQC inclus.
    jwks_client._cache.clear()
    t0 = time.perf_counter()
    one_full_auth(args.idp_url, session, args.username, args.password)
    t1 = time.perf_counter()
    establishment_ms = (t1 - t0) * 1000

    start = time.perf_counter()
    for i in range(1, args.n + 1):
        jwks_client._cache.clear()
        try:
            one_full_auth(args.idp_url, session, args.username, args.password)
            successful += 1
        except Exception as exc:
            failed += 1
            print(f"[!] authentification {i}/{args.n} ECHOUEE : {exc}", file=sys.stderr)
    end = time.perf_counter()

    total_time_s = end - start
    return {
        "throughput": round(args.n / total_time_s, 3),
        "total_time_s": round(total_time_s, 6),
        "establishment_ms": round(establishment_ms, 3),
        "successful_requests": successful,
        "failed_requests": failed,
        "reuse_verified": kal.reuse_is_respected(kal.pool_stats(session)),
        "reuse_details": kal.pool_stats(session),
    }


def measure_access_throughput(args: argparse.Namespace, token: str, session) -> dict:
    """Débit d'acces : connexion vers le PEP etablie une fois (hors
    T_total), puis N acces sequentiels sur ladite connexion ; D = N / T_total."""
    url = args.pep_url.rstrip("/") + "/api/data"
    headers = {"Authorization": f"Bearer {token}"}
    successful = 0
    failed = 0

    response = session.get(url, headers=headers, timeout=args.timeout)
    response.raise_for_status()
    establishment_ms = None

    start = time.perf_counter()
    for i in range(1, args.n + 1):
        try:
            response = session.get(url, headers=headers, timeout=args.timeout)
            response.raise_for_status()
            successful += 1
        except Exception as exc:
            failed += 1
            print(f"[!] acces {i}/{args.n} ECHOUEE : {exc}", file=sys.stderr)
    end = time.perf_counter()

    total_time_s = end - start
    return {
        "throughput": round(args.n / total_time_s, 3),
        "total_time_s": round(total_time_s, 6),
        "successful_requests": successful,
        "failed_requests": failed,
        "reuse_verified": kal.reuse_is_respected(kal.pool_stats(session)),
        "reuse_details": kal.pool_stats(session),
    }


def run(args: argparse.Namespace) -> dict:
    align_pep_config(args)
    if args.n < 1:
        raise ValueError("--n doit etre >= 1")

    auth_session = kal.make_session(args.ca_cert)
    kal.install_keepalive_jwks(config, jwks_client, auth_session)
    auth = measure_auth_throughput(args, auth_session)

    token = get_access_token(args.idp_url, args.ca_cert, args.username, args.password, args.timeout)
    access_session = kal.make_session(args.ca_cert)
    access = measure_access_throughput(args, token, access_session)

    return {
        "metric": "debit",
        "unit": "req/s",
        "n": args.n,
        "scenario": "CONNECTION_REUSE/KEEP_ALIVE",
        "backend": "zt-keepalive",
        "authentication": auth,
        "access": access,
    }


if __name__ == "__main__":
    args = parse_args()
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))
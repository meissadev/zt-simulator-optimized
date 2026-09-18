"""
bench_auth_keepalive.py -- CONNECTION_REUSE / KEEP_ALIVE : mesure du temps
d'authentification (chaine IdP -> PEP) sur UNE connexion TLS persistante.

Ce benchmark est le TTE (transports reutilises) du scenario CONNECTION_REUSE.
Il mesure EXACTEMENT le meme chemin applicatif que bench_auth.py (POST
/authenticate a l'IdP + recuperation JWKS + verification de signature par le
code du PEP), a ceci pres que :

  1. une SEULE connexion TCP/TLS est etablie une fois (session requests
     persistante) et sert a toutes les requetes (HttpKeepAlive : la connexion
     n'est pas fermee entre les requetes, contrairement au backend Werkzeug
     de reference qui envoie systhematiquement Connection: close) ;
  2. le cout d'ETABLISSEMENT de la connexion (handshake TLS PQC + premiere
     requete) est mesure SEPAREMENT (establishment_ms) ;
  3. les N iterations suivantes sont mesurees individuellement SUR la
     connexion deja etablie ;
  4. la reutilisation RELLE est attestee par les compteurs urllib3
     (num_connections / num_requests du pool) et reportee dans le JSON.

Regles identiques a bench_auth.py (la methode ne change pas) :
  - le cache JWKS du PEP est vide a chaque iteration (tous les echanges
    necessaires a l'authentification sont inclus dans la mesure) ;
  - time.perf_counter() (chronometre monotone haute resolution) ;
  - le code de verification du PEP (pep/jwt_signer.py, pep/jwks_client.py)
    est REUTILISE tel quel -- seule pep_jwks_client._fetch_jwks est
    redirige vers la session persistante COTE PROCESSUS DE MESURE
    (monkeypatch), aucun fichier du simulateur n'est modifie.

Usage (phase PQC, backend = zt-keepalive) :
    venv/bin/python metrics/bench_auth_keepalive.py --n 50 \
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
        description="CONNECTION_REUSE : mesure du temps d'authentification "
                    "(chaine IdP -> PEP) sur connexion TLS persistante, en millisecondes"
    )
    parser.add_argument("--idp-url", default="https://idp.ztpqc.lab:8444",
                        help="URL de l'IdP (endpoints /authenticate et /jwks)")
    parser.add_argument("--ca-cert", default=str(BASE_DIR / "pki" / "ca" / "certs" / "ca.cert.pem"),
                        help="certificat de la CA pour la verification TLS")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="demo123")
    parser.add_argument("--n", type=int, default=50,
                        help="nombre d'authentifications sur la connexion etablie (N)")
    parser.add_argument("--expected-alg", default=None,
                        help="algorithme attendu cote PEP (defaut : EXPECTED_JWT_ALG du config PEP)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


def align_pep_config(args: argparse.Namespace) -> None:
    """Aligne la configuration du PEP sur l'IdP reelle, l'algorithme vise et
    la CA -- exactement le meme mecanisme que bench_auth.py."""
    if args.idp_url:
        jwks_url = args.idp_url.rstrip("/") + "/jwks"
        config.ISSUER_JWKS_ENDPOINTS = {iss: jwks_url for iss in config.ISSUER_JWKS_ENDPOINTS}
        config.TRUSTED_ISSUERS = list(config.ISSUER_JWKS_ENDPOINTS.keys())
    if args.expected_alg:
        config.EXPECTED_JWT_ALG = args.expected_alg
    if args.ca_cert:
        config.CA_CERT = args.ca_cert


def one_full_auth(idp_url: str, session, username: str, password: str) -> None:
    """POST /authenticate (session persistante, connexion deja etablie) puis
    validation EXACTE du PEP (decode libre, controle alg/issuer, JWKS via la
    session, verification de signature)."""
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
        raise ValueError(f"Algorithme non autorise : {alg!r} (attendu {config.EXPECTED_JWT_ALG!r})")
    if issuer not in config.TRUSTED_ISSUERS:
        raise ValueError(f"Issuer non approuve : {issuer!r} (trusted: {config.TRUSTED_ISSUERS})")

    public_key, jwks_alg = jwks_client.get_verification_key(issuer, kid)
    if jwks_alg != alg:
        raise ValueError(f"Incoherence d'algorithme entre le token ({alg!r}) et le JWKS ({jwks_alg!r})")

    jwt_signer.verify_jwt(token, public_key, alg)


def run(args: argparse.Namespace) -> dict:
    align_pep_config(args)

    session = kal.make_session(args.ca_cert)
    kal.install_keepalive_jwks(config, jwks_client, session)

    # --- 1. ETABLISSEMENT de la connexion TLS PQC (mesure separee) ---------
    # La premiere authentification ouvre la connexion (handshake TLS + premiere
    # requete) : son cout est le seul temps que le scenario KEEP_ALIVE paie une
    # fois, au lieu d'une nouvelle connexion a CHAQUE requete.
    jwks_client._cache.clear()
    t0 = time.perf_counter()
    one_full_auth(args.idp_url, session, args.username, args.password)
    t1 = time.perf_counter()
    establishment_ms = (t1 - t0) * 1000
    print(f"[establishment] connexion TLS + 1ere authentification = "
          f"{establishment_ms:.3f} ms", file=sys.stderr)

    # --- 2. N authentifications SUR la connexion etablie -------------------
    samples_ms = []
    for i in range(1, args.n + 1):
        jwks_client._cache.clear()
        t_debut_auth = time.perf_counter()
        one_full_auth(args.idp_url, session, args.username, args.password)
        t_fin_auth = time.perf_counter()

        temps_auth_ms = (t_fin_auth - t_debut_auth) * 1000
        samples_ms.append(temps_auth_ms)
        print(f"[{i}/{args.n}] T_auth = {temps_auth_ms:.3f} ms", file=sys.stderr)

    # --- 3. Attestation de la reutilisation reelle de la connexion ---------
    stats = kal.pool_stats(session)
    reuse_ok = kal.reuse_is_respected(stats)

    return kal.summarize(
        "temps_authentification",
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
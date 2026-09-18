"""
bench_s2s_auth_keepalive.py -- CONNECTION_REUSE / KEEP_ALIVE : mesure du temps
d'authentification SERVICE -> SERVICE (mTLS) sur UNE connexion persistante.

Ce benchmark caracterise le NOMBRE de handshakes mTLS que le scenario
CONNECTION_REUSE doit realiser : exactement UN. En reference
(bench_s2s_auth), Service A ouvrait une connexion TLS fraiche (poignee de
main mTLS PQC complete) a CHAQUE iteration. Ici, UNE seule connexion mTLS
(Service A = batch-service -> Service B = Ressource, ssl.CERT_REQUIRED) est
etablie : son cout (handshake + validation d'identite) est mesure une fois
(establishment_ms), puis N requetes applicatives ('/' = /api/data de la
Ressource, mTLS) sont envoyees SUR LA MEME connexion pour attester que la
reutilisation est effective (les compteurs urllib3 sont reportes).

Mesures produites :
  - establishment_ms : cout unique du handshake mTLS PQC + premiere requete
    (c'est la totalite du cout d'authentification S2S dans un monde avec
    reutilisation de connexion) ;
  - N_establishment_measurements = 1 (comparer a N handshakes en reference) ;
  - latences des N-1 requetes suivantes sur la connexion etablie (fournies
    individuellement dans samples_ms mais NON une metrique headline d'auth :
    elles prouvent que les appels suivants ne re-handshakent pas) ;
  - reuse_verified / reuse_details : attestation reelle.

Regles identiques a bench_s2s_auth.py : time.perf_counter(), meme identite
(pep/mtls_handler.resource_client_cert), meme CA, same URL Service B
(config.RESOURCE_BASE_URL).

Usage (phase PQC, backend = zt-keepalive) :
    venv/bin/python metrics/bench_s2s_auth_keepalive.py --mode pqc --n 50
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

import config  # pep/config.py -- RESOURCE_BASE_URL et chemins PKI
import mtls_handler  # pep/mtls_handler.py -- identite mTLS sortante du PEP

_PKI_BY_MODE = {
    "classical": "pki",
    "pqc": "pki-pqc",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CONNECTION_REUSE : mesure du temps d'authentification "
                    "service -> service (mTLS) sur connexion persistante, en millisecondes"
    )
    parser.add_argument("--mode", choices=["classical", "pqc"], required=True,
                        help="configuration cryptographique mesuree (classical : RSA/ECDH ; pqc : CROSS/HQC-1)")
    parser.add_argument("--n", type=int, default=50,
                        help="nombre de requetes envoyees sur la connexion mTLS etablie (N)")
    parser.add_argument("--ca-cert", default=None,
                        help="certificat de la CA (defaut : pki[-pqc]/ca/certs/ca.cert.pem selon --mode)")
    parser.add_argument("--client-cert", default=None,
                        help="certificat client de Service A (defaut : pki[-pqc]/certs/pep.crt selon --mode)")
    parser.add_argument("--client-key", default=None,
                        help="cle privee correspondante (defaut : pki[-pqc]/certs/pep.key selon --mode)")
    parser.add_argument("--ressource-url", default=config.RESOURCE_BASE_URL,
                        help="URL de Service B (Ressource), defaut : https://ressource.ztpqc.lab:8446")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


def _resolve_paths(args: argparse.Namespace) -> dict:
    pki_dir = BASE_DIR / _PKI_BY_MODE[args.mode]
    return {
        "ca_cert": Path(args.ca_cert or pki_dir / "ca" / "certs" / "ca.cert.pem"),
        "client_cert": Path(args.client_cert or pki_dir / "certs" / "pep.crt"),
        "client_key": Path(args.client_key or pki_dir / "certs" / "pep.key"),
    }


def run(args: argparse.Namespace) -> dict:
    paths = _resolve_paths(args)
    for label, path in paths.items():
        if not path.exists():
            raise FileNotFoundError(f"{label} introuvable : {path}")

    # Même mécanique que bench_s2s_auth.py : aligne la config du PEP sur les
    # chemins réels et réutilise la fonction d'identité existante.
    config.CA_CERT = str(paths["ca_cert"])
    config.PEP_TLS_CERT = str(paths["client_cert"])
    config.PEP_TLS_KEY = str(paths["client_key"])
    client_identity = mtls_handler.resource_client_cert()

    session = kal.make_session(
        str(paths["ca_cert"]),
        client_cert=client_identity[0],
        client_key=client_identity[1],
    )
    url = args.ressource_url.rstrip("/") + "/api/data"

    # --- 1. ETABLISSEMENT de la connexion mTLS (mesure separee) ------------
    t0 = time.perf_counter()
    response = session.get(url, timeout=args.timeout)
    t1 = time.perf_counter()
    response.raise_for_status()
    establishment_ms = (t1 - t0) * 1000
    print(f"[establishment] handshake mTLS + 1ere requete = {establishment_ms:.3f} ms",
          file=sys.stderr)

    # --- 2. N-1 requetes SUR la connexion mTLS etablie ---------------------
    samples_ms = []
    for i in range(1, args.n):
        t_debut = time.perf_counter()
        response = session.get(url, timeout=args.timeout)
        t_fin = time.perf_counter()
        response.raise_for_status()
        latence_ms = (t_fin - t_debut) * 1000
        samples_ms.append(latence_ms)
        print(f"[{i}/{args.n}] requete sur connexion etablie = {latence_ms:.3f} ms",
              file=sys.stderr)

    # --- 3. Attestation de la reutilisation reelle -------------------------
    stats = kal.pool_stats(session)
    reuse_ok = kal.reuse_is_respected(stats)

    return {
        "metric": "temps_authentification_service_service",
        "unit": "ms",
        "scenario": "CONNECTION_REUSE/KEEP_ALIVE",
        "backend": "zt-keepalive",
        "n": args.n,
        "handshakes": 1,
        "establishment_ms": round(establishment_ms, 3),
        "samples_following_requests_ms": [round(s, 3) for s in samples_ms],
        "mean_following_requests_ms": kal.summarize(
            "latence_acces_service_service", samples_ms
        ) if samples_ms else None,
        "reuse_verified": reuse_ok,
        "reuse_details": stats,
    }


if __name__ == "__main__":
    args = parse_args()
    if args.n < 2:
        raise ValueError("--n doit etre >= 2 (etablissement + au moins 1 requete sur la connexion etablie)")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))
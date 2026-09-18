"""
bench_s2s_throughput_keepalive.py -- CONNECTION_REUSE / KEEP_ALIVE : mesure
du debit service -> service (S2S) sur une connexion mTLS persistante.

Chaine Zero Trust (une demande d'acces S2S complete) :

    Service A -> PEP -> PDP -> Service B (Ressource) -> Service A

Definition stricte de la metrique, IDENTIQUE a bench_s2s_throughput.py :

    D_S2S = successful_requests / T_total

avec :
* successful_requests : demandes d'acces S2S terminees avec succes ;
* T_total : temps ecoule entre le debut de la premiere demande et la fin de
  la derniere (time.perf_counter()).

Differences du scenario CONNECTION_REUSE (uniquement le transport) :
  1. UNE seule connexion mTLS Service A -> PEP (session requests persistante
     avec certificat client) sert aux N demandes -- la reference ouvrait une
     connexion HTTPS fraiche (donc un nouvel handshake mTLS HQC-1) a CHAQUE
     demande ;
  2. l'ETABLISSEMENT (handshake + premiere demande) est mesure separement et
     EXCLU du T_total : le debit rend compte des demandes sequentielles sur
     connexion TIEDE ;
  3. la reutilisation reelle est attestee par les compteurs urllib3.

POUR LE PORTEE MESUREE : il s'agit du DEBIT D'ACCES S2S en configuration
keep-alive. L'authentification mTLS de Service A n'est pas prefetchee ni
artificiellement retiree : dans ce scenario elle est payee une seule fois
(etablissement), conformement au comportement du transport persistant que
cette etape d'optimisation introduit.

Usage (phase PQC, backend = zt-keepalive) :
    venv/bin/python metrics/bench_s2s_throughput_keepalive.py --mode pqc --n 50
"""

import argparse
import json
import sys
import time
from pathlib import Path

import _keepalive_lib as kal

BASE_DIR = Path(__file__).resolve().parent.parent

_PKI_BY_MODE = {
    "classical": "pki",
    "pqc": "pki-pqc",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CONNECTION_REUSE : mesure du debit service -> service sur "
                    "connexion mTLS persistante, en requetes/seconde"
    )
    parser.add_argument("--mode", choices=["classical", "pqc"], required=True,
                        help="configuration cryptographique mesuree (classical : RSA/ECDH ; pqc : CROSS/HQC-1)")
    parser.add_argument("--n", type=int, default=50,
                        help="nombre de demande d'acces S2S sur la connexion etablie (N)")
    parser.add_argument("--pep-url", default="https://pep.ztpqc.lab:8443",
                        help="URL du PEP (endpoint d'acces S2S)")
    parser.add_argument("--ca-cert", default=None,
                        help="certificat de la CA (defaut : pki[-pqc]/ca/certs/ca.cert.pem selon --mode)")
    parser.add_argument("--client-cert", default=None,
                        help="certificat client de Service A (defaut : pki[-pqc]/certs/batch-service.crt selon --mode)")
    parser.add_argument("--client-key", default=None,
                        help="cle privee correspondante (defaut : pki[-pqc]/certs/batch-service.key selon --mode)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


def _resolve_paths(args: argparse.Namespace) -> dict:
    pki_dir = BASE_DIR / _PKI_BY_MODE[args.mode]
    return {
        "ca_cert": Path(args.ca_cert or pki_dir / "ca" / "certs" / "ca.cert.pem"),
        "client_cert": Path(args.client_cert or pki_dir / "certs" / "batch-service.crt"),
        "client_key": Path(args.client_key or pki_dir / "certs" / "batch-service.key"),
    }


def run(args: argparse.Namespace) -> dict:
    paths = _resolve_paths(args)
    for label, path in paths.items():
        if not path.exists():
            raise FileNotFoundError(f"{label} introuvable : {path}")

    session = kal.make_session(
        str(paths["ca_cert"]),
        client_cert=str(paths["client_cert"]),
        client_key=str(paths["client_key"]),
    )
    url = args.pep_url.rstrip("/") + "/api/data"

    # ETABLISSEMENT de la connexion mTLS (hors chronometrage).
    t0 = time.perf_counter()
    response = session.get(url, timeout=args.timeout)
    t1 = time.perf_counter()
    response.raise_for_status()
    establishment_ms = (t1 - t0) * 1000

    successful = 0
    failed = 0
    t_debut = time.perf_counter()
    for i in range(1, args.n + 1):
        try:
            response = session.get(url, timeout=args.timeout)
            response.raise_for_status()
            successful += 1
        except Exception as exc:
            failed += 1
            print(f"[{i}/{args.n}] ECHEC : {exc}", file=sys.stderr)
    t_fin = time.perf_counter()

    total_time_s = t_fin - t_debut
    throughput = successful / total_time_s if total_time_s > 0 else 0.0

    stats = kal.pool_stats(session)
    reuse_ok = kal.reuse_is_respected(stats)

    return {
        "metric": "debit_service_service",
        "unit": "req/s",
        "scenario": "CONNECTION_REUSE/KEEP_ALIVE",
        "backend": "zt-keepalive",
        "n": args.n,
        "throughput": round(throughput, 3),
        "total_time_s": round(total_time_s, 6),
        "establishment_ms": round(establishment_ms, 3),
        "successful_requests": successful,
        "failed_requests": failed,
        "reuse_verified": reuse_ok,
        "reuse_details": stats,
    }


if __name__ == "__main__":
    args = parse_args()
    if args.n < 1:
        raise ValueError("--n doit etre >= 1")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))
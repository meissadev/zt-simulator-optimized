"""
bench_s2s_latency_keepalive.py -- CONNECTION_REUSE / KEEP_ALIVE : mesure de la
latence d'acces bout-en-bout SERVICE -> SERVICE sur une connexion mTLS
persistante.

Meme chaine applicative que bench_s2s_latency.py :

    Service A -> PEP -> PDP -> Service B (Ressource) -> Service A

(GET /api/data via le PEP, identite Service A = batch-service presente en
mTLS). Differences du scenario CONNECTION_REUSE :

  1. UNE seule connexion mTLS Service A -> PEP est etablie une fois (session
     requests persistante avec certificat client) : plus d'handshake mTLS a
     CHAQUE requete, contrairement a la reference et a l'architecture
     historique (Werkzeug -> Connection: close) ;
  2. l'ETABLISSEMENT (handshake mTLS PQC + premiere requete) est mesure
     SEPAREMENT (establishment_ms) -- c'est le cout d'authentification S2S
     paye une seule fois ;
  3. les N iterations suivantes sont mesurees individuellement sur la
     connexion deja etablie (elles n'incluent plus de poignee de main mTLS) ;
  4. la reutilisation reelle est attestee par les compteurs urllib3.

Autres legs inchanges : l'appel PEP -> PDP (OPA) et le relais PEP -> Service B
restent des sessions persistantes cote serveur (aucune modification
architecturale).

Regles de mesure identiques a bench_s2s_latency.py : time.perf_counter(),
l'authentification mTLS de Service A n'est ni artificiellement ajoutee ni
prefetchee -- dans ce scenario elle est payee UNE fois, a l'etablissement, et
non plus a chaque requete.

Usage (phase PQC, backend = zt-keepalive) :
    venv/bin/python metrics/bench_s2s_latency_keepalive.py --mode pqc --n 50
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
        description="CONNECTION_REUSE : mesure de la latence d'acces bout-en-bout "
                    "service -> service sur connexion mTLS persistante, en millisecondes"
    )
    parser.add_argument("--mode", choices=["classical", "pqc"], required=True,
                        help="configuration cryptographique mesuree (classical : RSA/ECDH ; pqc : CROSS/HQC-1)")
    parser.add_argument("--n", type=int, default=50,
                        help="nombre d'acces S2S sur la connexion etablie (N)")
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

    # --- 1. ETABLISSEMENT de la connexion mTLS (mesure separee) ------------
    t0 = time.perf_counter()
    response = session.get(url, timeout=args.timeout)
    t1 = time.perf_counter()
    response.raise_for_status()
    establishment_ms = (t1 - t0) * 1000
    print(f"[establishment] handshake mTLS + 1er acces = {establishment_ms:.3f} ms",
          file=sys.stderr)

    # --- 2. N acces SUR la connexion mTLS etablie --------------------------
    samples_ms = []
    successful = 0
    failed = 0
    for i in range(1, args.n + 1):
        t_debut_acces = time.perf_counter()
        error = None
        try:
            response = session.get(url, timeout=args.timeout)
            t_fin_acces = time.perf_counter()
            response.raise_for_status()
        except Exception as exc:
            t_fin_acces = time.perf_counter()
            error = exc

        latence_ms = (t_fin_acces - t_debut_acces) * 1000
        if error is None:
            successful += 1
            samples_ms.append(latence_ms)
            print(f"[{i}/{args.n}] L_S2S = {latence_ms:.3f} ms", file=sys.stderr)
        else:
            failed += 1
            print(f"[{i}/{args.n}] ECHEC : {error}", file=sys.stderr)

    # --- 3. Attestation de la reutilisation reelle -------------------------
    stats = kal.pool_stats(session)
    reuse_ok = kal.reuse_is_respected(stats)

    result = kal.summarize(
        "latence_acces_service_service",
        samples_ms,
        unit="ms",
        extra={
            "scenario": "CONNECTION_REUSE/KEEP_ALIVE",
            "backend": "zt-keepalive",
            "establishment_ms": round(establishment_ms, 3),
            "successful_requests": successful,
            "failed_requests": failed,
            "reuse_verified": reuse_ok,
            "reuse_details": stats,
        },
    )
    return result


if __name__ == "__main__":
    args = parse_args()
    if args.n < 1:
        raise ValueError("--n doit etre >= 1")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))
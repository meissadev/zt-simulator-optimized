"""
aggregate_v2.py -- agrege les resultats de bench_v2.py (results/*.json).

Usage : python3 metrics/aggregate_v2.py results/ [--csv results/summary.csv]

Chaque fichier <env>-<mode>-<variante>.json devient une ligne ; les colonnes
sont les medianes (et p95 pour les latences). Une table de rapport PQ/classique
est imprimee pour chaque environnement et chaque variante commune.
"""

import argparse
import csv
import glob
import json
import os


def g(d, *path):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d


COLUMNS = [
    ("enroll_ms", ("enroll_ms",)),
    ("ca_cert_der", ("sizes", "ca_cert_der")),
    ("leaf_cert_der", ("sizes", "pep_cert_der")),
    ("jwt", ("sizes", "jwt")),
    ("jwks", ("sizes", "jwks")),
    ("ocsp_resp", ("sizes", "ocsp_response")),
    ("rtt_ms", ("handshake_server_auth", "tcp_connect_ms", "median")),
    ("hs_ms", ("handshake_server_auth", "tls_ms", "median")),
    ("hs_p95", ("handshake_server_auth", "tls_ms", "p95")),
    ("hs_c2s", ("handshake_server_auth", "bytes_client_to_server", "median")),
    ("hs_s2c", ("handshake_server_auth", "bytes_server_to_client", "median")),
    ("hs_rtts", ("handshake_server_auth", "tls_over_rtt")),
    ("mtls_ms", ("handshake_mtls", "tls_ms", "median")),
    ("mtls_p95", ("handshake_mtls", "tls_ms", "p95")),
    ("mtls_c2s", ("handshake_mtls", "bytes_client_to_server", "median")),
    ("mtls_s2c", ("handshake_mtls", "bytes_server_to_client", "median")),
    ("mtls_rtts", ("handshake_mtls", "tls_over_rtt")),
    ("token_ms", ("user_token", "median")),
    ("token_p95", ("user_token", "p95")),
    ("access_ms", ("user_access", "median")),
    ("access_p95", ("user_access", "p95")),
    ("s2s_ms", ("s2s_access", "median")),
    ("s2s_p95", ("s2s_access", "p95")),
    ("errors", None),
    ("rps_user", ("throughput_user", "req_per_s")),
    ("rps_s2s", ("throughput_s2s", "req_per_s")),
    ("revoked_after_s", ("revocation", "refused_after_s")),
    ("ocsp_fetches", ("pep_metrics_after", "ocsp", "fetches")),
    ("ocsp_checks", ("pep_metrics_after", "ocsp", "checks")),
    ("ocsp_fetch_ms", None),
    ("client_cpus", ("host", "cpus")),
    ("client_cpu", ("host", "cpu")),
]


def row(path):
    with open(path) as f:
        r = json.load(f)
    env, mode, tag = os.path.basename(path)[:-5].split("-", 2)
    out = {"env": env, "mode": mode, "variant": tag, "reuse": r.get("reuse")}
    for name, p in COLUMNS:
        out[name] = g(r, *p) if p else None
    out["errors"] = sum((g(r, k, "errors") or 0) for k in
                        ("user_token", "user_access", "s2s_access", "throughput_user", "throughput_s2s"))
    o = g(r, "pep_metrics_after", "ocsp") or {}
    if o.get("fetches"):
        out["ocsp_fetch_ms"] = round(o["fetch_ms_total"] / o["fetches"], 2)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--csv")
    a = ap.parse_args()
    rows = [row(p) for p in sorted(glob.glob(os.path.join(a.dir, "*-*-*.json")))]
    keys = ["env", "mode", "variant", "reuse"] + [c for c, _ in COLUMNS]
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, keys)
            w.writeheader()
            w.writerows(rows)
    show = ["env", "mode", "variant", "rtt_ms", "hs_ms", "mtls_ms", "hs_s2c", "mtls_c2s",
            "token_ms", "access_ms", "s2s_ms", "rps_user", "rps_s2s", "revoked_after_s", "errors"]
    print("\t".join(show))
    for r in rows:
        print("\t".join("" if r[k] is None else str(r[k]) for k in show))
    # Rapports PQ / classique
    idx = {(r["env"], r["mode"], r["variant"]): r for r in rows}
    print("\nrapport pqc/classique")
    for (env, mode, var), r in sorted(idx.items()):
        c = idx.get((env, "classical", var))
        if mode != "pqc" or not c:
            continue
        ratios = []
        for k in ("hs_ms", "mtls_ms", "token_ms", "access_ms", "s2s_ms", "rps_user", "rps_s2s"):
            if r.get(k) and c.get(k):
                ratios.append("%s x%.2f" % (k, r[k] / c[k]))
        print(env, var, " ".join(ratios))


if __name__ == "__main__":
    main()

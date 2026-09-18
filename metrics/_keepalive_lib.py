"""
_keepalive_lib.py -- utilites communes aux benchmarks CONNECTION_REUSE
(KEEP_ALIVE) du simulateur.

Ces fonctions ne modifient AUCUN composant du simulateur : elles sont
uniquement cote client de mesure. Elles permettent de :

  1. creer une session requests persistante (une seule connexion TCP/TLS,
     reutilisee pour toutes les requetes -- le scenario CONNECTION_REUSE) ;
  2. verifier la reutilisation REELLE de la connexion : compter les
     connexions TCP/TLS effectivement etablies (num_connections) et les
     requetes envoyees (num_requests) vues par le pool urllib3, ainsi que
     la taille du cache de connexions ;
  3. brancher la recuperation JWKS de pep/jwks_client.py sur la session
     persistante (le code du PEP n'est pas modifie : on remplace la
     fonction _fetch_jwks au niveau du processus de mesure uniquement).

La verification (2) est essentielle : elle rend <attestable> le fait que le
scenario KEEP_ALIVE a reellement reutilise UNE seule connexion TLS et ne s'est
pas contente de reutiliser des objets Python (session requests) qui
ouvriraient en realite plusieurs sockets a chaque requete.
"""

import time


def summarize(metric: str, samples_ms: list, unit: str = "ms", extra: dict = None) -> dict:
    """Statistiques identiques a celles des benchmarks de reference (mean,
    median, stdev, min, max) + champs supplementaires optionnels."""
    import statistics

    result = {
        "metric": metric,
        "unit": unit,
        "n": len(samples_ms),
        "mean": round(statistics.mean(samples_ms), 3),
        "median": round(statistics.median(samples_ms), 3),
        "stdev": round(statistics.stdev(samples_ms), 3) if len(samples_ms) > 1 else 0.0,
        "min": round(min(samples_ms), 3),
        "max": round(max(samples_ms), 3),
    }
    if extra:
        result.update(extra)
    return result


def make_session(ca_cert: str, client_cert: str = None, client_key: str = None):
    """
    Cree une session requests persistante (scenario CONNECTION_REUSE).

    verify : CA commune pour la verification TLS du serveur.
    cert   : identite certifiee presentee en mTLS (services uniquement).
    """
    import requests

    session = requests.Session()
    session.verify = ca_cert
    if client_cert and client_key:
        session.cert = (client_cert, client_key)
    return session


def pool_stats(session) -> dict:
    """
    Comptage reel cote pool urllib3 : connexions TCP/TLS etablies et
    requetes envoyees, par (hote, port).
    """
    pools = session.get_adapter("https://").poolmanager.pools
    total_connections = 0
    total_requests = 0
    per_host = []

    # list(pools.keys()) : l'iteration directe n'est pas garantie threadsafe
    # sur le conteneur de pools -- on materialise d'abord les cles.
    for key in list(pools.keys()):
        per_host.append(
            {
                "host": "%s:%s" % (key.key_host, key.key_port),
                "num_connections": int(pools[key].num_connections),
                "num_requests": int(pools[key].num_requests),
            }
        )
        total_connections += int(pools[key].num_connections)
        total_requests += int(pools[key].num_requests)

    return {
        "total_connections": total_connections,
        "total_requests": total_requests,
        "per_host": per_host,
    }


def reuse_is_respected(stats: dict) -> bool:
    """
    Vrai si exactement UNE connexion TCP/TLS (par hote) a ete etablie : le
    scenario CONNECTION_REUSE exige num_connections == 1 pour chaque pool
    contacte, quel que soit le nombre de requetes envoyees.
    """
    if not stats["per_host"]:
        return False
    return all(entry["num_connections"] == 1 for entry in stats["per_host"])


def install_keepalive_jwks(config, jwks_client, session):
    """
    Fait pointer pep/jwks_client._fetch_jwks vers la session persistante
    (monkeypatch cote processus de mesure uniquement, code du PEP intact).

    Le mapping issuer -> URL (config.ISSUER_JWKS_ENDPOINTS) et la verification
    TLS (session.verify) restent identiques a l'usage normal de jwks_client.
    """

    def _fetch_jwks(issuer: str) -> dict:
        # "issuer" est une identite de confiance resolue via le mapping
        # explicite de pep/config.py -- jamais derivee de "iss" (cf. jwks_client).
        url = config.ISSUER_JWKS_ENDPOINTS[issuer]
        response = session.get(url, timeout=config.JWKS_FETCH_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        keys = {}
        for entry in data.get("keys", []):
            keys[entry["kid"]] = {
                "alg": entry["alg"],
                "pub": jwks_client.jwt_signer.b64url_decode(entry["pub"]),
            }
        return {"keys": keys, "fetched_at": time.time()}

    jwks_client._fetch_jwks = _fetch_jwks
    return _fetch_jwks
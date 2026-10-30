"""
pdp_client.py -- interrogation du PDP (OPA) pour la décision d'autorisation.

Le PEP ne réévalue jamais de politique lui-même : il transmet le contexte
(identité authentifiée + requête) et applique la décision retournée,
conformément à la séparation PEP/PDP de NIST SP 800-207.
"""

import logging

import requests

import config

logger = logging.getLogger(__name__)

from common import httpclient

# Session vers le PDP, creee au premier appel (apres l'inscription du PEP).
_pdp_session = None


def _session():
    global _pdp_session
    if _pdp_session is None:
        if config.OPA_URL.startswith("https://"):
            # v2 : lien PEP -> PDP en TLS 1.3 post-quantique, authentifie par
            # le certificat du PEP (passerelle mTLS devant OPA).
            _pdp_session = httpclient.session(config.CA_CERT, (config.PEP_TLS_CERT, config.PEP_TLS_KEY))
        else:
            _pdp_session = requests.Session()
    return _pdp_session


class PDPError(Exception):
    pass


def evaluate(subject: dict, resource_path: str, method: str) -> bool:
    """
    Interroge OPA et retourne True (Allow) ou False (Deny).

    Toute erreur réseau/timeout lève PDPError -- à traiter comme un refus
    par défaut côté appelant (fail-closed : "never trust, always verify"
    implique qu'une absence de décision positive explicite équivaut à
    un refus, jamais à un accès implicite).
    """
    payload = {
        "input": {
            "subject": subject,
            "resource": resource_path,
            "method": method,
        }
    }
    try:
        headers = {} if config.UPSTREAM_REUSE else {"Connection": "close"}
        response = _session().post(config.OPA_URL, json=payload, headers=headers,
                                   timeout=config.OPA_TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise PDPError(f"Échec d'appel au PDP : {exc}") from exc

    result = response.json().get("result")
    return bool(result)
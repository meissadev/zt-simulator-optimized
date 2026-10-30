"""
PEP -- Policy Enforcement Point du simulateur Zero Trust.

Point de contrôle unique, à la frontière entre le Sujet et le reste de
l'architecture : intercepte toute requête, valide l'authentification
(mTLS pour un service, JWT pour un utilisateur), interroge le PDP pour la
décision d'autorisation, et ne relaie la requête vers la Ressource qu'en
cas de décision positive -- jamais l'inverse (fail-closed).

Trois étapes strictement séquentielles et jamais court-circuitées :
  1. authenticate_request()  -- validation cryptographique uniquement
  2. pdp_client.evaluate()   -- décision d'autorisation, déléguée au PDP
  3. relais mTLS vers la Ressource -- flux d'accès
"""

import logging
import os
import sys

import requests
from flask import Flask, Response, jsonify, request
from werkzeug.serving import WSGIRequestHandler, run_simple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import httpclient, tlsopt  # noqa: F401

import config
import jwks_client
import jwt_signer
import mtls_handler
import pdp_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [pep] %(message)s")
logger = logging.getLogger(__name__)

# Session vers la Ressource, creee au premier appel (apres l'inscription) avec
# un contexte TLS partage (common/httpclient.py).
_resource_session = None


def resource_session():
    global _resource_session
    if _resource_session is None:
        _resource_session = httpclient.session(config.CA_CERT, mtls_handler.resource_client_cert())
    return _resource_session

app = Flask(__name__)

# v2 : vérificateur OCSP, créé au démarrage après l'inscription auprès de la PKI.
_ocsp = None


class PeerCertRequestHandler(WSGIRequestHandler):
    """Expose le certificat client (s'il existe) dans l'environnement WSGI."""

    def make_environ(self):
        environ = super().make_environ()
        peer_cert = self.connection.getpeercert()
        if peer_cert:
            subject = dict(x[0] for x in peer_cert.get("subject", []))
            environ["SSL_CLIENT_CN"] = subject.get("commonName")
            environ["SSL_CLIENT_CERT_DER"] = self.connection.getpeercert(binary_form=True)
        else:
            environ["SSL_CLIENT_CN"] = None
            environ["SSL_CLIENT_CERT_DER"] = None
        return environ


class AuthenticationError(Exception):
    """Échec de l'étape 1 (authentification) -- distinct d'un refus d'autorisation."""


def authenticate_request() -> dict:
    """
    Étape 1 : authentification -- validation cryptographique uniquement.
    AUCUN appel au PDP ici : on ne fait que prouver une identité, pas
    encore statuer sur un droit d'accès (séparation des responsabilités,
    cf. NIST SP 800-207).

    Retourne un dict de claims/attributs si succès. Lève
    AuthenticationError sinon.
    """
    peer_cn = request.environ.get("SSL_CLIENT_CN")

    # --- Cas 1 : mTLS (service-to-service) ----------------------------------
    if peer_cn:
        # v2 : la chaîne a été vérifiée pendant le handshake ; on vérifie en
        # plus le statut de révocation (OCSP, avec cache borné). Toute
        # incertitude entraîne le refus (fail-closed).
        if _ocsp is not None:
            from common.ocsp_client import RevocationError
            try:
                _ocsp.check(request.environ.get("SSL_CLIENT_CERT_DER"))
            except RevocationError as exc:
                raise AuthenticationError(f"Statut de révocation refusé : {exc}") from exc
        logger.info("Authentification mTLS réussie (CN=%s)", peer_cn)
        return {"auth_method": "mtls", "service_id": peer_cn}

    # --- Cas 2 : JWT (utilisateur-service) ------------------------------------
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]

        try:
            decoded = jwt_signer.decode_unverified(token)
        except ValueError as exc:
            raise AuthenticationError(f"Token mal formé : {exc}") from exc

        issuer = decoded.payload.get("iss")
        kid = decoded.header.get("kid")
        alg = decoded.header.get("alg")
        
        logger.debug("JWT decoded: issuer=%s, kid=%s, alg=%s", issuer, kid, alg)

        # Algorithme fixé côté PEP (pas déduit aveuglément du header) --
        # évite une attaque par confusion d'algorithme.
        if alg != config.EXPECTED_JWT_ALG:
            raise AuthenticationError(f"Algorithme non autorisé : {alg!r} (attendu {config.EXPECTED_JWT_ALG!r})")

        # Vérification de l'issuer AVANT tout appel réseau (mitigation SSRF).
        if issuer not in config.TRUSTED_ISSUERS:
            raise AuthenticationError(f"Issuer non approuvé : {issuer!r} (trusted: {config.TRUSTED_ISSUERS})")

        try:
            public_key, jwks_alg = jwks_client.get_verification_key(issuer, kid)
            logger.debug("JWKS key found: jwks_alg=%s, pub key size=%d bytes", jwks_alg, len(public_key))
        except (jwks_client.UntrustedIssuerError, jwks_client.JWKSFetchError) as exc:
            raise AuthenticationError(str(exc)) from exc

        if jwks_alg != alg:
            raise AuthenticationError(f"Incohérence d'algorithme entre le token ({alg!r}) et le JWKS ({jwks_alg!r})")

        try:
            claims = jwt_signer.verify_jwt(token, public_key, alg, audience=config.EXPECTED_AUDIENCE)
        except ValueError as exc:
            raise AuthenticationError(f"Signature invalide ou token expiré: {exc}") from exc

        logger.info("Authentification JWT réussie (sub=%s)", claims.get("sub"))
        return {"auth_method": "jwt", **claims}

    # --- Aucun credential fourni ------------------------------------------------
    raise AuthenticationError("Aucune preuve d'authentification fournie (ni mTLS ni Bearer token)")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "pep"})


@app.route("/_zt/metrics", methods=["GET"])
def zt_metrics():
    """Compteurs internes de mesure (OCSP) -- prototype uniquement."""
    if not config.METRICS_ENABLED:
        return jsonify({"error": "disabled"}), 404
    return jsonify({"ocsp": dict(_ocsp.stats) if _ocsp else None,
                    "upstream_reuse": config.UPSTREAM_REUSE})


@app.route("/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(subpath):
    # --- Étape 1 : authentification -------------------------------------------
    try:
        subject = authenticate_request()
    except AuthenticationError as exc:
        logger.warning("Authentification refusée : %s", exc)
        return jsonify({"error": "authentication_failed", "detail": str(exc)}), 401

    # --- Étape 2 : autorisation (délégation stricte au PDP) --------------------
    try:
        allowed = pdp_client.evaluate(subject, "/" + subpath, request.method)
    except pdp_client.PDPError as exc:
        logger.error("PDP injoignable, refus par défaut (fail-closed) : %s", exc)
        return jsonify({"error": "pdp_unreachable"}), 503

    if not allowed:
        logger.info("Accès refusé par le PDP (subject=%s, resource=/%s)", subject.get("sub", subject.get("service_id")), subpath)
        return jsonify({"error": "access_denied"}), 403

    # --- Étape 3 : flux d'accès, relayé en mTLS vers la Ressource --------------
    target_url = config.RESOURCE_BASE_URL.rstrip("/") + "/" + subpath
    forwarded_headers = {k: v for k, v in request.headers
                         if k.lower() not in ("host", "content-length", "connection")}
    if not config.UPSTREAM_REUSE:
        forwarded_headers["Connection"] = "close"

    try:
        upstream = resource_session().request(
            method=request.method,
            url=target_url,
            headers=forwarded_headers,
            data=request.get_data(),
            timeout=config.RESOURCE_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        logger.error("Échec de relais mTLS vers la Ressource : %s", exc)
        return jsonify({"error": "resource_unreachable"}), 502

    return Response(
        upstream.content,
        status=upstream.status_code,
        content_type=upstream.headers.get("Content-Type", "application/json"),
    )


if __name__ == "__main__":
    if os.environ.get("PKI_URL"):
        # v2 : certificat obtenu auprès du service PKI, puis vérificateur OCSP.
        from common import enroll
        from common.ocsp_client import OCSPChecker
        config.PEP_TLS_CERT, config.PEP_TLS_KEY = enroll.enroll("pep")
        _ocsp = OCSPChecker(config.CA_CERT)
    for path, label in [
        (config.PEP_TLS_CERT, "certificat TLS du PEP"),
        (config.PEP_TLS_KEY, "clé privée TLS du PEP"),
        (config.CA_CERT, "certificat de la CA"),
    ]:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{label} introuvable : {path}\nExécutez d'abord pki/scripts/issue_cert.sh pep"
            )

    ssl_context = mtls_handler.build_server_ssl_context()

    logger.info("Démarrage du PEP sur https://%s:%s", config.HOST, config.PORT)
    from common import keepalive_server
    if keepalive_server.use_keepalive_backend():
        keepalive_server.serve(
            app, config.HOST, config.PORT, ssl_context,
            conn_log=os.environ.get("ZT_DEBUG_CONNS") == "1",
        )
    else:
        run_simple(
            config.HOST,
            config.PORT,
            app,
            ssl_context=ssl_context,
            request_handler=PeerCertRequestHandler,
            threaded=True,
        )
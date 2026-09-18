#!/usr/bin/env bash
# Lance l'empilement complet (OPA + Ressource + IdP + PEP) en PHASE PQC (HQC-1,
# Cross-rsdp-128-balanced) avec le BACKEND HTTPS KEEP-ALIVE
# (ZT_WSGI_BACKEND=keepalive, common/keepalive_server.py) et les logs de
# verification des connexions (ZT_DEBUG_CONNS=1).
#
# AUCUN OPENSSL_CONF : le groupe TLS est pilote par le openssl.cnf systeme
# (/usr/local/ssl/openssl.cnf, Groups = hqc1) -- identique a la reference.
#
# Pour les benchmarks de reference (backend Werkzeug, Connection: close),
# utiliser start_services.sh (le code des services n'est pas modifie).
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV=$ROOT/venv/bin/python
LOG_DIR=$ROOT/metrics/run_pqc/logs/keepalive
CA_CERT=$ROOT/pki-pqc/ca/certs/ca.cert.pem

mkdir -p "$LOG_DIR"

for port in 8181 8443 8444 8446; do
    pid=$(ss -tlnp 2>/dev/null | grep ":$port " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
done
sleep 1

# 0. PDP (OPA 1.20.2) -- decision d'autorisation du PEP
(cd "$ROOT" && setsid "$ROOT/opa" run --server \
    --config-file pdp/opa_config.yaml pdp/policies/ --addr :8181 \
    </dev/null >"$LOG_DIR/opa.log" 2>&1) &

# 1. Ressource (mTLS CERT_REQUIRED) -- backend keep-alive
(cd "$ROOT/ressource" && setsid env PKI_DIR=../pki-pqc \
    ZT_WSGI_BACKEND=keepalive ZT_DEBUG_CONNS=1 "$VENV" app.py \
    </dev/null >"$LOG_DIR/ressource.log" 2>&1) &

# 2. IdP (signature post-quantique CROSS) -- backend keep-alive
(cd "$ROOT/idp" && setsid env CRYPTO_MODE=pqc PQC_SIG_ALG=cross-rsdp-128-balanced \
    PKI_DIR=../pki-pqc ZT_WSGI_BACKEND=keepalive ZT_DEBUG_CONNS=1 "$VENV" app.py \
    </dev/null >"$LOG_DIR/idp.log" 2>&1) &

# 3. PEP (validation JWT CROSS) -- backend keep-alive
(cd "$ROOT/pep" && setsid env CRYPTO_MODE=pqc PKI_DIR=../pki-pqc \
    EXPECTED_JWT_ALG=cross-rsdp-128-balanced ZT_WSGI_BACKEND=keepalive \
    ZT_DEBUG_CONNS=1 "$VENV" app.py </dev/null >"$LOG_DIR/pep.log" 2>&1) &

sleep 4
echo "Services PQC lancés (backend zt-keepalive)."
for port in 8181 8443 8444 8446; do
    ss -tlnp 2>/dev/null | grep ":$port " >/dev/null && echo "  :$port OK" || echo "  :$port FAILED"
done
echo "Erreurs dans les logs :"
grep -l "Traceback\|Error\|ERROR" "$LOG_DIR"/*.log 2>/dev/null || echo "  aucune"
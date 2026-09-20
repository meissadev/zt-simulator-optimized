#!/usr/bin/env bash
# Validation des flux de l'architecture dockerisee (micro-segmentation).
#
# Verifie :
#   A. flux AUTORISES  : chaque chemin prevu fonctionne (en reseau, avec les
#                        FQDN ztpqc.lab, TLS HQC-1, verification de la PKI) ;
#   B. flux REFUSES    : les chemins de communication NON prevus par la
#                        micro-segmentation echouent (connexion/DNS refusee) ;
#   C. groupe TLS      : HQC-1 + signature CROSS negocies AU SEIN du reseau.
#
# Usage : bash docker/validate_flows.sh   (depuis la racine du projet)

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

PASS=0
FAIL=0
ok() { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
ko() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }

pexec() { # pexec <container> <python-code>  (stdout renvoye a l'appelant)
  docker compose exec -T "$1" python3 -c "$2" 2>&1
}

echo "== A) FLUX AUTORISES =="

# A1. PEP -> IdP (JWKS, TLS HQC-1, verification CA)
out=$(pexec pep 'import ssl, urllib.request
ctx = ssl.create_default_context(cafile="/pki-pqc/ca/certs/ca.cert.pem")
r = urllib.request.urlopen("https://idp.ztpqc.lab:8444/jwks", context=ctx, timeout=10)
print(r.status, "cross-rsdp-128-balanced" in r.read().decode())')
if [[ "$out" == *"200 True"* ]]; then ok "PEP -> IdP idp.ztpqc.lab:8444/jwks (JWKS CROSS, CA verifiee)"; else ko "PEP -> IdP (JWKS)"; fi

# A2. PEP -> PDP (OPA)
out=$(pexec pep 'import urllib.request
r = urllib.request.urlopen("http://pdp:8181/v1/data/authz/allow", timeout=10)
print(r.status, b"allow" in r.read())')
if [[ "$out" == *"200"* ]]; then ok "PEP -> PDP pdp:8181 (OPA, decision d'autorisation)"; else ko "PEP -> PDP (OPA)"; fi

# A3. PEP -> Ressource (mTLS client pep, SAN ressource.ztpqc.lab, HQC-1)
out=$(pexec pep 'import ssl, urllib.request
ctx = ssl.create_default_context(cafile="/pki-pqc/ca/certs/ca.cert.pem")
ctx.load_cert_chain("/pki-pqc/certs/pep.crt", "/pki-pqc/certs/pep.key")
r = urllib.request.urlopen("https://ressource.ztpqc.lab:8446/api/data", context=ctx, timeout=10)
print(r.status, b"ok" in r.read())')
if [[ "$out" == *"200"* ]]; then ok "PEP -> Ressource ressource.ztpqc.lab:8446 (mTLS, SAN conserve)"; else ko "PEP -> Ressource (mTLS)"; fi

# A4. PEP -> IdP : groupe TLS HQC-1 a l'interieur du reseau (DNS interne)
if docker compose exec -T pep sh -c \
  'echo | openssl s_client -connect idp.ztpqc.lab:8444 -servername idp.ztpqc.lab -CAfile /pki-pqc/ca/certs/ca.cert.pem 2>/dev/null' \
  | grep -q "Negotiated TLS1.3 group: hqc1"; then ok "PEP -> IdP : groupe negocie hqc1 (DNS interne + HQC-1)"; else ko "PEP -> IdP : hqc1 en reseau"; fi

echo "== B) FLUX REFUSES (micro-segmentation) =="

# B1. IdP ne doit PAS atteindre le PDP
out=$(pexec idp 'import socket
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("pdp", 8181)); print("connecte")
except Exception as e: print("refuse", type(e).__name__)')
if [[ "$out" == *"refuse"* ]]; then ok "IdP -> PDP : refuse (pas de reseau partage)"; else ko "IdP -> PDP : ne doit pas passer"; fi

# B2. IdP ne doit PAS atteindre la Ressource
out=$(pexec idp 'import socket
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("ressource.ztpqc.lab", 8446)); print("connecte")
except Exception as e: print("refuse", type(e).__name__)')
if [[ "$out" == *"refuse"* ]]; then ok "IdP -> Ressource : refuse"; else ko "IdP -> Ressource : ne doit pas passer"; fi

# B3. PDP ne doit PAS atteindre l'IdP
out=$(pexec pdp 'import socket
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("idp.ztpqc.lab", 8444)); print("connecte")
except Exception as e: print("refuse", type(e).__name__)')
if [[ "$out" == *"refuse"* ]]; then ok "PDP -> IdP : refuse"; else ko "PDP -> IdP : ne doit pas passer"; fi

# B4. Ressource ne doit PAS atteindre l'IdP
out=$(pexec ressource 'import socket
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("idp.ztpqc.lab", 8444)); print("connecte")
except Exception as e: print("refuse", type(e).__name__)')
if [[ "$out" == *"refuse"* ]]; then ok "Ressource -> IdP : refuse"; else ko "Ressource -> IdP : ne doit pas passer"; fi

# B5. PDP ne doit PAS atteindre la Ressource
out=$(pexec pdp 'import socket
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("ressource.ztpqc.lab", 8446)); print("connecte")
except Exception as e: print("refuse", type(e).__name__)')
if [[ "$out" == *"refuse"* ]]; then ok "PDP -> Ressource : refuse"; else ko "PDP -> Ressource : ne doit pas passer"; fi

# B6. Exterieur (hote) : seuls les ports publies 127.0.0.1:84xx sont ouverts.
nb="$(ss -tln 2>/dev/null | grep -cE "127\.0\.0\.1:(8181|8443|8444|8446) ")"
if [ "$nb" -ge 4 ] && ! ss -tln 2>/dev/null | grep -qE "0\.0\.0\.0:(8181|8443|8444|8446) "; then
  ok "Hote : ports (8181,8443,8444,8446) publies uniquement sur 127.0.0.1"
else
  ko "Hote : publication 127.0.0.1 uniquement"
fi

echo
echo "== RESULTAT : $PASS reussis, $FAIL en echec =="
[ "$FAIL" -eq 0 ] || exit 1
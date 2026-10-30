#!/bin/bash
# validate_v2.sh -- verifie la micro-segmentation et le controle d'acces du
# simulateur v2 (architecture demarree par zt2.sh up).
cd "$(dirname "$0")/.."
ok=0; ko=0
probe() {  # probe <conteneur> <hote> <port> <attendu: open|closed>
    if docker exec "$1" python3 -c "import socket,sys; socket.create_connection(('$2',$3),2)" 2>/dev/null; then got=open; else got=closed; fi
    if [[ $got == "$4" ]]; then ok=$((ok+1)); r=OK; else ko=$((ko+1)); r=ECHEC; fi
    printf '%-6s %-14s -> %-22s %-6s (attendu %s)\n' "$r" "$1" "$2:$3" "$got" "$4"
}
probe zt2-pep       idp.ztpqc.lab        8444 open
probe zt2-pep       pdp.ztpqc.lab        8182 open
probe zt2-pep       pdp.ztpqc.lab        8181 closed   # OPA en local uniquement
probe zt2-pep       ressource.ztpqc.lab  8446 open
probe zt2-pep       pki.ztpqc.lab        8447 open
probe zt2-idp       ressource.ztpqc.lab  8446 closed
probe zt2-idp       pdp.ztpqc.lab        8182 closed
probe zt2-ressource pdp.ztpqc.lab        8182 closed
probe zt2-ressource idp.ztpqc.lab        8444 closed
probe zt2-pdp       ressource.ztpqc.lab  8446 closed
probe zt2-idp       pki.ztpqc.lab        8447 open
probe zt2-ressource pki.ztpqc.lab        8447 open

# Passerelle PDP : seul le CN "pep" est admis.
gw() {  # gw <desc> <cert> <key> <attendu>
    code=$(docker exec zt2-pep python3 -c "
import requests
try:
    r=requests.post('https://pdp.ztpqc.lab:8182/v1/data/authz/allow',json={'input':{}},cert=('$2','$3'),verify='/trust/ca.cert.pem',timeout=5); print(r.status_code)
except Exception as e: print('refus_tls')" 2>/dev/null)
    if [[ $code == "$4" ]]; then ok=$((ok+1)); r=OK; else ko=$((ko+1)); r=ECHEC; fi
    printf '%-6s passerelle PDP, %-28s -> %-9s (attendu %s)\n' "$r" "$1" "$code" "$4"
}
gw "certificat du PEP" /run/zt/pep.crt /run/zt/pep.key 200
# (docker cp ne lit pas les tmpfs : copie par cat)
docker exec zt2-pep mkdir -p /tmp/zt-res
for f in ressource.crt ressource.key; do
    docker exec zt2-ressource cat /run/zt/$f | docker exec -i zt2-pep sh -c "cat > /tmp/zt-res/$f"
done
gw "certificat de la Ressource" /tmp/zt-res/ressource.crt /tmp/zt-res/ressource.key 403
docker exec zt2-pep sh -c 'cd /tmp && openssl req -x509 -newkey "${PKI_KEY_ALG:-rsa:3072}" -nodes -subj /CN=pep -keyout fake.key -out fake.crt -days 1 2>/dev/null'
gw "auto-signe CN=pep" /tmp/fake.crt /tmp/fake.key refus_tls
docker exec zt2-pep rm -rf /tmp/zt-res /tmp/fake.key /tmp/fake.crt
echo "$ok verifications OK, $ko echecs"
[[ $ko == 0 ]]

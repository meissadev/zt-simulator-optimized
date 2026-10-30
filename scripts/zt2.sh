#!/bin/bash
# zt2.sh -- pilotage du simulateur v2 (serveur et client de mesure).
#
#   scripts/zt2.sh tokens                      genere env/tokens.env (une fois par hote)
#   scripts/zt2.sh up <mode> [VAR=val ...]     demarre l'architecture (mode : pqc|classical)
#   scripts/zt2.sh down                        arrete et efface (CA comprise)
#   scripts/zt2.sh ca [fichier]                ancre de confiance (fichier ou stdout)
#   scripts/zt2.sh bench <mode> <cible_ip> <ca> <label> <reuse> [options bench_v2]
#   scripts/zt2.sh matrix <env_label> [N]      matrice complete (SERVER_SSH/SERVER_IP : serveur distant)
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker-compose.v2.yml)
IMG=ztpqc-services:v2
mkdir -p results

cnf() { [[ $1 == pqc ]] && echo /opt/openssl-3.5.8/openssl.cnf || echo /opt/openssl-3.5.8/openssl-classical.cnf; }
alg() { [[ $1 == pqc ]] && echo CROSSrsdp128balanced || echo rsa:3072; }

case "${1:-}" in
tokens)
    {
        for v in TOK_IDP TOK_PEP TOK_RES TOK_PDP TOK_BENCH PKI_ADMIN_TOKEN; do
            echo "$v=$(openssl rand -hex 16)"
        done
    } > env/tokens.env
    chmod 600 env/tokens.env ;;
up)
    mode=$2; shift 2
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    extra=(); [[ -f env/host.env ]] && extra=(--env-file env/host.env)   # ex. PUBLISH_ADDR=0.0.0.0
    env "$@" "${COMPOSE[@]}" --env-file env/$mode.env --env-file env/tokens.env "${extra[@]}" up -d --wait >/dev/null 2>&1
    echo "architecture $mode demarree ($*)" ;;
down)
    "${COMPOSE[@]}" down -v --remove-orphans ;;
ca)
    if [[ -n ${2:-} ]]; then docker exec zt2-pki cat /trust/ca.cert.pem > "$2"
    else docker exec zt2-pki cat /trust/ca.cert.pem; fi ;;
bench)
    mode=$2 ip=$3 ca=$4 label=$5 reuse=$6; shift 6
    set -a; . env/tokens.env; set +a
    docker run --rm --network host \
        --add-host pep.ztpqc.lab:$ip --add-host idp.ztpqc.lab:$ip --add-host pki.ztpqc.lab:$ip \
        -e OPENSSL_CONF="$(cnf $mode)" -e PKI_KEY_ALG="$(alg $mode)" \
        -e PKI_URL=https://pki.ztpqc.lab:18447 -e OCSP_URL=https://pki.ztpqc.lab:18447/ocsp \
        -e ZT_CRED_DIR=/tmp/zt \
        -e TOK_BENCH -e PKI_ADMIN_TOKEN -e ZT_SEND_ROOT="${ZT_SEND_ROOT:-1}" \
        -v "$(realpath "$ca")":/ca.pem:ro -v "$PWD/results":/results \
        $IMG python3 /app/metrics/bench_v2.py --label "$label" --reuse "$reuse" \
        --ca /ca.pem --pep-port 18443 --idp-port 18444 --pki-port 18447 \
        --out "/results/$label.json" "$@" ;;
matrix)
    # Serveur local par defaut ; serveur distant si SERVER_SSH (commande ssh
    # complete) et SERVER_IP sont definis. Les jetons (env/tokens.env) doivent
    # etre identiques sur le client et le serveur.
    env=$2 n=${3:-100}
    IP=${SERVER_IP:-127.0.0.1}
    srv() { if [[ -n ${SERVER_SSH:-} ]]; then $SERVER_SSH "cd ~/zt-simulator-v2 && scripts/zt2.sh $*"; else "$0" "$@"; fi; }
    cfg() {  # cfg <mode> <reuse> <etiquette> "<variables serveur>" [options bench]
        local mode=$1 reuse=$2 tag=$3 vars=$4; shift 4
        srv up "$mode" ZT_UPSTREAM_REUSE="$reuse" $vars
        srv ca > "results/ca-$env-$mode.pem"
        local sr=0; [[ $vars == *ZT_SEND_ROOT=1* ]] && sr=1
        ZT_SEND_ROOT=$sr "$0" bench "$mode" "$IP" "results/ca-$env-$mode.pem" "$env-$mode-$tag" "$reuse" --n "$n" "$@"             > "results/$env-$mode-$tag.log" 2>&1 || echo "ECHEC $env-$mode-$tag (voir le journal)"
        echo "$(date +%T) $env-$mode-$tag termine"
    }
    for mode in ${MODES:-classical pqc}; do
        cfg $mode 1 reuse1 "ZT_SEND_ROOT=0" --revocation
        cfg $mode 0 reuse0 "ZT_SEND_ROOT=0"
        cfg $mode 1 root   "ZT_SEND_ROOT=1" --only handshake
        cfg $mode 1 ttl0   "ZT_SEND_ROOT=0 OCSP_CACHE_TTL=0" --only s2s,throughput --revocation
        cfg $mode 1 noocsp "ZT_SEND_ROOT=0 OCSP_ENABLED=0" --only s2s,throughput
        cfg $mode 1 nagle  "ZT_SEND_ROOT=0 ZT_TCP_NODELAY=0" --only user,s2s
    done
    srv down >/dev/null 2>&1 ;;
*)
    sed -n 2,9p "$0"; exit 1 ;;
esac

#!/bin/bash
# campaign.sh -- campagne de mesures sur des hotes distants (VM, cloud, ...).
#
# S'execute sur un poste Linux "operateur" (la VM de developpement par exemple)
# qui joint les hotes en SSH. Les hotes sont des Ubuntu 24.04 avec Docker
# (deploy/aws/ les cree sur AWS ; deploy/bootstrap_host.sh prepare tout autre
# hote). Fichier de configuration : deploy/hosts.env
#
#   SERVER=ubuntu@203.0.113.10      # hote qui porte l'architecture
#   CLIENT=ubuntu@198.51.100.20     # hote client distant (optionnel)
#   SSH_KEY=~/.ssh/ztpqc_aws        # cle sans phrase de passe
#   N=100                           # echantillons par mesure
#
# Commandes :
#   campaign.sh prepare             code + image vers SERVER et CLIENT, jetons partages
#   campaign.sh local  <label>      matrice complete sur SERVER (client = serveur)
#   campaign.sh remote <label>      matrice reseau : CLIENT -> SERVER
#   campaign.sh here   <label>      matrice reseau : cet hote -> SERVER
#   campaign.sh fetch               rapatrie les resultats dans results/
#   campaign.sh report              agrege results/ (CSV + tableau)
#   campaign.sh all                 prepare, local aws, remote useast, here ici, fetch, report
#
# Les variantes "reseau" (REMOTE_VARIANTS) sont celles dont le resultat depend
# de la distance : reutilisation des connexions, nouvelle connexion par
# requete, chaine avec ou sans racine.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f deploy/hosts.env ]] && . deploy/hosts.env
: "${SERVER:?definir SERVER dans deploy/hosts.env}"
SSH_KEY=${SSH_KEY:-~/.ssh/ztpqc_aws}
SSH_KEY=${SSH_KEY/#\~/$HOME}
N=${N:-100}
REMOTE_VARIANTS=${REMOTE_VARIANTS:-reuse1 reuse0 root}
SSHO=(-i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)
DIR=zt-simulator-v2
IMG=ztpqc-services:v2

r() { local h=$1; shift; ssh "${SSHO[@]}" "$h" "$@"; }
ip_of() { echo "${1#*@}"; }
log() { echo "[$(date +%T)] $*"; }

ship() {  # ship <hote> : code (arbre de travail) + image
    local h=$1
    log "code -> $h"
    tar czf - --exclude=results --exclude=.git --exclude='env/tokens.env' --exclude='env/host.env' \
        --exclude=deploy/aws/.terraform . | r "$h" "mkdir -p $DIR && tar xzf - -C $DIR && mkdir -p $DIR/results"
    # IMAGE_SOURCE : pull (Docker Hub, defaut), ship (image locale envoyee), build
    local src=${IMAGE_SOURCE:-pull}
    [[ ${BUILD_REMOTE:-0} == 1 ]] && src=build
    if [[ $src == pull ]]; then
        log "image depuis Docker Hub sur $h"
        r "$h" "cd $DIR && scripts/zt2.sh pull"
    elif [[ $src == build ]]; then
        log "construction de l'image sur $h (20 a 30 min)"
        r "$h" "cd $DIR && scripts/zt2.sh build"
    else
        log "image -> $h"
        docker image inspect $IMG >/dev/null 2>&1 || scripts/zt2.sh build
        docker save $IMG | zstd -q -T0 -6 | r "$h" "zstd -dc | docker load -q"
    fi
}

case "${1:-}" in
prepare)
    hosts=("$SERVER"); [[ -n ${CLIENT:-} ]] && hosts+=("$CLIENT")
    for h in "${hosts[@]}"; do
        r "$h" "test -f /var/tmp/ready || command -v docker" >/dev/null \
            || { echo "$h : Docker absent (voir deploy/bootstrap_host.sh)"; exit 1; }
        ship "$h"
    done
    log "jetons d'inscription"
    r "$SERVER" "cd $DIR && scripts/zt2.sh tokens && echo PUBLISH_ADDR=0.0.0.0 > env/host.env"
    r "$SERVER" "cat $DIR/env/tokens.env" > env/tokens.env; chmod 600 env/tokens.env
    if [[ -n ${CLIENT:-} ]]; then
        r "$CLIENT" "cat > $DIR/env/tokens.env && chmod 600 $DIR/env/tokens.env" < env/tokens.env
        # le client pilote le serveur (zt2.sh matrix avec SERVER_SSH)
        r "$CLIENT" "mkdir -p ~/.ssh && cat > ~/.ssh/ztpqc_campaign && chmod 600 ~/.ssh/ztpqc_campaign" < "$SSH_KEY"
    fi ;;
local)
    log "matrice locale sur $SERVER ($2)"
    r "$SERVER" "cd $DIR && scripts/zt2.sh matrix $2 $N" ;;
remote)
    : "${CLIENT:?definir CLIENT}"
    log "matrice $CLIENT -> $SERVER ($2)"
    r "$CLIENT" "cd $DIR && SERVER_SSH=\"ssh -i \$HOME/.ssh/ztpqc_campaign -o BatchMode=yes -o StrictHostKeyChecking=accept-new $SERVER\" \\
        SERVER_IP=$(ip_of "$SERVER") VARIANTS='$REMOTE_VARIANTS' scripts/zt2.sh matrix $2 $N" ;;
here)
    log "matrice $(hostname) -> $SERVER ($2)"
    SERVER_SSH="ssh ${SSHO[*]} $SERVER" SERVER_IP=$(ip_of "$SERVER") VARIANTS="$REMOTE_VARIANTS" \
        scripts/zt2.sh matrix "$2" "$N" ;;
fetch)
    mkdir -p results
    for h in "$SERVER" ${CLIENT:-}; do
        r "$h" "cd $DIR/results && tar cf - *.json *.log 2>/dev/null || true" | tar xf - -C results
    done
    log "resultats dans results/" ;;
report)
    python3 metrics/aggregate_v2.py results/ --csv results/summary.csv ;;
all)
    "$0" prepare
    "$0" local "${LOCAL_LABEL:-aws}"
    [[ -n ${CLIENT:-} ]] && "$0" remote "${REMOTE_LABEL:-useast}"
    [[ ${RUN_HERE:-1} == 1 ]] && "$0" here "${HERE_LABEL:-vmaws}"
    "$0" fetch
    "$0" report ;;
*)
    sed -n 2,27p "$0"; exit 1 ;;
esac

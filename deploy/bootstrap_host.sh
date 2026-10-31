#!/bin/bash
# bootstrap_host.sh -- prepare un hote Ubuntu 22.04/24.04 (VM, serveur, autre
# cloud) pour le simulateur : Docker, Compose v2, zstd. A lancer une fois, en
# root ou avec sudo :
#
#   curl -fsSL <depot>/deploy/bootstrap_host.sh | sudo bash
#   ou : sudo bash deploy/bootstrap_host.sh
#
# Equivalent du user_data de deploy/aws/main.tf.
set -euo pipefail
apt-get update -q
apt-get install -y -q docker.io docker-compose-v2 docker-buildx zstd git python3 ca-certificates
systemctl enable --now docker
user=${SUDO_USER:-ubuntu}
id "$user" >/dev/null 2>&1 && usermod -aG docker "$user"
touch /var/tmp/ready
docker --version
docker compose version
echo "hote pret (reconnectez-vous pour appartenir au groupe docker)"

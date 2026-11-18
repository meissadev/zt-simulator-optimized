# Reproduire les mesures du chapitre 4

Toutes les mesures du memoire proviennent de `docker-compose.v2.yml` (architecture),
`metrics/bench_v2.py` (banc), `scripts/zt2.sh` (pilotage d'un hote) et
`scripts/campaign.sh` (campagne multi-hotes). Le meme code sert en mode classique
(X25519 + RSA-3072) et post-quantique (HQC-1 + CROSS-RSDP-128-balanced) ; seul le
fichier `env/<mode>.env` change.

## Prerequis

### Chaque hote qui execute l'architecture ou le banc

| Element | Detail |
|---|---|
| Systeme | Linux x86_64 (amd64). Teste sur Ubuntu 24.04 ; `deploy/bootstrap_host.sh` prend aussi en charge Ubuntu 22.04 |
| Ressources | 2 vCPU et 4 Go de RAM (configuration des mesures du memoire), environ 20 Go de disque |
| Docker | Docker Engine, Docker Compose v2 et `docker-buildx` (ce dernier seulement pour `zt2.sh build`). L'utilisateur doit appartenir au groupe `docker` |
| Outils | `bash`, `git`, `python3`, `openssl` (generation des jetons), `zstd` (seulement avec `IMAGE_SOURCE=ship`) |
| Reseau | Acces a Docker Hub pour `zt2.sh pull` (ou a Internet pour `zt2.sh build`). Ports 18443, 18444 et 18447 libres |

Sur Ubuntu, `sudo bash deploy/bootstrap_host.sh` installe Docker, Compose v2,
buildx, zstd, git et python3, puis ajoute l'utilisateur au groupe `docker`
(se reconnecter ensuite). Python et OpenSSL n'ont pas besoin de version
particuliere sur l'hote : toute la cryptographie s'execute dans l'image.

### En plus, pour une campagne sur plusieurs hotes (section 2)

* Sur le poste qui pilote : `ssh`, `tar`, et une cle SSH **sans phrase de
  passe** acceptee par le serveur et le client.
* Le serveur doit accepter les connexions du client (et du poste, pour
  `campaign.sh here`) sur les ports 18443, 18444 et 18447.
* `campaign.sh here` execute le banc sur le poste lui-meme : il lui faut alors
  aussi Docker et l'image (premier tableau).

### En plus, pour le deploiement sur AWS (section 3)

* Un compte AWS et un profil configure (`aws configure`). Terraform utilise le
  profil `default` ; pour un autre profil, passer `-var aws_profile=<nom>`.
* Terraform 1.5 ou plus recent (fournisseur `hashicorp/aws` 5.x, telecharge par
  `terraform init`), et `curl`.
* Les types d'instances par defaut sont eligibles a l'offre gratuite, mais la
  campagne peut entrainer des frais (trafic entre regions, depassement des
  quotas) : detruire l'infrastructure apres les mesures.

### Pour regenerer les figures

`python3` avec `matplotlib` (`pip install matplotlib`). `aggregate_v2.py`
n'utilise que la bibliotheque standard.

## Images

L'image exacte des mesures est publiee sur Docker Hub (depot public) :

| Tag | Contenu | Digest |
|---|---|---|
| `meissadev/pqc-zt:services-v2` | services (IdP, PEP, PDP, PKI, ressource, banc) | `sha256:110ed54ef576...` |
| `meissadev/pqc-zt:base` | Ubuntu 24.04, OpenSSL 3.5.8, liboqs, oqs-provider | `sha256:e53d477a3ddd...` |

`scripts/zt2.sh pull` la recupere et la renomme `ztpqc-services:v2` (nom attendu
par `docker-compose.v2.yml`). `scripts/zt2.sh build` reconstruit les memes
versions depuis les sources (`docker/Dockerfile.base`, `docker/Dockerfile`).

## Versions figees

| Composant | Version |
|---|---|
| Ubuntu (images) | 24.04, Python 3.12.3 |
| OpenSSL | 3.5.8 |
| liboqs | 0.16.0, commit be7ecb9 de main (18/09/2026) |
| oqs-provider | 36cafae (0.12.0-dev) |
| liboqs-python | 0.16.0 |
| Flask / Werkzeug / requests / urllib3 | 3.1.3 / 3.1.8 / 2.32.3 / 2.8.0 |
| OPA | 1.20.2 (somme SHA-256 verifiee au build) |

## 1. Un seul hote (VM, poste Linux, instance cloud)

```bash
sudo bash deploy/bootstrap_host.sh      # Docker + Compose (une fois)
scripts/zt2.sh pull                     # image des mesures depuis Docker Hub (~1 min)
# ou : scripts/zt2.sh build             # reconstruction complete, 20 a 30 min sur 2 vCPU
scripts/zt2.sh tokens                   # jetons d'inscription (env/tokens.env)
scripts/zt2.sh matrix vm 100            # 12 configurations, environ 25 min
scripts/zt2.sh report                   # results/summary.csv + tableau
scripts/validate_v2.sh                  # (architecture demarree) micro-segmentation
```

`matrix` enchaine, pour chaque mode (classique puis post-quantique), six
variantes :

| Variante | Parametres serveur | Mesures |
|---|---|---|
| `reuse1` | connexions reutilisees, chaine sans racine | tout + revocation (cache OCSP 60 s) |
| `reuse0` | nouvelle connexion TLS par requete | tout |
| `root` | racine envoyee dans la chaine (defaut OpenSSL) | handshakes |
| `ttl0` | OCSP sans cache | service -> service, debit, revocation |
| `noocsp` | OCSP desactive (reference) | service -> service, debit |
| `nagle` | TCP_NODELAY desactive cote serveur | flux utilisateur et service |

Chaque resultat est un fichier `results/<env>-<mode>-<variante>.json`
(medianes, p05, p95, min, max, taille des objets, octets du handshake,
compteurs OCSP du PEP, description de l'hote client).

## 2. Plusieurs hotes (client et serveur distants)

```bash
cp deploy/hosts.env.example deploy/hosts.env   # SERVER, CLIENT, SSH_KEY
scripts/campaign.sh prepare      # code + image + jetons sur les hotes
scripts/campaign.sh local aws    # matrice complete sur SERVER
scripts/campaign.sh remote useast   # CLIENT -> SERVER (variantes reseau)
scripts/campaign.sh here vmaws      # cet hote -> SERVER
scripts/campaign.sh fetch && scripts/campaign.sh report
```

N'importe quelle paire d'hotes SSH convient (deux VM, un serveur sur site, un
autre fournisseur cloud) : seuls Docker et une cle SSH sans phrase de passe sont
necessaires.

## 3. Sur AWS (Terraform)

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/ztpqc_aws
cd deploy/aws
terraform init
terraform apply -var operator_cidr=$(curl -s https://checkip.amazonaws.com)/32
terraform output -raw hosts_env > ../hosts.env && echo "SSH_KEY=~/.ssh/ztpqc_aws" >> ../hosts.env
cd ../.. && scripts/campaign.sh all
cd deploy/aws && terraform destroy -var operator_cidr=...    # ne rien laisser tourner
```

Par defaut : serveur `c7i-flex.large` a Londres (eu-west-2), client `t3.small`
en Virginie (us-east-1), types eligibles a l'offre gratuite. Les groupes de
securite n'ouvrent SSH et les ports du banc (18443, 18444, 18447) qu'a
l'operateur et a l'autre instance. Variables : `deploy/aws/variables.tf`
(regions, types, profil AWS).

## Resultats du memoire

`results-memoire/2026-10-31/` contient les 36 fichiers JSON bruts de la campagne
du chapitre 4 (environnements `vm`, `aws`, `useast`, `vmaws`) et `summary.csv`.
Les figures du chapitre se regenerent avec :

```bash
python3 metrics/plots_v2.py results-memoire/2026-10-31 media/
```

## Precautions de mesure

* Ne rien faire tourner d'autre sur l'hote pendant `matrix` (les mesures
  locales sont sensibles a la charge CPU, notamment sur une VM dont l'hote
  physique est utilise).
* Les health checks ne s'executent qu'au demarrage (un test toutes les 2 s),
  puis toutes les 10 minutes, pour ne pas perturber les mesures.
* `N=100` echantillons par mesure ; les tableaux du memoire donnent la mediane.

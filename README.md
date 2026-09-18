# Simulateur PQC-Zero Trust

Architecture Zero Trust (NIST SP 800-207) avec cryptographie post-quantique
a base de codes correcteurs d'erreurs : **HQC** pour le KEM TLS,
**CROSS** (rsdp-128-balanced) pour les signatures (certificats + JWT),
comparee a une baseline classique **RSA-3072**.

Le banc de mesure couvre deux scenarios :

* **User -> Service** : authentification JWT et acces d'un utilisateur via le
  PEP (tailles, temps d'authentification, latence d'acces, debit) ;
* **Service -> Service** : appel machine a machine en mTLS
  (Service A -> PEP -> PDP -> Service B), avec les memes metriques.

## Architecture

```
                        Plan de controle
                  +--------------------------+
                  |  PDP (OPA, port 8181)    |
                  |  Rego : authz.rego       |
                  +-----+--------------------+
                        |
        Sujet     PEP (port 8443)      Ressource (port 8446)
        ----->  [mTLS opt. + JWT]  --mTLS-->  [mTLS requis]
                        |
                  IdP (port 8444)
                  [auth + JWS]
```

- **PEP** : point de controle unique (fail-closed), authentification
  (mTLS ou JWT Bearer), delegation au PDP, relais mTLS vers la Ressource.
- **IdP** : authentifie l'utilisateur, emet un JWS (RSA ou CROSS selon
  `CRYPTO_MODE`), expose `/jwks`.
- **PDP** : OPA avec `default allow := false`, PA/PE fusionnes
  (limitation documentee).
- **Ressource** : microservice protege, exige mTLS, ne reevalue jamais
  d'autorisation.

## Prerequis

- Ubuntu 24.04 avec OpenSSL 3.x + oqs-provider installe
- liboqs-python dans le venv
- OPA 1.x (binaire `./opa` a la racine)
- bind9 avec zone `ztpqc.lab` (enregistrements : idp, pep, ressource,
  ca -> 192.168.60.133)

## Installation rapide

```bash
cd ~/zt-simulator
source venv/bin/activate
pip install -r requirements.txt
```

## Verification des algorithmes disponibles

```bash
bash pki/scripts/00_check_algorithms.sh
```

Doit confirmer :
- OpenSSL KEM : `hqc1` / Signature : `CROSSrsdp128balanced`
- liboqs-python KEM : `HQC-1` / Signature : `cross-rsdp-128-balanced`

## Generation de la PKI

Les PKI (`pki/`, `pki-pqc/`) ne sont **pas versionnees** : elles sont generees
sur la machine avec les scripts `pki/scripts/` et ignorees par `.gitignore`
(`pki/ca/`, `pki/certs/` et equivalents). Les commandes ci-dessous sont la
seule source de verite pour les creer.

> `generate_ca.sh` ecrase une CA existante apres confirmation : ne le relancez
> pas sur une PKI en service (les services rechargent les certificats au
> demarrage).

### PKI classique (RSA-3072)

```bash
# CA
bash pki/scripts/generate_ca.sh rsa:3072 pki

# Certificats feuille
bash pki/scripts/issue_cert.sh idp rsa:3072 pki
bash pki/scripts/issue_cert.sh pep rsa:3072 pki
bash pki/scripts/issue_cert.sh ressource rsa:3072 pki
bash pki/scripts/issue_cert.sh batch-service rsa:3072 pki
```

### PKI post-quantique (CROSS)

```bash
# CA
bash pki/scripts/generate_ca.sh CROSSrsdp128balanced pki-pqc

# Certificats feuille
bash pki/scripts/issue_cert.sh idp CROSSrsdp128balanced pki-pqc
bash pki/scripts/issue_cert.sh pep CROSSrsdp128balanced pki-pqc
bash pki/scripts/issue_cert.sh ressource CROSSrsdp128balanced pki-pqc
bash pki/scripts/issue_cert.sh batch-service CROSSrsdp128balanced pki-pqc
```

## Configuration TLS : openssl.cnf systeme, aucun OPENSSL_CONF

Contrainte de methodologie : **aucun `OPENSSL_CONF` n'est pose**, ni cote
services ni cote clients. Le `/usr/local/ssl/openssl.cnf` systeme s'applique
partout, ce qui garantit que les deux phases utilisent exactement le meme
chemin de configuration.

Le choix de la phase se fait donc dans `/usr/local/ssl/openssl.cnf`
(fichier root) :

| Phase      | Ligne active                       |
|------------|------------------------------------|
| Classique  | `Groups = x25519:P-256`            |
| PQC        | `Groups = hqc1`                    |

Verification du groupe reellement negocie sur l'IdP vivant :

```bash
# phase classique -> X25519
echo | openssl s_client -connect idp.ztpqc.lab:8444 \
    -CAfile pki/ca/certs/ca.cert.pem 2>/dev/null | grep -i "temp key"
# Peer Temp Key: X25519, 253 bits

# phase PQC -> hqc1
# (la trace TLS cote IdP affiche le groupe hqc1)
```

Les scripts de benchmark utilisent donc le meme openssl.cnf que les services
(aucune surcharge d'environnement) : lancer les mesures **sans** definir
`OPENSSL_CONF`.

## Lancement des services

Le PDP (OPA) ne depend pas de la phase et reste lance une seule fois :

```bash
./opa run --server \
    --config-file pdp/opa_config.yaml \
    pdp/policies/ \
    --addr :8181
```

Les scripts `metrics/run_*/start_services.sh` relancent les trois services
applicatifs (Ressource, IdP, PEP) pour la phase voulue, **sans
`OPENSSL_CONF`** :

```bash
# Phase classique (RSA-3072 + ECDH, PKI_DIR=../pki)
bash metrics/run_classical/start_services.sh

# Phase PQC (CROSS + HQC-1, PKI_DIR=../pki-pqc)
bash metrics/run_pqc/start_services.sh
```

Equivalent manuel (phase classique) :

```bash
cd ressource
PKI_DIR=../pki python app.py

cd idp
CRYPTO_MODE=classical PKI_DIR=../pki python app.py

cd pep
CRYPTO_MODE=classical PKI_DIR=../pki \
    EXPECTED_JWT_ALG=RSA3072-PSS-SHA384 \
    python app.py
```

Equivalent manuel (phase PQC) :

```bash
cd ressource
PKI_DIR=../pki-pqc python app.py

cd idp
CRYPTO_MODE=pqc PQC_SIG_ALG=cross-rsdp-128-balanced \
    PKI_DIR=../pki-pqc python app.py

cd pep
CRYPTO_MODE=pqc PKI_DIR=../pki-pqc \
    EXPECTED_JWT_ALG=cross-rsdp-128-balanced \
    python app.py
```

## Tests manuels rapides

```bash
# Authentification (JWT)
curl -sk https://idp.ztpqc.lab:8444/health
curl -sk -X POST https://idp.ztpqc.lab:8444/authenticate \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"demo123"}' \
    --cacert pki/ca/certs/ca.cert.pem

# Acces via PEP (Bearer token)
TOKEN=$(curl -sk -X POST https://idp.ztpqc.lab:8444/authenticate \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"demo123"}' \
    --cacert pki/ca/certs/ca.cert.pem | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -sk https://pep.ztpqc.lab:8443/api/data \
    -H "Authorization: Bearer $TOKEN" \
    --cacert pki/ca/certs/ca.cert.pem

# Acces via PEP (mTLS service-to-service)
curl -sk https://pep.ztpqc.lab:8443/api/data \
    --cert pki/certs/batch-service.crt \
    --key pki/certs/batch-service.key \
    --cacert pki/ca/certs/ca.cert.pem

# Tests Rego
./opa test pdp/policies/ -v
```

En phase PQC, remplacer les chemins `pki/...` par `pki-pqc/...`.

## Benchmarks

Tous les clients de mesure sont dans `metrics/`. Chacun mesure **une** metrique,
affiche un JSON sur la sortie standard et sa progression sur la sortie d'erreur.
Conventions communes :

- `time.perf_counter()` ;
- mesures **sequentielles**, une **nouvelle connexion HTTPS par iteration**
  (aucune reutilisation / keep-alive / reprise de session) ;
- `--n` : nombre d'iterations independantes (defaut 50) ;
- `--mode {classical,pqc}` pour les tailles et les tests S2S ; les autres
  scripts prennent `--ca-cert` et `--expected-alg` explicitement.

### Vue d'ensemble

| Script                       | Metrique                                   | Sortie |
|------------------------------|--------------------------------------------|--------|
| `bench_sizes.py`             | tailles crypto User -> Service (octets)    | `tailles_cryptographiques` |
| `bench_auth.py`              | temps d'authentification (ms)              | `temps_authentification` |
| `bench_access.py`            | latence d'acces bout-en-bout (ms)          | `latence_acces_bout_en_bout` |
| `bench_throughput.py`        | debit User -> Service (req/s)              | `debit` |
| `bench_s2s_sizes.py`         | tailles crypto Service -> Service (octets) | `tailles_cryptographiques_service_service` |
| `bench_s2s_auth.py`          | temps d'authentification S2S mTLS (ms)     | `temps_authentification_service_service` |
| `bench_s2s_latency.py`       | latence d'acces S2S bout-en-bout (ms)      | `latence_acces_service_service` |
| `bench_s2s_throughput.py`    | debit Service -> Service (req/s)           | `debit_service_service` |

### User -> Service

```bash
# Tailles des cles et certificats
python3 metrics/bench_sizes.py --mode classical      # ou --mode pqc

# Temps d'authentification (IdP -> PEP)
python3 metrics/bench_auth.py --n 50 \
    --ca-cert pki/ca/certs/ca.cert.pem \
    --expected-alg RSA3072-PSS-SHA384

# Latence d'acces bout-en-bout (Client -> PEP -> PDP -> Ressource -> Client)
python3 metrics/bench_access.py --n 50 \
    --ca-cert pki/ca/certs/ca.cert.pem

# Debit (authentification et acces)
python3 metrics/bench_throughput.py --n 50 \
    --ca-cert pki/ca/certs/ca.cert.pem \
    --expected-alg RSA3072-PSS-SHA384
```

En phase PQC, utiliser `--ca-cert pki-pqc/ca/certs/ca.cert.pem` et
`--expected-alg cross-rsdp-128-balanced`.

**T_auth** est chronometre de l'envoi de `POST /authenticate` a l'IdP jusqu'a la
fin de la validation du token par le code du PEP (recuperation `/jwks` +
verification cryptographique de la signature). Le PDP et la Ressource sont
**exclus** du temps d'authentification.

**Latence d'acces** : le token est obtenu **hors chronometrage**, puis la
mesure couvre le GET `/api/data` via le PEP, l'appel au PDP et le relais mTLS
vers la Ressource.

### Service -> Service

Scenario : **Service A = `batch-service`** (cert client mTLS) appelle via le
PEP -> PDP -> **Service B = `ressource`** ; le PEP relaie en mTLS avec
`pep.crt`. Toutes les options de PKI sont deduites de `--mode`
(`pki` / `pki-pqc`).

```bash
# Temps d'authentification mTLS seul (handshake Service A -> Service B)
python3 metrics/bench_s2s_auth.py --mode classical

# Latence d'acces bout-en-bout Service A -> PEP -> PDP -> Service B -> reponse
python3 metrics/bench_s2s_latency.py --mode classical

# Debit S2S (D = succes / T_total)
python3 metrics/bench_s2s_throughput.py --mode classical

# Tailles des elements reellement utilises dans le flux S2S
python3 metrics/bench_s2s_sizes.py --mode classical
```

Remplacer `--mode classical` par `--mode pqc` pour la phase post-quantique.

`bench_s2s_sizes.py` ne mesure que les elements effectivement utilises par le
scenario S2S : certificat Service A, certificat Service B, certificat CA,
cle publique/privee d'authentification, et (PQC uniquement) cle KEM HQC-1.
En classique, les champs KEM sont marques `not_applicable` (ECDHE ephemere).

## Resultats consolides

Chaque phase dispose d'un dossier de resultats :

```
metrics/run_classical/
  results.txt   # rapport lisible (metriques User -> Service et S2S)
  results.json  # meme contenu, exploitable
  sizes.json, auth.json, access.json, throughput.json
  s2s_auth.json, s2s_latency.json, s2s_throughput.json, s2s_sizes.json
  start_services.sh
  logs/
metrics/run_pqc/   # idem
```

Pour (re)genérer ces fichiers, lancer chaque benchmark en redirigeant sa
sortie JSON, puis consolider dans `results.json` / `results.txt`.

### Resultats (N = 50, aucun OPENSSL_CONF)

| Metrique                                  | Classique (RSA-3072/ECDH) | PQC (CROSS/HQC-1) |
|-------------------------------------------|---------------------------|-------------------|
| Auth User -> Service (moyenne)            | 243.087 ms                | 346.313 ms        |
| Latence d'acces bout-en-bout (moyenne)    | 238.873 ms                | 376.098 ms        |
| Debit auth / acces                        | 4.1 / 4.094 req/s         | 2.544 / 2.729 req/s |
| Auth Service -> Service (moyenne)         | 19.758 ms                 | 79.003 ms         |
| Latence d'acces Service -> Service (moy.) | 249.570 ms                | 403.394 ms        |
| Debit Service -> Service                  | 4.006 req/s               | 2.699 req/s       |
| Certificat CA / IdP (DER)                 | 1247 / 1254 B             | 13696 / 13703 B   |
| Cle publique de signature                 | 422 B (SPKI RSA)          | 77 B raw liboqs (SPKI 99 B) |
| Cle privee de signature                   | 1793 B (PKCS#8)           | 136 B (PKCS#8)    |
| Cle KEM publique / privee                 | non applicable            | 2241 / 2321 B     |

Les tailles de certificats PQC (CROSS) sont nettement superieures ; les cles
KEM HQC-1 (2241/2321 B) remplacent les ephemeres ECDHE classiques. Les temps
dependent de la charge de la machine au moment de la mesure.

### Options de `metrics/bench_auth.py`

| Option           | Defaut                     | Description                                   |
|------------------|----------------------------|-----------------------------------------------|
| `--n`            | 50                         | nombre d'authentifications independantes      |
| `--idp-url`      | https://idp.ztpqc.lab:8444 | URL de l'IdP (`/authenticate` et `/jwks`)     |
| `--ca-cert`      | pki/ca/certs/ca.cert.pem   | CA TLS (pki-pqc/... en phase PQC)             |
| `--expected-alg` | selon config PEP           | algorithme attendu (RSA3072-PSS-SHA384, cross-rsdp-128-balanced) |
| `--username`     | alice                      | identifiant (utilisateurs en memoire)         |
| `--password`     | demo123                    | mot de passe                                  |
| `--timeout`      | 10.0                       | timeout HTTP en secondes                      |

Note : le **code** des benchmarks (`metrics/*.py`, `metrics/run_*/start_services.sh`)
est versionne ; seuls les **resultats** (`metrics/**/*.json`, `*.txt`, `logs/`)
sont exclus par `.gitignore`.

## Scenario CONNECTION_REUSE / KEEP_ALIVE (optimisation etape 1)

**Probleme mesure** : Werkzeug (`run_simple`, backend historique) impose
`Connection: close` sur chaque reponse : UNE requete HTTPS par connexion TLS.
En PQC, chaque nouvelle requete rejoue donc l'handshake TLS avec le KEM HQC-1
(plusieurs centaines de ms) -- par iteration, et non une seule fois.

**Backend keep-alive** (`common/keepalive_server.py`) : serveur HTTPS -> WSGI
stdlib (threaded) qui BOUCLE plusieurs requetes sur la meme connexion TLS.
Il sert exactement les memes applications Flask, les memes certificats et
les memes `SSLContext` (construits par les services, non modifies) ; aucun
composant du simulateur n'est change. Selection par variable d'environnement :

```
ZT_WSGI_BACKEND=keepalive   # backend keep-alive (scenario CONNECTION_REUSE)
ZT_WSGI_BACKEND=            # defaut : Werkzeug, comportement historique
ZT_DEBUG_CONNS=1            # logs : chaque NOUVELLE CONNEXION TLS et chaque requete
```

**Methode** (definition des metriques INCHANGEE, `time.perf_counter()`, N=50) :
1. etablissement de la connexion (1re requete sur connexion neuve, handshake
   HQC-1 inclus) mesure SEPAREMENT (`establishment_ms`) ;
2. N echantiillons chronometres UNIQUEMENT sur la connexion deja etablie
   (aucun handshake rejoue) ;
3. attestation de la reutilisation reelle de la connexion via les compteurs
   urllib3 du pool (`num_connections` / `num_requests`) et les logs serveur
   (`ZT_DEBUG_CONNS=1`) -- chaque JSON de resultat porte `reuse_verified`.

**Lancement** (phase PQC, backend keep-alive) :

```bash
bash metrics/run_pqc/start_services_keepalive.sh   # OPA + Ressource + IdP + PEP
# verification du groupe HQC-1 sur les services vivants :
echo | openssl s_client -connect 127.0.0.1:8444 -servername idp.ztpqc.lab \
       -CAfile pki-pqc/ca/certs/ca.cert.pem 2>/dev/null | grep "Negotiated TLS"
```

**Benchmarks du scenario** (`*_keepalive.py`, N=50, sortie JSON) :

```bash
CA=pki-pqc/ca/certs/ca.cert.pem
venv/bin/python metrics/bench_auth_keepalive.py            --n 50 --ca-cert $CA --expected-alg cross-rsdp-128-balanced
venv/bin/python metrics/bench_access_keepalive.py          --n 50 --ca-cert $CA
venv/bin/python metrics/bench_throughput_keepalive.py      --n 50 --ca-cert $CA --expected-alg cross-rsdp-128-balanced
venv/bin/python metrics/bench_s2s_auth_keepalive.py        --mode pqc --n 50 --ca-cert $CA
venv/bin/python metrics/bench_s2s_latency_keepalive.py     --mode pqc --n 50 --ca-cert $CA
venv/bin/python metrics/bench_s2s_throughput_keepalive.py  --mode pqc --n 50 --ca-cert $CA
```

**Resultats PQC (N=50, meme machine)** : base de comparaison = scripts de
reference sur backend Werkzeug, mesures sur cette machine (reproduits sur
cette meme machine dans `metrics/run_pqc/baseline_on_werkzeug/`) :

| Metrique (connexion tiede)                     | Werkzeug (ref.) | KEEP_ALIVE     | Gain  |
|------------------------------------------------|-----------------|----------------|-------|
| Auth User -> Service (moyenne)                 | 334.034 ms      | 107.558 ms     | x3.1  |
| Latence d'acces bout-en-bout (moyenne)         | 368.096 ms      | 71.963 ms      | x5.1  |
| Debit auth / acces                             | 2.874 / 2.873   | 9.052 / 13.654 | x3.2 / x4.8 |
| Latence d'acces Service -> Service (moyenne)   | 365.820 ms      | 62.685 ms      | x5.8  |
| Debit Service -> Service                       | 2.814 req/s     | 15.970 req/s   | x5.7  |
| Handshakes mTLS S2S (pour 50 requetes)         | 50              | 1              | --    |

Etablissement (1 seule fois, non amorti dans les echantiillons) :
auth 240.426 ms, acces 361.757 ms, S2S latence 222.845 ms. Rapport complet et
jeux de donnees bruts : `metrics/run_pqc/keepalive/` (`results.txt`,
`results.json`, `*_keepalive.json`, `logs/keepalive/`).

**Perimetre** : cette etape ne touche QUE le transport TLS. Cache JWKS
persistant, connexion PDP persistante et autres optimisations du plan sont
volontairement HORS perimetre (etapes suivantes, a valider explicitement).

## Ports

| Service    | Port | Protocole        |
|------------|------|------------------|
| PEP        | 8443 | HTTPS (mTLS opt) |
| IdP        | 8444 | HTTPS            |
| Ressource  | 8446 | HTTPS (mTLS req) |
| PDP (OPA)  | 8181 | HTTP             |

## Limitations documentees

- **Werkzeug** : serveur de developpement, pas de production.
- **PA/PE fusionnes** : pas de composant PA separe (architecture simplifiee).
- **JWS hors registre IANA** : l'algorithme CROSS n'a pas d'identifiant IANA
  (extension assumee, documentee dans le memoire).
- **Utilisateurs statiques** : identifiants en memoire (prototype de recherche).

## Arborescence

```
zt-simulator/
  venv/
  pki/                        # PKI classique (RSA-3072)
    scripts/
      00_check_algorithms.sh
      generate_ca.sh
      issue_cert.sh
    ca/
    certs/
  pki-pqc/                    # PKI post-quantique (CROSS)
    ca/
    certs/
  idp/
    app.py, config.py, jwt_signer.py, requirements.txt
  pep/
    app.py, config.py, jwks_client.py, pdp_client.py,
    mtls_handler.py, jwt_signer.py, requirements.txt
  pdp/
    policies/authz.rego, authz_test.rego
    opa_config.yaml
  ressource/
    app.py, openssl_pqc.cnf, requirements.txt
  common/
    keepalive_server.py       # backend HTTPS->WSGI keep-alive (CONNECTION_REUSE)
  metrics/                    # code versionne ; resultats ignores (.gitignore)
    _keepalive_lib.py         # session persistante + comptage connexions urllib3
    bench_sizes.py            # tailles crypto User -> Service
    bench_auth.py             # temps d'authentification
    bench_access.py           # latence d'acces bout-en-bout
    bench_throughput.py       # debit User -> Service
    bench_s2s_sizes.py        # tailles crypto Service -> Service
    bench_s2s_auth.py         # temps d'authentification S2S (mTLS)
    bench_s2s_latency.py      # latence d'acces S2S
    bench_s2s_throughput.py   # debit Service -> Service
    bench_auth_keepalive.py   # scenario CONNECTION_REUSE (connexion persistante)
    bench_access_keepalive.py
    bench_throughput_keepalive.py
    bench_s2s_auth_keepalive.py
    bench_s2s_latency_keepalive.py
    bench_s2s_throughput_keepalive.py
    run_classical/            # resultats + start_services.sh (RSA-3072)
    run_pqc/                  # resultats + start_services.sh (CROSS/HQC-1)
      start_services_keepalive.sh   # OPA + services (backend keep-alive)
      keepalive/                    # resultats du scenario CONNECTION_REUSE
      baseline_on_werkzeug/         # controle : scripts de ref. sur Werkzeug
      baseline_on_keepalive_server/ # controle : scripts de ref. sur backend KA
  README.md
```

> `ressource/openssl_pqc.cnf` est conserve pour reference historique ; il n'est
> plus utilise (la configuration TLS provient desormais du openssl.cnf systeme).

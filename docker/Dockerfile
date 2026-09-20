# Image construite pour dockeriser l'architecture PQC : les quatre services
# du simulateur tournent dans des conteneurs relies par des reseaux Docker
# dedies (micro-segmentation) tout en conservant le domaine ztpqc.lab, la PKI
# existante (pki-pqc, certs idp/pep/ressource.ztpqc.lab), OpenSSL 3.5.8 +
# oqs-provider + liboqs, HQC-1, CROSS-rsdp-128-balanced et le backend HTTPS
# keep-alive.
#
# La pile PQC presente dans l'image de base `pqc` (OpenSSL 3.5.8, oqs-provider,
# liboqs, KEM HQC-1) n'est PAS reconstruite. Cette image ne fait que :
#   * installer les dependances Python applicatives (meme versions que l'hote) ;
#   * completer le openssl.cnf de l'image avec la section TLS systeme
#     (ssl_conf -> Groups = hqc1), miroir du /usr/local/ssl/openssl.cnf de
#     l'hote, necessaire pour que le module ssl de Python negocie HQC-1 ;
#   * copier le code des services (idp, pep, ressource, common), la politique
#     OPA et le binaire opa (1.20.2) fourni par l'hote.

FROM pqc:latest

# Dependances Python (pins = idp/pep/ressource/requirements.txt de l'hote).
# PEP 668 : --break-system-packages requis sur Ubuntu 24.04 (image mono-usage).
RUN python3 -m pip install --no-cache-dir --break-system-packages \
        'Flask==3.1.3' \
        'Werkzeug==3.1.8' \
        'cryptography==50.0.1' \
        'requests==2.32.3' \
        'liboqs-python==0.16.0'

# HQC-1 pour le module ssl de Python : ajouter ssl_conf/Groups = hqc1 au
# openssl.cnf de l'image (oqsprovider y est deja active).
RUN python3 - <<'PY'
import io
path = "/opt/openssl-3.5.8/openssl.cnf"
s = io.open(path, encoding="utf-8").read()
if "ssl_module" not in s:
    s = s.replace(
        "providers = provider_sect",
        "providers = provider_sect\nssl_conf = ssl_module",
        1,
    )
if "[tls_system_default]" not in s:
    s += (
        "\n[ssl_module]\nsystem_default = tls_system_default\n\n"
        "[tls_system_default]\nGroups = hqc1\n"
    )
io.open(path, "w", encoding="utf-8").write(s)
print("openssl.cnf: ssl_module/hqc1 OK")
PY

# Code des services + politique OPA.
COPY common/   /app/common/
COPY idp/      /app/idp/
COPY pep/      /app/pep/
COPY ressource/ /app/ressource/
COPY pdp/      /app/pdp/

# Binaire OPA 1.20.2 (fourni avec le projet, cf. .gitignore) pour le
# conteneur PDP.
COPY opa /usr/local/bin/opa
RUN chmod 755 /usr/local/bin/opa

WORKDIR /app
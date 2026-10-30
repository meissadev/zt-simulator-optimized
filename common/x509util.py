"""
x509util.py -- verification de signatures X.509 / OCSP, classiques ou
post-quantiques (v2).

Le module ssl de Python verifie deja les chaines de certificats pendant le
handshake (via OpenSSL + oqs-provider). En revanche, la reponse OCSP est
verifiee par le PEP lui-meme : ce module fournit la verification d'une
signature quelle que soit la famille :
  * CROSS (OID oqs-provider) -> liboqs-python ;
  * RSA (PKCS#1 v1.5 ou PSS)  -> bibliotheque cryptography.

asn1crypto sert a decoder les structures sans interpreter la cle publique
(asn1crypto ne connait pas les OID post-quantiques).
"""

import hashlib

from asn1crypto import core, pem, x509

# OID -> nom liboqs des signatures post-quantiques utilisees par le projet.
PQC_SIG_OIDS = {
    "1.3.6.1.4.1.62245.2.1.1.2.2": "cross-rsdp-128-balanced",
}


def load_cert(data: bytes) -> x509.Certificate:
    """Charge un certificat PEM ou DER."""
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    return x509.Certificate.load(data)


def load_cert_file(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return load_cert(f.read())


def spki_der(cert: x509.Certificate) -> bytes:
    return cert["tbs_certificate"]["subject_public_key_info"].dump()


def raw_public_key(cert: x509.Certificate) -> bytes:
    """Octets bruts de la cle publique (contenu du BIT STRING)."""
    return core.Sequence.load(spki_der(cert))[1].contents[1:]


def subject_der(cert: x509.Certificate) -> bytes:
    return cert["tbs_certificate"]["subject"].dump()


def key_hash_sha1(cert: x509.Certificate) -> bytes:
    return hashlib.sha1(raw_public_key(cert)).digest()


def verify_signature(signed: bytes, signature: bytes, sig_alg, issuer: x509.Certificate) -> bool:
    """
    Verifie `signature` sur `signed` avec la cle publique de `issuer`.
    sig_alg : champ SignedDigestAlgorithm (asn1crypto) de l'objet signe.
    """
    oid = sig_alg["algorithm"].dotted
    if oid in PQC_SIG_OIDS:
        import oqs
        with oqs.Signature(PQC_SIG_OIDS[oid]) as verifier:
            return bool(verifier.verify(signed, signature, raw_public_key(issuer)))

    # Signatures classiques : on delegue a cryptography.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    pub = load_der_public_key(spki_der(issuer))
    name = sig_alg.signature_algo
    try:
        if name == "rsassa_pss":
            params = sig_alg["parameters"]
            h = getattr(hashes, params["hash_algorithm"]["algorithm"].native.upper())()
            pub.verify(signature, signed,
                       padding.PSS(mgf=padding.MGF1(h), salt_length=params["salt_length"].native), h)
        elif name == "rsassa_pkcs1v15":
            h = getattr(hashes, sig_alg.hash_algo.upper())()
            pub.verify(signature, signed, padding.PKCS1v15(), h)
        elif name == "ecdsa":
            h = getattr(hashes, sig_alg.hash_algo.upper())()
            pub.verify(signature, signed, ec.ECDSA(h))
        else:
            return False
    except InvalidSignature:
        return False
    return True


def verify_cert_issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    return verify_signature(cert["tbs_certificate"].dump(), cert["signature_value"].native,
                            cert["signature_algorithm"], issuer)

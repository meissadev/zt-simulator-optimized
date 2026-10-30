"""
httpclient.py -- sessions HTTPS partageant un contexte TLS par identite.

requests/urllib3 creent un contexte TLS (SSL_CTX) pour chaque nouvelle
connexion. Avec oqs-provider, SSL_CTX_new coute environ 100 ms, car OpenSSL
charge tous les algorithmes du fournisseur. Un client reel prepare son contexte
une fois (CA de confiance + certificat client) et le reutilise pour toutes ses
connexions : c'est ce que fait ce module. Chaque nouvelle connexion fait
toujours un handshake complet (pas de reprise de session).

Les appelants ne passent ni verify= ni cert= aux requetes : la CA et le
certificat sont deja dans le contexte (les systemes de confiance par defaut ne
sont pas charges).
"""

import ssl
import threading

import requests
from requests.adapters import HTTPAdapter

from common import tlsopt

_contexts = {}
_lock = threading.Lock()


def context(ca: str, cert=None) -> ssl.SSLContext:
    key = (ca, tuple(cert) if cert else None)
    with _lock:
        ctx = _contexts.get(key)
        if ctx is None:
            ctx = ssl.create_default_context(cafile=ca)
            if cert:
                ctx.load_cert_chain(*cert)
            ctx = _contexts[key] = tlsopt.apply(ctx)
        return ctx


class _ContextAdapter(HTTPAdapter):
    def __init__(self, ctx, **kw):
        self._zt_ctx = ctx
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kw):
        kw["ssl_context"] = self._zt_ctx
        return super().init_poolmanager(*args, **kw)


def session(ca: str, cert=None) -> requests.Session:
    s = requests.Session()
    s.mount("https://", _ContextAdapter(context(ca, cert)))
    return s

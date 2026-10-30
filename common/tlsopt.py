"""
tlsopt.py -- reglage de la chaine de certificats envoyee pendant le handshake.

Par defaut, OpenSSL complete la chaine du serveur avec les certificats trouves
dans le magasin de confiance, racine comprise (auto-chain). Or la racine est
deja connue du client (ancre de confiance) : RFC 8446, section 4.4.2, permet de
l'omettre. Avec CROSS, la racine pese environ 13,5 Ko par handshake.

ZT_SEND_ROOT=0 desactive l'auto-chain (SSL_MODE_NO_AUTO_CHAIN) : seule la
feuille est envoyee. Le module ssl de Python n'expose pas ce mode ; on passe
par ctypes sur le SSL_CTX sous-jacent.
"""

import ctypes
import os
import ssl

SSL_CTRL_MODE = 33
SSL_MODE_NO_AUTO_CHAIN = 0x8
SEND_ROOT = os.environ.get("ZT_SEND_ROOT", "1") == "1"


def _ctx_ptr(ctx: ssl.SSLContext) -> int:
    # struct PySSLContext { PyObject_HEAD; SSL_CTX *ctx; ... }
    return ctypes.c_void_p.from_address(id(ctx) + 2 * ctypes.sizeof(ctypes.c_void_p)).value


def apply(ctx: ssl.SSLContext) -> ssl.SSLContext:
    if SEND_ROOT:
        return ctx
    lib = ctypes.CDLL(ssl._ssl.__file__)          # dlsym parcourt libssl lie a _ssl
    fn = lib.SSL_CTX_ctrl
    fn.restype, fn.argtypes = ctypes.c_long, [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
    fn(_ctx_ptr(ctx), SSL_CTRL_MODE, SSL_MODE_NO_AUTO_CHAIN, None)
    return ctx


def _patch_urllib3():
    """Applique le reglage aux contextes clients crees par urllib3 (requests)."""
    import urllib3.connection
    import urllib3.util.ssl_ as u
    orig = u.create_urllib3_context
    if getattr(orig, "_zt", False):
        return

    def create(*a, **k):
        return apply(orig(*a, **k))
    create._zt = True
    u.create_urllib3_context = create
    urllib3.connection.create_urllib3_context = create


if not SEND_ROOT:
    _patch_urllib3()

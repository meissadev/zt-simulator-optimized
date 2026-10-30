"""
common/keepalive_server.py -- backend de service HTTPS -> WSGI avec support
HTTP/1.1 keep-alive (plusieurs requetes sur une meme connexion TLS).

Pourquoi ce module :
- Werkzeug (``run_simple``, backend historique) traite UNE requete par
  connexion et envoie systematiquement ``Connection: close`` : il est donc
  IMPOSSIBLE de reutiliser une connexion TLS entre deux requetes avec lui.
- Ce backend est le point d'entree du scenario CONNECTION_REUSE (metriques
  *_keepalive) : il sert EXACTEMENT les memes applications Flask, les memes
  certificats, les memes ``SSLContext`` (construits par chaque service, non
  modifies) et la meme extraction du CN client (``SSL_CLIENT_CN`` via
  ``getpeercert()``, comme ``PeerCertRequestHandler`` de Werkzeug).

Selection du backend par variable d'environnement :
    ZT_WSGI_BACKEND=keepalive   -> ce serveur (connexions persistantes)
    (defaut, valeur absente)    -> Werkzeug ``run_simple`` (comportement
                                   historique identique au projet d'origine)

Validation / logs de debug (nombre de handshakes, nombre de requetes) :
    ZT_DEBUG_CONNS=1            -> journalise chaque nouvelle connexion
                                   TCP/TLS acceptee et chaque requete.

Implementation : serveur threadé (http.server.ThreadingHTTPServer) dont les
connexions acceptees sont enveloppees TLS (``SSLContext`` du service) puis
confiees a un handler HTTP/1.1 qui BOUCLE sur la meme connexion tant que le
client ne demande pas la fermeture. L'enveloppe WSGI est produite a la main
(framing HTTP completement maitrise : Content-Length toujours present, corps
tamponne, corps de requete consomme/draine) pour garantir un keep-alive
correct -- c'est le seul objectif de ce module.
"""

import os
import socket
import ssl
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


import time

# v2 : duree de vie maximale d'une connexion TLS reutilisee (secondes).
TCP_NODELAY = os.environ.get("ZT_TCP_NODELAY", "1") == "1"
MAX_CONN_LIFETIME = float(os.environ.get("ZT_MAX_CONN_LIFETIME", "900"))


def use_keepalive_backend():
    """True si ZT_WSGI_BACKEND=keepalive (sinon défaut : Werkzeug)."""
    return os.environ.get("ZT_WSGI_BACKEND", "").strip().lower() == "keepalive"


_conn_lock = threading.Lock()
_conn_seq = 0
_req_seq = 0


def _next_conn_seq():
    global _conn_seq
    with _conn_lock:
        _conn_seq += 1
        return _conn_seq


def _next_req_seq():
    global _req_seq
    with _conn_lock:
        _req_seq += 1
        return _req_seq


class _CountingInput:
    """Wrapper de rfile pour compter les octets de corps effectivement lus."""

    def __init__(self, rfile):
        self._rfile = rfile
        self.read_total = 0

    def read(self, size=-1):
        data = self._rfile.read(size)
        self.read_total += len(data)
        return data

    def readline(self, size=-1):
        data = self._rfile.readline(size)
        self.read_total += len(data)
        return data

    def readlines(self, hint=-1):
        data = self._rfile.readlines(hint)
        self.read_total += sum(len(line) for line in data)
        return data

    def __iter__(self):
        return self


class KeepAliveRequestHandler(BaseHTTPRequestHandler):
    """Handler HTTP/1.1 : boucle keep-alive sur la connexion etablie."""

    protocol_version = "HTTP/1.1"
    server_version = "zt-keepalive/1.0"
    sys_version = ""
    timeout = 30
    close_connection = False

    # --- handshake TLS dans le thread de la connexion (v2) -------------------
    # Le handshake n'est plus fait dans la boucle d'acceptation : un handshake
    # post-quantique lent ne bloque plus les autres clients.

    def setup(self):
        self._born = time.monotonic()
        self._hs_ok = True
        try:
            self.request.do_handshake()
        except (ssl.SSLError, OSError, socket.timeout) as exc:
            self._hs_ok = False
            if self.server.conn_log:
                print("[zt-keepalive] handshake TLS refuse : %s" % exc,
                      file=sys.stderr, flush=True)
        super().setup()

    def _lifetime_exceeded(self):
        return (time.monotonic() - self._born) > MAX_CONN_LIFETIME

    # --- boucle keep-alive --------------------------------------------------

    def handle(self):
        if not self._hs_ok:
            self.close_connection = True
            return
        try:
            while not self.close_connection:
                try:
                    self.handle_one_request()
                except (socket.timeout, BrokenPipeError, ConnectionResetError,
                        OSError) as exc:
                    break
        finally:
            self.close_connection = True

    # --- routage des methodes ----------------------------------------------

    def do_GET(self):
        self._run_wsgi()

    def do_HEAD(self):
        self._run_wsgi(head_only=True)

    def do_POST(self):
        self._run_wsgi()

    def do_PUT(self):
        self._run_wsgi()

    def do_DELETE(self):
        self._run_wsgi()

    def do_PATCH(self):
        self._run_wsgi()

    # --- execution WSGI -----------------------------------------------------

    def _build_environ(self):
        env = {
            "REQUEST_METHOD": self.command,
            "SCRIPT_NAME": "",
            "SERVER_NAME": self.server.server_name,
            "SERVER_PORT": str(self.server.server_port),
            "SERVER_PROTOCOL": self.request_version,
            "SERVER_SOFTWARE": self.server_version,
            "REMOTE_ADDR": self.client_address[0],
            "REMOTE_HOST": "",
            "REMOTE_PORT": str(self.client_address[1]),
            "CONTENT_LENGTH": "",
            "CONTENT_TYPE": "text/plain",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": self.server.wsgi_server_scheme,
            "wsgi.input": _CountingInput(self.rfile),
            "wsgi.errors": sys.stderr,
            "wsgi.multithread": True,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }

        scheme, netloc, path, query, _frag = urllib.parse.urlsplit(self.path)
        env["PATH_INFO"] = urllib.parse.unquote(path, "iso-8859-1")
        env["QUERY_STRING"] = query

        content_type = self.headers.get("Content-Type")
        if content_type:
            env["CONTENT_TYPE"] = content_type
        content_length = self.headers.get("Content-Length")
        if content_length:
            env["CONTENT_LENGTH"] = content_length

        for key, value in self.headers.items():
            up_key = key.replace("-", "_").upper()
            stripped = value.strip()
            if up_key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                continue
            http_key = "HTTP_" + up_key
            env[http_key] = env[http_key] + "," + stripped if http_key in env else stripped

        peer_cert = self.connection.getpeercert()
        cn = None
        if peer_cert:
            for part in peer_cert.get("subject", []):
                for k, v in part:
                    if k == "commonName":
                        cn = v
        env["SSL_CLIENT_CN"] = cn
        # v2 : certificat client complet (DER), pour la verification OCSP.
        env["SSL_CLIENT_CERT_DER"] = (
            self.connection.getpeercert(binary_form=True) if cn else None
        )
        return env

    def _run_wsgi(self, head_only=False):
        try:
            if self.command is None:
                self.close_connection = True
                return

            environ = self._build_environ()
            write_called = []
            chunks = []

            def start_response(status, response_headers, exc_info=None):
                if exc_info is not None:
                    exc_info[2].traceback.tb_frame
                write_called.append((status, response_headers))

                def write(data):
                    if data:
                        chunks.append(data)

                return write

            try:
                app_iter = self.server.application(environ, start_response)
                try:
                    for data in app_iter:
                        if data:
                            chunks.append(data)
                finally:
                    if hasattr(app_iter, "close"):
                        app_iter.close()
            except BrokenPipeError:
                self.close_connection = True
                return
            except Exception:
                import traceback
                traceback.print_exc(file=sys.stderr)
                self._send_simple_error(500, "Internal Server Error")
                return

            if not write_called:
                self._send_simple_error(500, "Internal Server Error")
                return

            status_line, response_headers = write_called[0]
            try:
                code = int(status_line.split(" ", 1)[0])
            except (ValueError, IndexError):
                code = 500
                status_line = "500 Internal Server Error"

            body = b"".join(chunks)

            headers = []
            seen = set()
            has_length = False
            for key, value in response_headers:
                if "--" in key or ("\n" in key) or ("\r" in key):
                    continue
                lower = key.lower()
                if lower == "content-length":
                    has_length = True
                if lower in seen:
                    continue
                seen.add(lower)
                headers.append((key, value))

            if not has_length:
                headers.append(("Content-Length", str(len(body))))
            headers.sort(key=lambda kv: kv[0].lower() != "content-length")

            # v2 : la connexion est fermee si le client le demande
            # (Connection: close) ou si sa duree de vie maximale est atteinte
            # (SP 800-207A : connexion bornee a 15-30 min ou a la duree du
            # certificat).
            if self._lifetime_exceeded():
                self.close_connection = True
            self.send_response_only(code, status_line.split(" ", 1)[1] if " " in status_line else None)
            for key, value in headers:
                if key.lower() == "connection":
                    continue
                self.send_header(key, value)
            self.send_header("Connection", "close" if self.close_connection else "keep-alive")
            self.end_headers()

            if not head_only and body:
                self.wfile.write(body)
            self.wfile.flush()

            # Drain du corps de requete non consomme (indispensable pour que
            # la boucle keep-alive lise correctement la requete suivante).
            expected = int(environ.get("CONTENT_LENGTH") or 0)
            consumed = environ["wsgi.input"].read_total
            remaining = expected - consumed
            if remaining > 0:
                self.rfile.read(remaining)

            if self.server.conn_log:
                seq = _next_req_seq()
                print(
                    "[zt-keepalive] requete #%d : %s %s -> %d (%d B) sur connexion etablie"
                    % (seq, self.command, self.path, code, len(body)),
                    file=sys.stderr, flush=True,
                )
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self.close_connection = True
        except Exception:
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.close_connection = True

    def _send_simple_error(self, code, message):
        body = ("%d %s" % (code, message)).encode("latin-1")
        self.send_response_only(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def log_message(self, format, *args):
        pass


class KeepAliveHTTPServer(ThreadingHTTPServer):
    """Serveur HTTPS threadé : wraps TLS des connexions acceptées + comptage."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, application, ssl_context,
                 server_name=None, conn_log=False):
        self.application = application
        self.ssl_context = ssl_context
        self.conn_log = conn_log
        self.wsgi_server_scheme = "https"
        super().__init__(server_address, KeepAliveRequestHandler)
        self.server_name = server_name or socket.getfqdn(self.server_address[0])
        self.server_port = self.server_address[1]

    def get_request(self):
        sock, addr = super().get_request()
        try:
            sock.settimeout(15)
            # Sans TCP_NODELAY, l'en-tete et le corps de la reponse partent en
            # deux segments : Nagle retient le second jusqu'a l'ACK du premier,
            # que le client differe (~40 ms sous Linux).
            if TCP_NODELAY:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn = self.ssl_context.wrap_socket(
                sock, server_side=True, do_handshake_on_connect=False)
        except ssl.SSLError:
            try:
                sock.close()
            except OSError:
                pass
            raise
        if self.conn_log:
            seq = _next_conn_seq()
            print(
                "[zt-keepalive] NOUVELLE CONNEXION TLS #%d (handshake TLS complet) de %s"
                % (seq, "%s:%s" % (addr[0], addr[1])),
                file=sys.stderr, flush=True,
            )
        return conn, addr


def serve(app, host, port, ssl_context, server_name=None,
          conn_log=False):
    """Lance le backend keep-alive en boucle (bloquant, comme run_simple)."""
    from common import tlsopt
    tlsopt.apply(ssl_context)
    httpd = KeepAliveHTTPServer(
        (host, port), app, ssl_context,
        server_name=server_name, conn_log=conn_log,
    )
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
"""
bench_v2.py -- banc de mesure unique du simulateur v2.

S'execute dans l'image ztpqc-services:v2 (OpenSSL 3.5.8 + oqs-provider), sur
n'importe quel hote client. Les noms *.ztpqc.lab sont resolus vers l'hote
serveur par --add-host (docker run).

Mesures (N echantillons chacune) :
  sizes      : tailles des objets (certificats DER, JWT, JWKS, reponse OCSP) ;
  handshake  : handshake TLS 1.3 vers le PEP, sans et avec certificat client
               (mTLS) : duree, octets envoyes/recus, et temps de connexion TCP
               (une estimation de l'aller-retour reseau, RTT) ;
  user       : obtention d'un jeton (IdP) puis acces via le PEP (JWT) ;
  s2s        : acces service -> service via le PEP (mTLS + OCSP) ;
  throughput : requetes/s avec C clients concurrents pendant D secondes ;
  revocation : (option) delai entre la revocation et le refus effectif.

--reuse 1 : chaque client garde sa connexion TLS (keep-alive) ;
--reuse 0 : nouvelle connexion TLS a chaque requete (pire cas).
"""

import argparse
import json
import os
import socket
import ssl
import statistics
import sys
import threading
import time

sys.path.insert(0, "/app")

import requests

from common import enroll, tlsopt, x509util


def stats(xs):
    xs = list(xs)
    if not xs:
        return {"n": 0}
    s = sorted(xs)
    q = lambda p: s[min(len(s) - 1, int(round(p * (len(s) - 1))))]
    return {"n": len(xs), "mean": round(statistics.mean(xs), 3),
            "median": round(statistics.median(xs), 3),
            "stdev": round(statistics.stdev(xs), 3) if len(xs) > 1 else 0.0,
            "p05": round(q(0.05), 3), "p95": round(q(0.95), 3),
            "min": round(s[0], 3), "max": round(s[-1], 3)}


def host_info():
    info = {"node": socket.gethostname(), "cpus": os.cpu_count()}
    try:
        with open("/proc/cpuinfo") as f:
            info["cpu"] = next(l.split(":", 1)[1].strip() for l in f if l.startswith("model name"))
        with open("/proc/meminfo") as f:
            info["mem_kb"] = int(f.readline().split()[1])
    except Exception:
        pass
    return info


class Bench:
    def __init__(self, a):
        self.a = a
        self.ca = a.ca
        self.pep = "https://pep.ztpqc.lab:%d" % a.pep_port
        self.idp = "https://idp.ztpqc.lab:%d" % a.idp_port
        self.res = {"label": a.label, "reuse": a.reuse, "n": a.n, "send_root": tlsopt.SEND_ROOT,
                    "started": time.time(), "host": host_info()}

    # ------------------------------------------------------------ outils --
    def session(self, cert=None):
        s = requests.Session()
        s.verify = self.ca
        if cert:
            s.cert = cert
        return s

    def timed(self, fn, n, reuse, cert=None):
        """Execute fn(session) n fois ; renvoie les durees en ms."""
        out, errors = [], 0
        shared = self.session(cert) if reuse else None
        if shared is not None:
            fn(shared)                       # etablissement hors mesure
        for _ in range(n):
            s = shared or self.session(cert)
            t0 = time.perf_counter()
            try:
                r = fn(s)
                ok = r.status_code < 400
            except requests.RequestException:
                ok = False
            dt = (time.perf_counter() - t0) * 1000
            if shared is None:
                s.close()
            if ok:
                out.append(dt)
            else:
                errors += 1
        return out, errors

    def hdr(self, reuse):
        return {} if reuse else {"Connection": "close"}

    # ---------------------------------------------------------- mesures ---
    def enroll_client(self):
        t0 = time.perf_counter()
        self.cert = enroll.enroll("batch-service", token=self.a.token)
        self.res["enroll_ms"] = round((time.perf_counter() - t0) * 1000, 1)

    def get_token(self, s, reuse=True):
        return s.post(self.idp + "/authenticate", json={"username": "alice", "password": "demo123"},
                      headers=self.hdr(reuse), timeout=30)

    def sizes(self):
        sz = {}
        with open(self.ca, "rb") as f:
            sz["ca_cert_der"] = len(x509util.load_cert(f.read()).dump())
        with open(self.cert[0], "rb") as f:
            sz["client_cert_der"] = len(x509util.load_cert(f.read()).dump())
        ctx = ssl.create_default_context(cafile=self.ca)
        with socket.create_connection((self.a.host, self.a.pep_port), 10) as raw:
            with ctx.wrap_socket(raw, server_hostname="pep.ztpqc.lab") as t:
                sz["pep_cert_der"] = len(t.getpeercert(binary_form=True))
                sz["tls_version"] = t.version()
                sz["cipher"] = t.cipher()[0]
        s = self.session()
        tok = self.get_token(s).json()["access_token"]
        self.token = tok
        sz["jwt"] = len(tok)
        sz["jwks"] = len(s.get(self.idp + "/jwks", timeout=10).content)
        # Reponse OCSP vue du client (meme repondeur que celui du PEP).
        from common.ocsp_client import OCSPChecker
        chk = OCSPChecker(self.ca)
        with open(self.cert[0], "rb") as f:
            der = x509util.load_cert(f.read()).dump()
        t0 = time.perf_counter()
        chk.check(der)
        sz["ocsp_response"] = chk.stats["last_size"]
        sz["ocsp_client_fetch_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        self.res["sizes"] = sz

    def handshake(self, with_cert):
        ctx = tlsopt.apply(ssl.create_default_context(cafile=self.ca))
        if with_cert:
            ctx.load_cert_chain(*self.cert)
        tcp, hs, sent, recv = [], [], [], []
        for _ in range(self.a.n):
            t0 = time.perf_counter()
            sock = socket.create_connection((self.a.host, self.a.pep_port), 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            t1 = time.perf_counter()
            inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
            obj = ctx.wrap_bio(inc, out, server_hostname="pep.ztpqc.lab")
            b_out = b_in = 0
            while True:
                try:
                    obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    data = out.read()
                    if data:
                        sock.sendall(data)
                        b_out += len(data)
                    chunk = sock.recv(65536)
                    if not chunk:
                        raise ConnectionError("fermeture pendant le handshake")
                    b_in += len(chunk)
                    inc.write(chunk)
            data = out.read()           # Finished du client (+ Certificate en mTLS)
            if data:
                sock.sendall(data)
                b_out += len(data)
            t2 = time.perf_counter()
            sock.close()
            tcp.append((t1 - t0) * 1000)
            hs.append((t2 - t1) * 1000)
            sent.append(b_out)
            recv.append(b_in)
        key = "handshake_mtls" if with_cert else "handshake_server_auth"
        self.res[key] = {"tcp_connect_ms": stats(tcp), "tls_ms": stats(hs),
                         "bytes_client_to_server": stats(sent),
                         "bytes_server_to_client": stats(recv),
                         "tls_over_rtt": round(statistics.median(hs) / max(statistics.median(tcp), 1e-3), 2)}

    def user(self):
        r = self.a.reuse
        tok_ms, e1 = self.timed(lambda s: self.get_token(s, r), self.a.n, r)
        hdr = dict(self.hdr(r), Authorization="Bearer " + self.token)
        acc_ms, e2 = self.timed(lambda s: s.get(self.pep + "/api/data", headers=hdr, timeout=30),
                                self.a.n, r)
        self.res["user_token"] = dict(stats(tok_ms), errors=e1)
        self.res["user_access"] = dict(stats(acc_ms), errors=e2)

    def s2s(self):
        r = self.a.reuse
        ms, e = self.timed(lambda s: s.get(self.pep + "/api/data", headers=self.hdr(r), timeout=30),
                           self.a.n, r, cert=self.cert)
        self.res["s2s_access"] = dict(stats(ms), errors=e)

    def throughput(self, kind):
        r, stop = self.a.reuse, time.time() + self.a.duration
        counts, errs, lat = [0] * self.a.conc, [0] * self.a.conc, [[] for _ in range(self.a.conc)]
        cert = self.cert if kind == "s2s" else None
        hdr = dict(self.hdr(r))
        if kind == "user":
            hdr["Authorization"] = "Bearer " + self.token

        def worker(i):
            s = self.session(cert) if r else None
            while time.time() < stop:
                ss = s or self.session(cert)
                t0 = time.perf_counter()
                try:
                    ok = ss.get(self.pep + "/api/data", headers=hdr, timeout=30).status_code == 200
                except requests.RequestException:
                    ok = False
                if s is None:
                    ss.close()
                if ok:
                    counts[i] += 1
                    lat[i].append((time.perf_counter() - t0) * 1000)
                else:
                    errs[i] += 1

        th = [threading.Thread(target=worker, args=(i,)) for i in range(self.a.conc)]
        t0 = time.time()
        for t in th:
            t.start()
        for t in th:
            t.join()
        el = time.time() - t0
        self.res["throughput_" + kind] = {
            "concurrency": self.a.conc, "seconds": round(el, 2),
            "requests": sum(counts), "errors": sum(errs),
            "req_per_s": round(sum(counts) / el, 2),
            "latency_ms": stats([x for l in lat for x in l])}

    def pep_metrics(self):
        try:
            return self.session().get(self.pep + "/_zt/metrics", timeout=10).json()
        except Exception as exc:
            return {"error": str(exc)}

    def revocation(self):
        """Inscrit un service, le revoque, mesure le delai jusqu'au refus."""
        crt = enroll.enroll("revoked-service", token=self.a.token)
        s = self.session(crt)
        first = s.get(self.pep + "/api/data", timeout=30).status_code
        pki = "https://pki.ztpqc.lab:%d" % self.a.pki_port
        t_rev = time.time()
        rv = self.session().post(pki + "/revoke", json={"token": self.a.admin_token,
                                                       "name": "revoked-service"}, timeout=30).json()
        refused_after, codes = None, []
        while time.time() - t_rev < self.a.revocation_wait:
            c = self.session(crt).get(self.pep + "/api/data", timeout=30).status_code
            codes.append(c)
            if c in (401, 403):
                refused_after = round(time.time() - t_rev, 2)
                break
            time.sleep(0.5)
        self.res["revocation"] = {"status_before": first, "revoked": rv,
                                  "refused_after_s": refused_after, "polls": len(codes)}

    def run(self):
        self.enroll_client()
        self.sizes()
        m0 = self.pep_metrics()
        if "handshake" in self.a.only:
            self.handshake(False)
            self.handshake(True)
        if "user" in self.a.only:
            self.user()
        if "s2s" in self.a.only:
            self.s2s()
        if "throughput" in self.a.only:
            self.throughput("user")
            self.throughput("s2s")
        self.res["pep_metrics_before"], self.res["pep_metrics_after"] = m0, self.pep_metrics()
        if self.a.revocation:
            self.revocation()
        self.res["finished"] = time.time()
        return self.res


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--label", required=True)
    p.add_argument("--host", default="pep.ztpqc.lab")
    p.add_argument("--pep-port", type=int, default=8443)
    p.add_argument("--idp-port", type=int, default=8444)
    p.add_argument("--pki-port", type=int, default=8447)
    p.add_argument("--ca", default="/trust/ca.cert.pem")
    p.add_argument("--token", default=os.environ.get("TOK_BENCH", ""))
    p.add_argument("--admin-token", default=os.environ.get("PKI_ADMIN_TOKEN", ""))
    p.add_argument("--reuse", type=int, default=1)
    p.add_argument("--n", type=int, default=100)
    p.add_argument("--conc", type=int, default=4)
    p.add_argument("--duration", type=float, default=15)
    p.add_argument("--only", default="handshake,user,s2s,throughput")
    p.add_argument("--revocation", action="store_true")
    p.add_argument("--revocation-wait", type=float, default=120)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    os.environ.setdefault("CA_CERT", a.ca)
    enroll.CA_CERT = a.ca
    res = Bench(a).run()
    with open(a.out, "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k in ("label", "sizes")}, indent=1))

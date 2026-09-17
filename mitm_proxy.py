#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kwrt 解密代理（记录请求 + 返回正文）
- 透明模式：80/443 被 nft 重定向到本进程的端口，用 SO_ORIGINAL_DST 取真实目标
- 显式模式：也可当普通 HTTP 代理用（curl -x / 设备填代理）
- 用现有 MITM CA 动态签发证书终结 TLS，还原明文后再转发
- 把「请求方法/URL/请求头/请求体 + 响应状态/响应头/响应体」写进 /tmp/mitm-body.jsonl
"""
import os
import re
import ssl
import sys
import json
import time
import zlib
import socket
import struct
import hashlib
import datetime
import threading

def _default_ca(ext):
    """CA 默认路径：兼容老位置（squid 目录）与新位置（/etc/mitm/ca），
    免得服务单元和环境变量不一致时找不到证书。"""
    for p in ("/etc/squid/ssl/mitm-ca." + ext, "/etc/mitm/ca/mitm-ca." + ext):
        if os.path.exists(p):
            return p
    return "/etc/mitm/ca/mitm-ca." + ext


CA_CERT = os.environ.get("MITM_CA_CERT") or _default_ca("crt")
CA_KEY = os.environ.get("MITM_CA_KEY") or _default_ca("key")
CERT_DIR = os.environ.get("MITM_CERT_DIR", "/tmp/mitm-certs")
OUT = os.environ.get("MITM_OUT", "/tmp/mitm-body.jsonl")
HTTP_PORT = int(os.environ.get("MITM_HTTP_PORT", "8080"))
HTTPS_PORT = int(os.environ.get("MITM_HTTPS_PORT", "8443"))
MAX_BODY = int(os.environ.get("MITM_MAX_BODY", "200000"))
MAX_SNIPPET = int(os.environ.get("MITM_MAX_SNIPPET", "0"))          # 0 = 不额外截断，正文按抓到的原样存
HARD_TEXT_CAP = int(os.environ.get("MITM_HARD_TEXT_CAP", str(8 * 1024 * 1024)))  # 解码后正文字符上限（防解压炸弹）
REQ_BUFFER = int(os.environ.get("MITM_REQ_BUFFER", "262144"))       # 请求体先缓冲多少，超出则流式转发
CAP_TEXT_MAX = int(os.environ.get("MITM_CAP_TEXT", "2097152"))      # 文本响应抓取上限（原始字节，2MB）
CAP_BIN_MAX = int(os.environ.get("MITM_CAP_BIN", "2048"))           # 二进制响应抓取前缀上限
MAX_LOG_BYTES = int(os.environ.get("MITM_MAX_LOG", str(8 * 1024 * 1024)))  # 记录文件上限（/tmp 是内存盘！）
KEEP_LOG_LINES = int(os.environ.get("MITM_KEEP_LINES", "400"))      # 超限时最多保留最后多少条（仍受字节预算约束）
MAX_CTX = 300

# ---- 可预览二进制资源（图片 / PDF / 文档）----
# 抓下来的图片等存到 /tmp 下的独立目录，网页上可以直接看图、下载文档。
BLOB_DIR = os.environ.get("MITM_BLOB_DIR", "/tmp/mitm-blobs")
BLOB_MAX = int(os.environ.get("MITM_BLOB_MAX", str(1024 * 1024)))        # 单个文件上限
BLOB_TOTAL = int(os.environ.get("MITM_BLOB_TOTAL", str(16 * 1024 * 1024)))  # 目录总量上限（/tmp 是内存盘）

ORIG_DST_OPT = 80
SO_ORIGINAL_DST = 80

CONF_DIR = os.environ.get("MITM_CONF", "/etc/mitm")
MODE_FILE = os.path.join(CONF_DIR, "mode")
DOMAINS_FILE = os.path.join(CONF_DIR, "domains.txt")
BYPASS_FILE = os.path.join(CONF_DIR, "auto-bypass.txt")
LOGCFG = os.path.join(CONF_DIR, "logcfg")
LOG_ENABLE_FILE = os.path.join(CONF_DIR, "log-enable")

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CJK_RE = re.compile(r"[\u3000-\u303f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef]{2,}")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
# 合法 HTTP 请求行：METHOD SP TARGET SP HTTP/1.x
HTTP_REQ_RE = re.compile(r"^[A-Z]{3,10} \S+ HTTP/1\.[01]$")

_lock = threading.Lock()
_ca_key = None
_ca_cert = None
_ctx_cache = {}
_seq = 0
_emit_n = 0
_emit_bytes = 0              # 距上次裁剪累计写入的字节数
_active = 0


def log(*a):
    sys.stderr.write("[mitm] " + " ".join(str(x) for x in a) + "\n")
    sys.stderr.flush()


# ----------------------------------------------------------------- 策略：解哪些域名
_policy = {"stamp": None, "mode": "all", "domains": []}


def load_policy():
    """读取 /etc/mitm/mode 与 /etc/mitm/domains.txt（按 mtime 缓存）。"""
    try:
        stamp = 0.0
        for p in (MODE_FILE, DOMAINS_FILE):
            try:
                stamp = max(stamp, os.path.getmtime(p))
            except OSError:
                pass
        if _policy["stamp"] == stamp:
            return _policy
        mode = "all"
        try:
            with open(MODE_FILE) as f:
                mode = (f.read().strip().lower() or "all")
        except OSError:
            mode = "all"
        doms = []
        try:
            with open(DOMAINS_FILE) as f:
                for ln in f:
                    ln = ln.strip().lower()
                    if ln and not ln.startswith("#"):
                        doms.append(ln.lstrip(".").split("/")[0])
        except OSError:
            doms = []
        _policy.update(stamp=stamp, mode=mode, domains=doms)
    except Exception:
        pass
    return _policy


def is_target(host):
    """mode=list  只解密列表内的域名（显式点名，优先级最高，不受自动放行影响）
    mode=exclude 全部解密，但排除名下与「自动放行」的域名透传
    mode=all     全部解密，但「自动放行」的域名仍透传（自愈）"""
    pol = load_policy()
    mode = pol["mode"]
    h = (host or "").lower().strip(".")

    def _in_list():
        if not h:
            return False
        for d in pol["domains"]:
            if h == d or h.endswith("." + d):
                return True
        return False

    if mode == "list":
        return _in_list()

    # 其它模式：曾被客户端拒绝证书的域名（证书固定）一律原样透传
    if h and is_bypassed(h):
        return False
    if mode != "exclude":
        return True
    return not _in_list()


# ------------------------------------------------------- 自动放行（证书固定自愈）
_bypass = set()
_bypass_loaded = False

# 二级后缀：这些情况下「主域名」取最后三段
SECOND_LEVEL = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.jp", "ne.jp", "or.jp", "co.uk", "org.uk", "me.uk",
    "com.hk", "org.hk", "com.tw", "org.tw", "com.au", "net.au",
    "com.sg", "com.my", "co.kr", "com.br", "com.mo",
}


def parent_domain(h):
    """取可注册主域名：img.pddpic.com -> pddpic.com；a.x.com.cn -> x.com.cn。
    已经是主域名则返回 None（不放大范围）。IP 不处理。"""
    h = (h or "").lower().strip(".")
    if IPV4_RE.match(h) or ":" in h:
        return None
    parts = [p for p in h.split(".") if p]
    if len(parts) < 3:
        return None
    if all(p.isdigit() for p in parts):
        return None
    last2 = ".".join(parts[-2:])
    if last2 in SECOND_LEVEL and len(parts) >= 4:
        parent = ".".join(parts[-3:])
    else:
        parent = last2
    if len(parent) < 4 or "." not in parent or parent.split(".")[-1].isdigit():
        return None
    return parent


def is_bypassed(h):
    """精确或子域匹配自动放行名单。"""
    if not h:
        return False
    for b in _bypass:
        if h == b or h.endswith("." + b):
            return True
    return False


def load_bypass():
    global _bypass_loaded
    if _bypass_loaded:
        return
    _bypass_loaded = True
    try:
        with open(BYPASS_FILE) as f:
            for ln in f:
                ln = ln.strip().lower()
                if ln and not ln.startswith("#"):
                    _bypass.add(ln.lstrip("."))
    except OSError:
        pass


def mark_bypass(host):
    """记录一个解密失败（客户端拒绝我们的证书）的域名，之后对该域名放行。
    同时放行其父域名，避免同一 App 的几百个子域逐个失败。"""
    h = (host or "").lower().strip(".").split(":")[0]
    if not h:
        return
    new = []
    with _lock:
        for cand in (h, parent_domain(h)):
            if cand and cand not in _bypass:
                _bypass.add(cand)
                new.append(cand)
    if not new:
        return
    try:
        with open(BYPASS_FILE, "a") as f:
            for cand in new:
                f.write(cand + "\n")
    except Exception:
        pass
    log("auto-bypass (pinned?):", ",".join(new))


# ----------------------------------------------------------------- 证书
def load_ca():
    global _ca_key, _ca_cert
    if _ca_key is None:
        _ca_key = serialization.load_pem_private_key(open(CA_KEY, "rb").read(), password=None)
        _ca_cert = x509.load_pem_x509_certificate(open(CA_CERT, "rb").read())
    return _ca_key, _ca_cert


def _safe(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "unknown"


_leaf_key = None


def get_leaf_key():
    """所有叶子证书共用一个密钥，省掉每次 RSA 生成的耗时（弱 CPU 上很关键）。"""
    global _leaf_key
    if _leaf_key is None:
        _leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _leaf_key


def leaf_context(host):
    if not host:
        host = "unknown"
    with _lock:
        c = _ctx_cache.get(host)
        if c:
            return c
    os.makedirs(CERT_DIR, exist_ok=True)
    crt = os.path.join(CERT_DIR, _safe(host) + ".crt")
    key = os.path.join(CERT_DIR, _safe(host) + ".key")
    if not (os.path.exists(crt) and os.path.exists(key)):
        ca_key, ca_cert = load_ca()
        pk = get_leaf_key()
        try:
            ip = host.strip("[]")
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) or ":" in ip:
                import ipaddress
                san = [x509.IPAddress(ipaddress.ip_address(ip))]
                cn = ip
            else:
                san = [x509.DNSName(host)]
                cn = host
        except Exception:
            san = [x509.DNSName(host)]
            cn = host
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn[:64])]))
             .issuer_name(ca_cert.subject)
             .public_key(pk.public_key())
             .serial_number(x509.random_serial_number())
             .add_extension(x509.SubjectAlternativeName(san), critical=False)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(
                 digital_signature=True, content_commitment=False, key_encipherment=True,
                 data_encipherment=False, key_agreement=False, key_cert_sign=False,
                 crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(pk.public_key()), critical=False)
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=825)))
        try:
            ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                                critical=False)
        except Exception:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                                critical=False)
        cert = b.sign(ca_key, hashes.SHA256())
        with open(crt, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            f.write(open(CA_CERT, "rb").read())   # 链里带上 CA
        with open(key, "wb") as f:
            f.write(pk.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with _lock:
        if len(_ctx_cache) > MAX_CTX:
            _ctx_cache.clear()
        _ctx_cache[host] = ctx
    return ctx


def client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def sni_bytes(host):
    """python3-light 缺 encodings.idna，传 bytes 可绕开 ssl 的 idna 编码。"""
    try:
        return host.encode("ascii")
    except Exception:
        try:
            return host.encode("idna")
        except Exception:
            return host.encode("utf-8")


# ----------------------------------------------------------------- 工具
def parse_tls_sni(buf):
    try:
        if len(buf) < 6 or buf[0] != 22:
            return None
        rlen = struct.unpack(">H", buf[3:5])[0]
        hs = buf[5:5 + rlen]
        if len(hs) < 4 or hs[0] != 1:
            return None
        p = 4 + 2 + 32
        if p >= len(hs):
            return None
        sid = hs[p]
        p += 1 + sid
        cs = struct.unpack(">H", hs[p:p + 2])[0]
        p += 2 + cs
        cm = hs[p]
        p += 1 + cm
        if p + 2 > len(hs):
            return None
        ext_total = struct.unpack(">H", hs[p:p + 2])[0]
        p += 2
        end = min(len(hs), p + ext_total)
        while p + 4 <= end:
            et, el = struct.unpack(">HH", hs[p:p + 4])
            p += 4
            ed = hs[p:p + el]
            p += el
            if et == 0 and len(ed) >= 5:
                nl = struct.unpack(">H", ed[3:5])[0]
                return ed[5:5 + nl].decode("ascii", "replace")
        return None
    except Exception:
        return None


def peek_sni(sock, timeout=8.0):
    """在不消费数据的前提下窥探 ClientHello 里的 SNI。"""
    sock.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            b = sock.recv(8192, socket.MSG_PEEK)
        except Exception:
            return None
        if not b:
            return None
        buf = b
        if len(buf) >= 5:
            rlen = struct.unpack(">H", buf[3:5])[0]
            if len(buf) >= 5 + rlen:
                break
        time.sleep(0.03)
    return parse_tls_sni(buf)


def orig_dst(sock):
    """取被重定向前的原始目标（透明模式）。"""
    for level in (0, 6):
        try:
            data = sock.getsockopt(level, SO_ORIGINAL_DST, 16)
        except Exception:
            continue
        if not data or len(data) < 8:
            continue
        port = struct.unpack(">H", data[2:4])[0]
        ip = socket.inet_ntoa(data[4:8])
        if port and ip and not ip.startswith("127."):
            return ip, port
    return None, None


class Buf:
    def __init__(self, sock):
        self.s = sock
        self.b = b""

    def readline(self, limit=65536):
        while b"\r\n" not in self.b and b"\n" not in self.b:
            ch = self.s.recv(4096)
            if not ch:
                break
            self.b += ch
            if len(self.b) > limit:
                break
        i = self.b.find(b"\n")
        if i < 0:
            out, self.b = self.b, b""
            return out
        out, self.b = self.b[:i + 1], self.b[i + 1:]
        return out

    def read(self, n):
        while len(self.b) < n:
            ch = self.s.recv(min(65536, max(1, n - len(self.b))))
            if not ch:
                break
            self.b += ch
        out, self.b = self.b[:n], self.b[n:]
        return out

    def read_until_eof(self, cap=MAX_BODY * 4):
        while len(self.b) < cap:
            try:
                ch = self.s.recv(65536)
            except Exception:
                break
            if not ch:
                break
            self.b += ch
        out, self.b = self.b, b""
        return out


def read_headers(buf):
    raw = b""
    while True:
        line = buf.readline()
        if not line:
            break
        raw += line
        if line in (b"\r\n", b"\n"):
            break
        if len(raw) > 65536:
            break
    text = raw.decode("iso-8859-1", "replace")
    lines = [l for l in text.split("\r\n") if l != ""]
    if not lines:
        lines = [l for l in text.split("\n") if l != ""]
    if not lines:
        return None, None, {}
    first = lines[0]
    headers = {}
    order = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            k = k.strip()
            headers[k] = v.strip()
            order.append(k)
    return first, raw, headers


def read_body(buf, headers, is_request, buffer_limit=None):
    """读请求体。buffer_limit 控制「先缓冲多少」：
    - 缓冲得下就一次读完（好记录）；
    - 超出则只缓冲这么多，剩下的由调用方流式转发（不破坏数据）。
    """
    if buffer_limit is None:
        buffer_limit = MAX_BODY
    te = (headers.get("Transfer-Encoding") or headers.get("transfer-encoding") or "").lower()
    cl = headers.get("Content-Length") or headers.get("content-length")
    if "chunked" in te:
        out = b""
        while True:
            sz = buf.readline().strip()
            if not sz:
                break
            try:
                n = int(sz.split(b";")[0], 16)
            except Exception:
                break
            if n == 0:
                buf.readline()
                break
            out += buf.read(n)
            buf.readline()
            if len(out) > buffer_limit:
                break
        return out
    if cl:
        try:
            n = int(cl)
        except Exception:
            return b""
        if n <= 0:
            return b""
        return buf.read(min(n, buffer_limit))
    if not is_request:
        return buf.read_until_eof()
    return b""


# ---------------------------------------------------- 可预览二进制（图片/文档）
_IMG_EXT = {"jpeg": "jpg", "jpg": "jpg", "png": "png", "gif": "gif", "webp": "webp",
            "bmp": "bmp", "svg+xml": "svg", "x-icon": "ico", "vnd.microsoft.icon": "ico",
            "avif": "avif", "heic": "heic"}


def blob_kind(ctype):
    """判断这个类型值不值得存下来给网页看。返回 (kind, ext) 或 None。"""
    c = (ctype or "").lower().split(";")[0].strip()
    if not c:
        return None
    if c.startswith("image/"):
        sub = c[6:].strip()
        return ("image", _IMG_EXT.get(sub, "bin"))
    if c == "application/pdf":
        return ("pdf", "pdf")
    for t, e in (("msword", "doc"), ("wordprocessingml", "docx"),
                 ("ms-excel", "xls"), ("spreadsheetml", "xlsx"),
                 ("ms-powerpoint", "ppt"), ("presentationml", "pptx")):
        if t in c:
            return ("doc", e)
    return None


def _blob_prune():
    """目录超量就按 mtime 从旧到新删（/tmp 是内存盘，必须有上限）。"""
    try:
        items, tot = [], 0
        for n in os.listdir(BLOB_DIR):
            p = os.path.join(BLOB_DIR, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            items.append((st.st_mtime, st.st_size, p))
            tot += st.st_size
        if tot <= BLOB_TOTAL:
            return
        items.sort()
        for _mt, sz, p in items:
            if tot <= BLOB_TOTAL:
                break
            try:
                os.remove(p)
                tot -= sz
            except OSError:
                pass
    except Exception:
        pass


def blob_write(data, ctype):
    """存下可预览的二进制，返回 id（内容 sha1 前 16 位 + 扩展名，天然去重）。"""
    k = blob_kind(ctype)
    if not k or not data or len(data) > BLOB_MAX:
        return None
    kind, ext = k
    bid = hashlib.sha1(data).hexdigest()[:16] + "." + ext
    p = os.path.join(BLOB_DIR, bid)
    try:
        if not os.path.isdir(BLOB_DIR):
            os.makedirs(BLOB_DIR, exist_ok=True)
        if not os.path.exists(p):
            with open(p, "wb") as f:
                f.write(data)
            _blob_prune()
        return bid
    except Exception:
        return None


def _is_texty(ctype):
    """响应是否可能含可读文本（决定抓多少前缀）。"""
    c = (ctype or "").lower()
    if not c:
        return True
    for t in ("text/", "json", "xml", "javascript", "x-www-form-urlencoded",
              "html", "plain", "csv", "graphql", "svg"):
        if t in c:
            return True
    return False


def decode_prefix(data, headers, limit=None):
    """对「可能被截断」的响应前缀做容错解码（gzip/deflate 用 decompressobj，允许不完整）。"""
    if not data:
        return None, None, 0
    if limit is None:
        limit = MAX_SNIPPET
    # limit <= 0 表示不额外截断，只受 HARD_TEXT_CAP 保护
    eff = limit if limit and limit > 0 else HARD_TEXT_CAP
    enc = (headers.get("Content-Encoding") or headers.get("content-encoding") or "").lower()
    raw = data
    if "gzip" in enc or "x-gzip" in enc:
        try:
            raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data)
        except Exception:
            raw = data
    elif "deflate" in enc:
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                raw = zlib.decompressobj(wbits).decompress(data)
                break
            except Exception:
                raw = data
    # br/zstd 等不支持 -> 直接当二进制
    if "br" in enc or "zstd" in enc:
        return None, None, len(data)
    text = None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            t = raw.decode("utf-8", "ignore")
            sb = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
            if t and sb / max(1, len(t)) >= 0.85:
                text = t
        except Exception:
            text = None
        if text is None:
            try:
                t = raw.decode("latin-1")
                ok = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
                if t and ok / max(1, len(t)) >= 0.9:
                    text = t
            except Exception:
                text = None
    if text is None:
        return None, None, len(data)
    cn = list(dict.fromkeys(CJK_RE.findall(text)))[:8] or None
    return text[:eff], cn, len(data)


def decode_body(data, headers):
    if not data:
        return None, None, 0
    enc = (headers.get("Content-Encoding") or headers.get("content-encoding") or "").lower()
    raw = data
    if "gzip" in enc:
        try:
            raw = zlib.decompress(data, 16 + zlib.MAX_WBITS)
        except Exception:
            try:
                raw = zlib.decompress(data)
            except Exception:
                raw = data
    elif "deflate" in enc:
        try:
            raw = zlib.decompress(data)
        except Exception:
            try:
                raw = zlib.decompress(data, -zlib.MAX_WBITS)
            except Exception:
                raw = data
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
        try:
            t = raw.decode("latin-1")
            ok = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
            if t and ok / len(t) >= 0.9:
                text = t
        except Exception:
            text = None
    if text is None:
        return None, None, len(data)
    snip = text[:4000]
    cn = list(dict.fromkeys(CJK_RE.findall(text)))[:8] or None
    return snip, cn, len(data)


def _log_limits():
    """日志保留配置，运行时读取（面板可改）：第一行字节上限，第二行保留条数。"""
    maxb, keep = MAX_LOG_BYTES, KEEP_LOG_LINES
    try:
        parts = [x.strip() for x in open(LOGCFG).read().splitlines() if x.strip()]
        if parts and parts[0].isdigit():
            maxb = max(64 * 1024, int(parts[0]))
        if len(parts) >= 2 and parts[1].isdigit():
            keep = max(20, int(parts[1]))
    except Exception:
        pass
    return maxb, keep


def _trim_log():
    """超限就丢最旧的记录。

    两条约束同时生效：① 最多保留 keep_n 条；② 总字节数不得超过 maxb。
    /tmp 是 tmpfs（内存盘），单条正文可能上百 KB，所以**必须**按字节卡，
    否则光按条数限制，400 条大正文能吃掉上百 MB 内存。
    """
    try:
        maxb, keep_n = _log_limits()
        if os.path.getsize(OUT) <= maxb:
            return
        with open(OUT, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        keep = lines[-keep_n:]
        total = sum(len(x) for x in keep)
        drop = 0
        while total > maxb and drop < len(keep) - 1:
            total -= len(keep[drop])
            drop += 1
        keep = keep[drop:]
        tmp = OUT + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(keep)
        os.replace(tmp, OUT)
        log("trimmed log -> %d lines / %d KB (limits %d lines, %d KB)"
            % (len(keep), total // 1024, keep_n, maxb // 1024))
    except Exception:
        pass


_log_en_cache = {"mtime": None, "val": True}


def log_enabled():
    """日志总开关（面板可改）。关闭后：不写记录、也不抓正文，纯转发。
    按 mtime 缓存，避免每个请求都读文件。"""
    try:
        m = os.stat(LOG_ENABLE_FILE).st_mtime
        if _log_en_cache["mtime"] != m:
            v = open(LOG_ENABLE_FILE, "r").read().strip().lower()
            _log_en_cache["val"] = v not in ("0", "off", "false", "no", "")
            _log_en_cache["mtime"] = m
        return _log_en_cache["val"]
    except Exception:
        return True     # 配置不存在时默认启用


def emit(entry):
    global _seq, _emit_n, _emit_bytes
    if not log_enabled():
        return          # 日志关闭：不写盘、不占内存
    with _lock:
        _seq += 1
        entry["n"] = _seq
        entry["ts"] = time.time()
        entry["t"] = time.strftime("%H:%M:%S", time.localtime())
        line = json.dumps(entry, ensure_ascii=False)
        try:
            with open(OUT, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
        _emit_n += 1
        _emit_bytes += len(line) + 1
        # 单条正文可能上百 KB，所以按「累计写入量」触发裁剪，别等条数凑够：
        # 每写满预算的 1/8 检查一次，最坏也就超出 1/8。
        if _emit_bytes * 8 >= MAX_LOG_BYTES or _emit_n % 50 == 0:
            _trim_log()
            _emit_bytes = 0


# ----------------------------------------------------------------- 转发
def splice(sock, host, port, prefix=b""):
    """不解密，直接把原始字节双向透传（用于白名单外的域名，App 照常工作）。
    prefix：已经从客户端读走但还没转发的字节，先补发过去。"""
    try:
        sock.settimeout(None)   # 隧道期间不设超时，避免长连接被切断
    except Exception:
        pass
    try:
        up = socket.create_connection((sni_bytes(host), port), timeout=12)
    except Exception as e:
        log("splice connect failed", host, repr(e)[:80])
        return
    try:
        up.settimeout(None)
    except Exception:
        pass
    try:
        if prefix:
            up.sendall(prefix)
    except Exception:
        pass

    def pump(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except Exception:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

    t = threading.Thread(target=pump, args=(sock, up), daemon=True)
    t.start()
    pump(up, sock)
    try:
        t.join(1.5)
    except Exception:
        pass
    try:
        up.close()
    except Exception:
        pass


def forward_http(client_sock, first, headers, body, host, port, scheme, client_ip, sni,
                 record=True, src_buf=None):
    """把请求转发到真实服务器，并把响应【逐字节流式】回写给客户端，同时抓前缀做记录。

    关键：响应体绝不缓冲后重发、绝不改 Content-Encoding / Content-Length，
    否则大响应会被截断、或压缩数据被去掉编码头，App 拿到坏数据就显示不出来。
    """
    entry = {"client": client_ip, "scheme": scheme, "host": host, "port": port,
             "method": first.split(" ")[0] if first else "",
             "target": first.split(" ")[1] if first and len(first.split(" ")) > 1 else "",
             "req_headers": headers, "resp_headers": {}, "status": ""}
    # 请求体（只记录前缀）
    rt, rc, rl = decode_body(
        body if not MAX_SNIPPET or MAX_SNIPPET <= 0 else body[:MAX_SNIPPET], headers)
    entry["req_body"] = rt
    entry["req_cjk"] = rc
    entry["req_len"] = rl
    if rt:
        entry["req_ctype"] = headers.get("Content-Type") or headers.get("content-type") or ""

    # 组装转发用的请求头（保留客户端原始 Content-Length，不重写）
    tgt = entry["target"]
    if tgt.startswith("http://") or tgt.startswith("https://"):
        # 绝对 URI -> 转成 origin-form
        i = tgt.find("/", tgt.find("//") + 2)
        tgt = tgt[i:] if i > 0 else "/"
    req = ["%s %s HTTP/1.1" % (entry["method"] or "GET", tgt)]
    for k, v in headers.items():
        kl = k.lower()
        if kl in ("proxy-connection", "connection", "accept-encoding", "te", "upgrade",
                  "keep-alive"):
            continue
        req.append("%s: %s" % (k, v))
    if not any(k.lower() == "host" for k in headers):
        req.append("Host: " + host)
    req.append("Connection: close")
    # 请求不要压缩响应，方便记录明文（不影响正确性）
    req.append("Accept-Encoding: identity")
    if body and not any(k.lower() == "content-length" for k in headers):
        req.append("Content-Length: %d" % len(body))
    req_head = ("\r\n".join(req) + "\r\n\r\n").encode("iso-8859-1", "replace")

    raw_sock = socket.create_connection((sni_bytes(host), port), timeout=12)
    if scheme == "https":
        octx = client_context()
        try:
            octx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        srv = octx.wrap_socket(raw_sock, server_hostname=sni_bytes(sni or host))
    else:
        srv = raw_sock

    rheaders = {}
    for _s in (srv, client_sock):
        try:
            _s.settimeout(60)     # 转发阶段给足超时，别把大响应/慢客户端掐断
        except Exception:
            pass
    try:
        # ---- 1) 发请求头 + 已缓冲的请求体，超出的部分继续从客户端流式搬过去 ----
        srv.sendall(req_head)
        if body:
            srv.sendall(body)
        if src_buf is not None:
            declared = headers.get("Content-Length") or headers.get("content-length")
            try:
                remaining = max(0, int(declared) - len(body)) if declared else 0
            except Exception:
                remaining = 0
            while remaining > 0:
                piece = src_buf.b
                if not piece:
                    try:
                        piece = src_buf.s.recv(min(65536, remaining))
                    except Exception:
                        break
                    if not piece:
                        break
                else:
                    src_buf.b = b""
                if len(piece) > remaining:
                    src_buf.b = piece[remaining:]
                    piece = piece[:remaining]
                srv.sendall(piece)
                remaining -= len(piece)

        # ---- 2) 读响应头 ----
        rbuf = Buf(srv)
        rfirst, rraw, rheaders = read_headers(rbuf)
        if rfirst is None:
            raise IOError("empty response")
        parts = rfirst.split(" ", 2)
        entry["status"] = parts[1] if len(parts) > 1 else ""
        entry["resp_headers"] = rheaders

        # ---- 3) 回写响应头：原样保留 Content-Length / Content-Encoding / Transfer-Encoding ----
        hdrs = [rfirst]
        for k, v in rheaders.items():
            if k.lower() in ("connection", "keep-alive", "proxy-connection", "te", "upgrade"):
                continue
            hdrs.append("%s: %s" % (k, v))
        hdrs.append("Connection: close")
        client_sock.sendall(("\r\n".join(hdrs) + "\r\n\r\n").encode("iso-8859-1", "replace"))

        # ---- 4) 流式转发响应体（一个字节都不改、不截断），只抓前缀用于记录 ----
        ctype = rheaders.get("Content-Type") or rheaders.get("content-type") or ""
        bk = blob_kind(ctype)
        # 日志总开关关闭时：完全不抓正文（省 CPU/内存），只做纯转发
        if not log_enabled():
            cap = 0
        elif _is_texty(ctype):
            cap = CAP_TEXT_MAX
        elif bk:
            cap = min(BLOB_MAX, 2 * 1024 * 1024)     # 图片/文档多抓点，否则看不到
        else:
            cap = CAP_BIN_MAX
        captured = bytearray()
        total = 0
        chunk = rbuf.b
        rbuf.b = b""
        while True:
            if chunk:
                client_sock.sendall(chunk)
                total += len(chunk)
                if len(captured) < cap:
                    captured += chunk[:cap - len(captured)]
            try:
                chunk = srv.recv(65536)
            except Exception:
                break
            if not chunk:
                break
        entry["resp_ctype"] = ctype
        entry["resp_len"] = total
        if cap and bk and captured:
            # 只有「完整且未被截断」的才存成可预览文件
            # （chunked 的原始字节里含分块头，直接存会得到损坏文件，所以跳过）
            te_r = (rheaders.get("Transfer-Encoding") or "").lower()
            cl_r = rheaders.get("Content-Length") or ""
            whole = (not te_r and cl_r.isdigit() and int(cl_r) == total
                     and len(captured) == total)
            if whole:
                bid = blob_write(bytes(captured), ctype)
                if bid:
                    entry["blob"] = bid
                    entry["blob_kind"] = bk[0]
                    try:
                        nm = (entry.get("target") or "").split("?")[0].rstrip("/").split("/")[-1]
                        if nm and len(nm) <= 80 and "." in nm:
                            entry["blob_name"] = nm
                    except Exception:
                        pass
            else:
                entry["blob_partial"] = True      # 太大或分块：只记大小
        elif cap:
            st, sc, _ = decode_prefix(bytes(captured), rheaders)
            entry["resp_body"] = st
            entry["resp_cjk"] = sc
            entry["resp_captured"] = len(captured)
            # 只有「服务端返回的比我们抓到的多」才算没抓全（转发给客户端的始终是完整的）
            entry["resp_truncated"] = bool(
                st and (total > len(captured) or len(st) >= HARD_TEXT_CAP))
    except Exception as e:
        log("forward error", host, repr(e)[:120])
        # 还没回任何字节时给客户端一个明确的错误，避免 App 卡住
        if not entry.get("status"):
            try:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n"
                                    b"Content-Type: text/plain\r\nContent-Length: 12\r\n"
                                    b"Connection: close\r\n\r\nbad gateways")
            except Exception:
                pass
    finally:
        try:
            srv.close()
        except Exception:
            pass

    if record:
        emit(entry)


def handle_plain(sock, client_ip, orig_ip, orig_port):
    # 快速判定：HTTP 请求行必须以大写字母开头（GET/POST/PUT/DELETE/HEAD/CONNECT...）
    # 否则是别的协议（如 App 的私有二进制协议），直接原样透传，别当 HTTP 解析
    try:
        head = sock.recv(1, socket.MSG_PEEK)
    except Exception:
        return
    if not head or not (65 <= head[0] <= 90):
        if orig_ip:
            log("non-http on :80 -> splice (early)", orig_ip, "first_byte=%r" % (head[0] if head else None))
            splice(sock, orig_ip, orig_port or 80)
        return
    buf = Buf(sock)
    first, raw, headers = read_headers(buf)
    if first is None:
        return
    parts = first.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else "/"

    if method.upper() == "CONNECT":
        # 显式代理的 HTTPS
        host, _, port = target.rpartition(":")
        port = int(port) if port.isdigit() else 443
        try:
            sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except Exception:
            return
        do_tls(sock, client_ip, host, 443)
        return

    if not HTTP_REQ_RE.match(first):
        # 不是合法 HTTP 请求（可能是其它协议）→ 原样透传给原始目标，避免误伤
        if orig_ip:
            log("non-http on :80 -> splice", orig_ip, repr(first[:40]))
            splice(sock, orig_ip, orig_port or 80, prefix=raw + buf.b)
        return

    if target.startswith("http://"):
        rest = target[7:]
        hostport = rest.split("/", 1)[0]
        if ":" in hostport:
            host, _, ps = hostport.rpartition(":")
            port = int(ps) if ps.isdigit() else 80
        else:
            host, port = hostport, 80
    else:
        host = headers.get("Host") or headers.get("host") or orig_ip or ""
        host = host.split(":")[0]
        port = orig_port or 80
    if not host:
        return
    body = read_body(buf, headers, is_request=True, buffer_limit=REQ_BUFFER)
    forward_http(sock, first, headers, body, host, port, "http", client_ip, host,
                 record=is_target(host), src_buf=buf)


def do_tls(sock, client_ip, host_hint, port):
    sni = peek_sni(sock)
    host = sni or host_hint
    if not host:
        return
    if not is_target(host):
        splice(sock, host, port)
        return
    try:
        ctx = leaf_context(host)
        tls = ctx.wrap_socket(sock, server_side=True)
    except Exception as e:
        log("TLS handshake failed for", host, repr(e)[:120])
        # 客户端拒绝我们的证书（多半是证书固定）→ 记住它，之后原样放行
        msg = repr(e).upper()
        if any(m in msg for m in ("CERTIFICATE_UNKNOWN", "BAD_CERTIFICATE", "UNKNOWN_CA",
                                  "HANDSHAKE_FAILURE", "UNRECOGNIZED_NAME",
                                  "ALERT_CERTIFICATE", "CERTIFICATE_REQUIRED")):
            mark_bypass(host)
        return
    buf = Buf(tls)
    first, raw, headers = read_headers(buf)
    if first is None:
        return
    body = read_body(buf, headers, is_request=True, buffer_limit=REQ_BUFFER)
    h = headers.get("Host") or headers.get("host") or host
    hh = h.split(":")[0]
    forward_http(tls, first, headers, body, hh, port, "https", client_ip, sni or hh, src_buf=buf)
    try:
        tls.close()
    except Exception:
        pass


def handle(sock, client_ip, mode):
    """mode: 'http' (80 重定向, 明文) 或 'https' (443 重定向, TLS)"""
    try:
        if mode == "https":
            ip, p = orig_dst(sock)
            # 把原始目标 IP 作为兜底提示：没有 SNI 时也能处理，而不是直接丢弃
            do_tls(sock, client_ip, ip, (p if p == 443 else 443))
        else:
            ip, p = orig_dst(sock)
            if ip and p == 80:
                handle_plain(sock, client_ip, ip, 80)
            else:
                # 也可能是显式代理进来的
                handle_plain(sock, client_ip, ip, p)
    except Exception as e:
        log("handle error", repr(e)[:160])
    finally:
        try:
            sock.close()
        except Exception:
            pass


def listen(port, mode):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(128)
    log("listening", port, mode)
    while True:
        try:
            conn, addr = s.accept()
        except Exception:
            continue
        try:
            conn.settimeout(30)   # 限制握手/读头阶段，防止畸形流量挂死线程
        except Exception:
            pass
        global _active
        with _lock:
            _active += 1
            n = _active
        if n > 80:
            with _lock:
                _active -= 1
            try:
                conn.close()
            except Exception:
                pass
            continue

        def runner(c=conn, a=addr, m=mode):
            try:
                handle(c, a[0], m)
            finally:
                global _active
                with _lock:
                    _active -= 1
        threading.Thread(target=runner, daemon=True).start()


def main():
    """启动解密代理：HTTP 一个线程，HTTPS 跑在主线程。"""
    load_ca()
    load_bypass()
    os.makedirs(CERT_DIR, exist_ok=True)
    log("CA ok; out =", OUT, "; auto-bypass =", len(_bypass))
    threading.Thread(target=listen, args=(HTTP_PORT, "http"), daemon=True).start()
    listen(HTTPS_PORT, "https")


if __name__ == "__main__":
    main()

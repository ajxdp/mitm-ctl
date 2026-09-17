#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kwrt 抓包网页查看器 - 后端
- 运行 tcpdump 抓 br-lan，自己解析 pcap 流
- 输出结构化 JSON，并通过 SSE 推给浏览器
- 解码：DNS 查询名（含中文域名）、HTTP 明文（含中文）、TLS SNI
仅用 Python 标准库（socket/struct/threading/json/re/subprocess/select/base64）。
"""
import os
import sys
import re
import ssl
import json
import time
import zlib
import struct
import socket
import base64
import hashlib
import threading
import subprocess

IFACE = os.environ.get("PKTCAP_IFACE", "br-lan")
PORT = int(os.environ.get("PKTCAP_PORT", "7690"))
USER = os.environ.get("PKTCAP_USER", "root")
PASS = os.environ.get("PKTCAP_PASS", "root")
BPF = os.environ.get("PKTCAP_FILTER", "")
INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
HTTPS_INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "https.html")
BODY_INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "body.html")
ACCESS_LOG = os.environ.get("PKTCAP_ACCESSLOG", "/tmp/squid-access.log")
BODY_LOG = os.environ.get("PKTCAP_BODYLOG", "/tmp/mitm-body.jsonl")
PANEL_INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.html")
CHEAT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CHEATSHEET.md")
BLOB_DIR = os.environ.get("MITM_BLOB_DIR", "/tmp/mitm-blobs")
BLOB_ID_RE = re.compile(r"^[0-9a-f]{16}\.[a-z0-9]{1,8}$")
BLOB_CTYPE = {
    "png": "image/png", "jpg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
    "bmp": "image/bmp", "svg": "image/svg+xml", "ico": "image/x-icon", "avif": "image/avif",
    "heic": "image/heic", "pdf": "application/pdf", "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "bin": "application/octet-stream",
}
MITM_CONF = os.environ.get("MITM_CONF", "/etc/mitm")
MITM_MODE = os.path.join(MITM_CONF, "mode")
MITM_DOMAINS = os.path.join(MITM_CONF, "domains.txt")
MITM_IFACES = os.path.join(MITM_CONF, "ifaces")
MITM_BYPASS = os.path.join(MITM_CONF, "auto-bypass.txt")
MITM_TARGETS = os.environ.get("MITM_TARGETS", "/etc/squid/mitm-targets")
KEEPALIVE_FILE = os.environ.get("PKTCAP_KEEPALIVE", "/etc/pktcap-keepalive")
IDLE_STOP_SEC = int(os.environ.get("PKTCAP_IDLE_STOP", "60"))   # 无人在看多久后自动停抓包
BODY_HISTORY = int(os.environ.get("PKTCAP_BODY_HISTORY", "60"))  # 进入页面时回放多少条


def keepalive_on():
    """是否「无人观看也保持抓包」。默认关（省 CPU）。"""
    try:
        with open(KEEPALIVE_FILE, "r") as f:
            return f.read().strip() in ("1", "on", "true", "yes")
    except Exception:
        return False


def set_keepalive(on):
    try:
        d = os.path.dirname(KEEPALIVE_FILE)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        with open(KEEPALIVE_FILE, "w") as f:
            f.write("1" if on else "0")
        return True
    except Exception:
        return False

CJK_RE = re.compile(r"[\u3000-\u303f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef]{2,}")
MAX_SNIPPET = int(os.environ.get("PKTCAP_MAX_SNIPPET", "20000"))

PORT_APP = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 137: "NBNS", 138: "NBNS",
    443: "TLS", 8443: "TLS", 80: "HTTP", 8080: "HTTP", 8000: "HTTP",
    5222: "XMPP", 3478: "STUN", 5353: "mDNS", 1900: "SSDP",
}


# ------------------------------------------------------------------ helpers
def _ip4(b):
    return "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])


def _ip6(b):
    parts = ["%x" % struct.unpack(">H", b[i:i + 2])[0] for i in range(0, 16, 2)]
    best_i = best_len = cur_i = cur_len = -1
    for i in range(9):
        if i < 8 and parts[i] == "0":
            if cur_len < 0:
                cur_i, cur_len = i, 1
            else:
                cur_len += 1
        else:
            if cur_len > best_len:
                best_i, best_len = cur_i, cur_len
            cur_len = -1
    s = ":".join(parts)
    return s


def _mac(b):
    return ":".join("%02x" % x for x in b)


def _readn(f, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = f.read(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _decode_idn(name):
    """把 xn-- 的 punycode 标签解回中文域名。"""
    out = []
    for lab in name.split("."):
        if lab.lower().startswith("xn--"):
            try:
                out.append(lab[4:].encode("ascii").decode("punycode"))
                continue
            except Exception:
                pass
        out.append(lab)
    return ".".join(out)


def _readable(text):
    if not text:
        return False
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return ok / max(1, len(text)) >= 0.90


def _text_cjk(data, limit=400):
    """从字节里提取可读文本片段与中文片段；二进制则返回 (None, None)。"""
    if not data:
        return None, None
    text = None
    try:
        t = data.decode("utf-8")
        if _readable(t):
            text = t
    except UnicodeDecodeError:
        pass
    if text is None:
        try:
            t = data.decode("latin-1")
            if _readable(t):
                text = t
        except Exception:
            text = None
    if text is None:
        return None, None
    snippet = "".join(ch if (ch.isprintable() and ch not in "\r\n\t") else " " for ch in text)
    snippet = re.sub(r"\s{2,}", " ", snippet).strip()[:limit]
    cjks = CJK_RE.findall(text)
    return (snippet or None), (list(dict.fromkeys(cjks))[:5] or None)


def _tcp_flags(fl):
    m = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"),
         (0x08, "PSH"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
    return " ".join(n for bit, n in m if fl & bit) or "-"


# ------------------------------------------------------------------ decoders
def _dns_name(payload, p):
    """解析 DNS 名称，支持压缩指针；返回 (名称, 下一个位置)。"""
    labels = []
    start = p
    jumped = False
    while p < len(payload):
        l = payload[p]
        if l == 0:
            p += 1
            break
        if l & 0xC0:
            if p + 1 >= len(payload):
                p += 2
                break
            ptr = ((l & 0x3F) << 8) | payload[p + 1]
            p += 2
            if not jumped:
                start = p
                jumped = True
            p = ptr
            continue
        p += 1
        labels.append(payload[p:p + l])
        p += l
    return b".".join(labels).decode("ascii", "replace"), (start if jumped else p)


def parse_dns(payload, is_tcp=False):
    try:
        if len(payload) < 12:
            return None
        flags = struct.unpack(">H", payload[2:4])[0]
        qd = struct.unpack(">H", payload[4:6])[0]
        an = struct.unpack(">H", payload[6:8])[0]
        p = 12
        names = []
        for _ in range(min(qd, 4)):
            nm, p = _dns_name(payload, p)
            if not nm:
                break
            names.append(nm)
            p += 4
        answers = []
        if (flags & 0x8000) and an:  # 这是一个应答
            for _ in range(min(an, 16)):
                if p >= len(payload):
                    break
                nm, p = _dns_name(payload, p)
                if p + 10 > len(payload):
                    break
                rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", payload[p:p + 10])
                p += 10
                rd = payload[p:p + rdlen]
                p += rdlen
                if rtype == 1 and rdlen == 4:
                    answers.append((nm, _ip4(rd)))
                elif rtype == 28 and rdlen == 16:
                    answers.append((nm, _ip6(rd)))
        if not names and not answers:
            return None
        qname = names[0] if names else (answers[0][0] if answers else "")
        uni = _decode_idn(qname) if qname else ""
        return {"query": qname,
                "query_cn": (uni if (qname and uni != qname) else None),
                "all": names, "answers": answers}
    except Exception:
        return None


def parse_http(payload, is_request):
    try:
        idx = payload.find(b"\r\n\r\n")
        if idx < 0:
            head, body = payload, b""
        else:
            head, body = payload[:idx], payload[idx + 4:]
        htxt = head.decode("iso-8859-1", "replace")
        lines = htxt.split("\r\n")
        if not lines:
            return None
        first = lines[0]
        d = {}
        if is_request:
            m = re.match(r"([A-Z]{3,7})\s+(\S+)\s+HTTP/([\d.]+)", first)
            if not m:
                return None
            d["method"] = m.group(1)
            d["path"] = m.group(2)[:200]
            d["http"] = m.group(3)
        else:
            m = re.match(r"HTTP/([\d.]+)\s+(\d{3})", first)
            if not m:
                return None
            d["status"] = m.group(2)
            d["http"] = m.group(1)
        for ln in lines[1:40]:
            low = ln.lower()
            if low.startswith("host:"):
                d["host"] = ln.split(":", 1)[1].strip()[:120]
            elif low.startswith("content-type:"):
                d["ctype"] = ln.split(":", 1)[1].strip()[:60]
        if body:
            snip, cjks = _text_cjk(body)
            if snip:
                d["body"] = snip
                if cjks:
                    d["cjk"] = cjks
            else:
                d["body_bin"] = len(body)
        return d
    except Exception:
        return None


def parse_tls_sni(payload):
    try:
        if len(payload) < 6 or payload[0] != 22:
            return None
        rec_len = struct.unpack(">H", payload[3:5])[0]
        hs = payload[5:5 + rec_len]
        if len(hs) < 4 or hs[0] != 1:
            return None
        p = 4 + 2 + 32  # handshake type/len + version + random
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


# ------------------------------------------------------------------ packet parse
def parse_packet(data, linktype, tstamp, seq):
    out = {"n": seq, "ts": tstamp,
           "t": time.strftime("%H:%M:%S", time.localtime(tstamp)),
           "ms": int((tstamp % 1) * 1000),
           "len": len(data), "proto": "?", "src": "", "dst": "",
           "sport": None, "dport": None, "flags": "", "app": "", "info": "",
           "detail": {}}
    try:
        off = 0
        etype = None
        if linktype == 1:  # Ethernet
            if len(data) < 14:
                return out
            etype = struct.unpack(">H", data[12:14])[0]
            off = 14
            while etype == 0x8100 and len(data) >= off + 4:  # VLAN
                etype = struct.unpack(">H", data[off + 2:off + 4])[0]
                off += 4
        else:
            return out

        if etype == 0x0806:  # ARP
            out["proto"] = "ARP"
            if len(data) >= off + 28:
                op = struct.unpack(">H", data[off + 6:off + 8])[0]
                spa = _ip4(data[off + 14:off + 18])
                tpa = _ip4(data[off + 24:off + 28])
                out["src"], out["dst"] = spa, tpa
                out["info"] = ("ARP 请求 " if op == 1 else "ARP 应答 ") + tpa
            return out
        if etype == 0x0800:
            if len(data) < off + 20:
                return out
            ihl = (data[off] & 0x0F) * 4
            proto = data[off + 9]
            src = _ip4(data[off + 12:off + 16])
            dst = _ip4(data[off + 16:off + 20])
            out["src"], out["dst"] = src, dst
            l4 = data[off + ihl:]
        elif etype == 0x86DD:
            if len(data) < off + 40:
                return out
            proto = data[off + 6]
            src = _ip6(data[off + 8:off + 24])
            dst = _ip6(data[off + 24:off + 40])
            out["src"], out["dst"] = src, dst
            l4 = data[off + 40:]
        else:
            out["proto"] = "ETH"
            out["info"] = "以太网 类型 0x%04x" % etype
            return out

        if proto == 6 and len(l4) >= 20:  # TCP
            out["proto"] = "TCP"
            sport, dport = struct.unpack(">HH", l4[0:4])
            doff = (l4[12] >> 4) * 4
            fl = l4[13]
            out.update(sport=sport, dport=dport, flags=_tcp_flags(fl))
            pl = l4[doff:]
            out["app"] = PORT_APP.get(dport) or PORT_APP.get(sport) or ""
            _decode_app(out, pl, dport, sport, is_req=(dport not in (80, 8080, 443, 8443)))
        elif proto == 17 and len(l4) >= 8:  # UDP
            out["proto"] = "UDP"
            sport, dport = struct.unpack(">HH", l4[0:4])
            out.update(sport=sport, dport=dport)
            pl = l4[8:]
            out["app"] = PORT_APP.get(dport) or PORT_APP.get(sport) or ""
            if 53 in (sport, dport):
                d = parse_dns(pl)
                if d:
                    out["app"] = "DNS"
                    out["detail"]["dns"] = d
                    if d.get("answers"):
                        ips = ", ".join(ip for _, ip in d["answers"][:3])
                        out["info"] = "DNS 应答 %s → %s" % (d["query"], ips)
                    else:
                        s = "DNS 查询 %s" % d["query"]
                        if d.get("query_cn"):
                            s += " （%s）" % d["query_cn"]
                        out["info"] = s
            elif 67 in (sport, dport) or 68 in (sport, dport):
                out["app"] = "DHCP"
                out["info"] = "DHCP"
        elif proto == 1 or proto == 58:  # ICMP / ICMPv6
            out["proto"] = "ICMP" if proto == 1 else "ICMPv6"
            if l4:
                icmp_type = l4[0]
                out["info"] = {8: "ICMP 回显请求", 0: "ICMP 回显应答", 3: "ICMP 目标不可达",
                               11: "ICMP 超时"}.get(icmp_type, "ICMP 类型 %d" % icmp_type)
        elif proto == 2:
            out["proto"] = "IGMP"
            out["info"] = "IGMP"
        else:
            out["proto"] = "IP-%d" % proto
        if not out["info"]:
            out["info"] = _default_info(out)
    except Exception:
        pass
    return out


def _decode_app(out, payload, dport, sport, is_req):
    if not payload:
        return
    if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
        is_request = dport in (80, 8080, 8000)
        d = parse_http(payload, is_request)
        if d:
            out["app"] = "HTTP"
            out["detail"]["http"] = d
            if is_request:
                p = d.get("path", "")
                if p.startswith("http"):
                    out["info"] = "%s %s" % (d.get("method", "HTTP"), p)
                else:
                    out["info"] = "%s %s%s" % (d.get("method", "HTTP"),
                                               d.get("host", ""), p)
            else:
                out["info"] = "HTTP %s 响应" % d.get("status", "")
        return
    if dport in (443, 8443) or sport in (443, 8443):
        if dport in (443, 8443):  # 只有客户端→服务器方向才有 ClientHello
            sni = parse_tls_sni(payload)
            if sni:
                out["app"] = "TLS"
                out["detail"]["tls"] = {"sni": sni}
                out["info"] = "TLS 握手 → %s" % sni
        else:
            out["app"] = "TLS"


def _default_info(out):
    if out["proto"] in ("TCP", "UDP"):
        s = "%s %s" % (out["proto"], ("[%s]" % out["flags"]).strip() if out["flags"] else "")
        if out["app"]:
            s = "%s %s" % (out["app"], s)
        return s.strip()
    return out["proto"]


# ------------------------------------------------------------------ capture
class Capture(object):
    def __init__(self):
        self.clients = set()
        self.lock = threading.Lock()
        self.proc = None
        self.running = False
        self.seq = 0
        self.last = None
        self.flows = {}
        self.ipnames = {}
        self.last_client_ts = 0.0
        self._idle_started = False

    def annotate(self, pkt):
        """给包标注所属会话：TLS→SNI / HTTP→Host / DNS 应答→IP 反查域名。"""
        try:
            d = pkt.get("detail") or {}
            k = (pkt["src"], pkt["sport"], pkt["dst"], pkt["dport"])
            rk = (pkt["dst"], pkt["dport"], pkt["src"], pkt["sport"])
            tls = d.get("tls") or {}
            http = d.get("http") or {}
            dns = d.get("dns") or {}
            if tls.get("sni"):
                f = ("TLS", tls["sni"])
                self.flows[k] = f
                self.flows[rk] = f
            elif http.get("host"):
                f = ("HTTP", http["host"])
                self.flows[k] = f
                self.flows[rk] = f
            qname = dns.get("query")
            for nm, ip in dns.get("answers", []):
                if ip:
                    self.ipnames[ip] = qname or nm
            fl = self.flows.get(k)
            if fl:
                proto, name = fl
            else:
                name = self.ipnames.get(pkt["dst"]) or self.ipnames.get(pkt["src"])
                proto = "DNS 反查" if name else None
            if name:
                pkt["detail"]["flow"] = {"proto": proto, "name": name}
                rich = bool(d.get("http") or d.get("dns") or d.get("tls"))
                if not rich:
                    fl_s = (" [%s]" % pkt["flags"]) if pkt.get("flags") else ""
                    base = pkt.get("app") or pkt.get("proto") or ""
                    pkt["info"] = "%s · %s%s" % (base, name, fl_s)
            if len(self.flows) > 8000:
                self.flows.clear()
            if len(self.ipnames) > 5000:
                self.ipnames.clear()
        except Exception:
            pass

    def start(self):
        with self.lock:
            if self.running:
                return False
        cmd = ["tcpdump", "-i", IFACE, "-nn", "-s", "0", "-U", "-w", "-"]
        if BPF:
            cmd.append(BPF)
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, bufsize=0)
        self.running = True
        self.seq = 0
        self.flows.clear()
        self.ipnames.clear()
        self.last_client_ts = time.time()   # 从启动时刻起算空闲，避免「没人看过就永不自动停」
        threading.Thread(target=self._loop, daemon=True).start()
        self._start_idle_monitor()
        return True

    def stop(self):
        """停止 tcpdump（省 CPU）。抓包默认就是关的，只有点「开始抓包」才会跑。"""
        self.running = False
        p = self.proc
        self.proc = None
        if p:
            try:
                p.terminate()
            except Exception:
                pass
            try:
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        return True

    def _start_idle_monitor(self):
        if self._idle_started:
            return
        self._idle_started = True

        def mon():
            while True:
                time.sleep(5)
                try:
                    if not self.running:
                        continue
                    if keepalive_on():
                        continue
                    with self.lock:
                        n = len(self.clients)
                    if n == 0 and time.time() - self.last_client_ts > IDLE_STOP_SEC:
                        self.stop()
                except Exception:
                    pass

        threading.Thread(target=mon, daemon=True).start()

    def status(self):
        with self.lock:
            n = len(self.clients)
        return {"running": bool(self.running), "clients": n,
                "iface": IFACE, "filter": BPF,
                "idle_stop": IDLE_STOP_SEC, "keepalive": keepalive_on()}

    def _loop(self):
        f = self.proc.stdout
        gh = _readn(f, 24)
        if not gh:
            return
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, ns = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, ns = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, ns = "<", True
        else:
            endian, ns = ">", True
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        while self.running:
            hdr = _readn(f, 16)
            if not hdr:
                break
            try:
                ts_s, ts_u, incl, orig = struct.unpack(endian + "IIII", hdr)
            except Exception:
                break
            data = _readn(f, incl)
            if data is None:
                break
            ts = ts_s + (ts_u / 1e9 if ns else ts_u / 1e6)
            self.seq += 1
            pkt = parse_packet(data, linktype, ts, self.seq)
            self.annotate(pkt)
            self.last = pkt
            line = ("data: " + json.dumps(pkt, ensure_ascii=False) + "\n\n").encode("utf-8")
            self.broadcast(line)

    def start_replay(self, path, delay=0.02):
        self.running = True
        threading.Thread(target=self._replay_loop, args=(path, delay), daemon=True).start()

    def _replay_loop(self, path, delay):
        with open(path, "rb") as f:
            gh = f.read(24)
            endian = "<" if gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            ns = gh[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
            linktype = struct.unpack(endian + "I", gh[20:24])[0]
            while self.running:
                f.seek(24)
                while self.running:
                    hdr = f.read(16)
                    if len(hdr) < 16:
                        break
                    ts_s, ts_u, incl, orig = struct.unpack(endian + "IIII", hdr)
                    data = f.read(incl)
                    if len(data) < incl:
                        break
                    self.seq += 1
                    pkt = parse_packet(data, linktype, time.time(), self.seq)
                    self.annotate(pkt)
                    self.last = pkt
                    self.broadcast(("data: " + json.dumps(pkt, ensure_ascii=False) + "\n\n").encode("utf-8"))
                    time.sleep(delay)

    def snapshot(self):
        return self.last

    def add_client(self, conn):
        with self.lock:
            self.clients.add(conn)
            self.last_client_ts = time.time()

    def remove_client(self, conn):
        with self.lock:
            self.clients.discard(conn)
            self.last_client_ts = time.time()   # 从「最后一个观看者离开」起算空闲

    def broadcast(self, b):
        with self.lock:
            dead = []
            for c in list(self.clients):
                try:
                    c.sendall(b)
                except Exception:
                    dead.append(c)
            for d in dead:
                self.clients.discard(d)


CAP = Capture()

# ---------------- 解密页「有人在看」判定 ----------------
# 不能用 SSE 连接数来判断：连接可能被挂着不关（预览面板、休眠标签页），会永远算「有人在看」。
# 改成看「最近有没有心跳」：页面可见时每 30 秒 ping 一次，关掉/切后台就不再 ping。
BOOT_TS = time.time()
PING_TS = {}
PING_LOCK = threading.Lock()
PING_GRACE = int(os.environ.get("PKTCAP_PING_GRACE", "90"))   # 超过这么久没 ping 就不算在看


def ping_client(key):
    with PING_LOCK:
        PING_TS[key] = time.time()


def active_viewers():
    now = time.time()
    with PING_LOCK:
        for k in [k for k, v in PING_TS.items() if now - v > PING_GRACE]:
            PING_TS.pop(k, None)
        return len(PING_TS)


def idle_seconds():
    """距最后一次心跳（或服务启动）过了多久。"""
    with PING_LOCK:
        last = max(PING_TS.values()) if PING_TS else 0.0
    return time.time() - max(last, BOOT_TS)


def serve_sse(conn):
    conn.sendall(b"HTTP/1.1 200 OK\r\n"
                 b"Content-Type: text/event-stream; charset=utf-8\r\n"
                 b"Cache-Control: no-cache\r\n"
                 b"Connection: keep-alive\r\n"
                 b"X-Accel-Buffering: no\r\n"
                 b"Access-Control-Allow-Origin: *\r\n\r\n")
    CAP.add_client(conn)
    try:
        # 不随抓包开关退出：页面保持连接，这样点「开始抓包」能立刻收到数据
        while True:
            time.sleep(10)
            conn.sendall(b": keep-alive\n\n")
    except Exception:
        pass
    finally:
        CAP.remove_client(conn)


def ca_cert_path():
    return os.environ.get("MITM_CA_CERT", "/etc/squid/ssl/mitm-ca.crt")


def ca_key_path():
    return os.environ.get("MITM_CA_KEY", "/etc/squid/ssl/mitm-ca.key")


CERT_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>安装 CA 证书</title>
<style>body{font:16px/1.7 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;padding:24px;
background:#f5f6f8;color:#1f2430}h1{font-size:19px;margin:0 0 4px}p.sub{color:#6b7280;font-size:13px;margin:0 0 18px}
a.btn{display:block;padding:16px;margin:12px 0;background:#2f6fed;color:#fff;text-decoration:none;border-radius:10px;
text-align:center;font-weight:600}a.alt{background:#fff;color:#1f2430;border:1px solid #d7dbe3}
.note{color:#6b7280;font-size:13px;margin-top:18px;background:#fff;border:1px solid #eef0f4;border-radius:10px;padding:14px}
.note b{color:#1f2430}.fp{font:12px/1.5 ui-monospace,Consolas,monospace;word-break:break-all;color:#6b7280}
a.back{color:#2f6fed;font-size:13px;text-decoration:none}</style></head><body>
<h1>安装解密根证书</h1>
<p class="sub">装好后，本机浏览器访问的 HTTPS 才能看到明文（不装的话会提示证书错误）</p>
<a class="btn" href="/mitm-ca.crt">① 下载证书 .crt（推荐）</a>
<a class="btn alt" href="/mitm-ca.pem">② 备用格式 .pem</a>
<div class="note">
<b>Android</b>：设置 → 安全 → 加密与凭据 → 安装证书 → <b>CA 证书</b>，选刚下载的文件
（Android 7+ 部分 App 不信任用户证书，属系统限制）<br>
<b>iOS</b>：下载后用 AirDrop/邮件点开 → 设置 → 通用 → VPN与设备管理 里信任 →
再到 通用 → 关于本机 → 证书信任设置 打开开关<br>
<b>Windows</b>：双击 .crt → 安装证书 → 本地计算机 → 受信任的根证书颁发机构<br>
<b>macOS</b>：双击导入"钥匙串访问" → 系统 → 右键"显示简介" → 信任 → 始终信任<br>
<b>Firefox</b>：设置 → 隐私与安全 → 证书 → 查看证书 → 导入（自带信任库，需单独装）
</div>
<div class="note">
CA 指纹（SHA-256）：<br><span class="fp">{fp}</span><br>
有效期至：{notafter}
</div>
<p><a class="back" href="/body">← 返回解密内容页</a></p>
</body></html>"""


def _ca_fingerprint():
    """取 CA 指纹与有效期；失败就返回占位文案。"""
    fp, na = "（读取失败）", "（未知）"
    try:
        import hashlib
        raw = open(ca_cert_path(), "rb").read()
        der = ssl.PEM_cert_to_DER_cert(raw.decode("utf-8", "replace"))
        h = hashlib.sha256(der).hexdigest().upper()
        fp = ":".join(h[i:i + 2] for i in range(0, len(h), 2))
    except Exception:
        pass
    try:
        out = _sh("openssl x509 -in %s -noout -enddate 2>/dev/null" % ca_cert_path())
        if "=" in out:
            na = out.strip().split("=", 1)[1]
    except Exception:
        pass
    return fp, na


def serve_cert_page(conn):
    fp, na = _ca_fingerprint()
    body = CERT_PAGE.replace("{fp}", _esc(fp)).replace("{notafter}", _esc(na)).encode("utf-8")
    conn.sendall(b"HTTP/1.1 200 OK\r\n"
                 b"Content-Type: text/html; charset=utf-8\r\n"
                 b"Cache-Control: no-cache\r\nConnection: close\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def serve_ca_file(conn, name):
    """下发 CA 证书文件（不要求登录：手机装证书时没法带 Basic 认证）。"""
    p = ca_cert_path()
    try:
        body = open(p, "rb").read()
    except Exception:
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                     b"Connection: close\r\n\r\n")
        return
    ctype = ("application/x-x509-ca-cert" if name.endswith(".crt")
             else "application/x-pem-file")
    conn.sendall(("HTTP/1.1 200 OK\r\nContent-Type: " + ctype + "\r\n"
                  "Content-Disposition: attachment; filename=\"" + name + "\"\r\n"
                  "Cache-Control: no-cache\r\nConnection: close\r\n"
                  "Content-Length: " + str(len(body)) + "\r\n\r\n").encode("utf-8") + body)


def serve_file(conn, path, ctype="text/html"):
    try:
        with open(path, "rb") as fp:
            body = fp.read()
    except Exception:
        body = b"<h1>not found</h1>"
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype.encode() +
                 b"; charset=utf-8\r\nCache-Control: no-cache\r\nConnection: close\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def serve_index(conn):
    serve_file(conn, INDEX, "text/html")


def parse_access_line(ln):
    p = [x.strip() for x in ln.split("|", 5)]
    d = {"raw": ln.strip()}
    if len(p) >= 5:
        d["t"], d["client"], d["method"], d["result"] = p[0], p[1], p[2], p[3]
        if len(p) == 6:
            d["ctype"], d["url"] = p[4], p[5]
        else:
            d["ctype"], d["url"] = "-", p[4]
    return d


def _as_json(ln):
    try:
        return json.loads(ln)
    except Exception:
        return {"raw": ln.strip()}


def _tail_stream(conn, path, parse, hist_limit=200):
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n"
                 b"Cache-Control: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n\r\n")
    pos = 0
    try:
        if os.path.exists(path):
            with open(path, "r", errors="replace") as f:
                hist = f.readlines()[-hist_limit:]
            buf = b""
            for ln in hist:
                if ln.strip():
                    buf += ("data: " + json.dumps(parse(ln), ensure_ascii=False) + "\n\n").encode("utf-8")
            if buf:
                conn.sendall(buf)
            pos = os.path.getsize(path)
    except Exception:
        pass
    try:
        while True:
            if not os.path.exists(path):
                time.sleep(1)
                continue
            sz = os.path.getsize(path)
            if sz < pos:
                pos = 0
            if sz > pos:
                with open(path, "r", errors="replace") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                buf = b""
                for ln in chunk.splitlines():
                    if ln.strip():
                        buf += ("data: " + json.dumps(parse(ln), ensure_ascii=False) + "\n\n").encode("utf-8")
                if buf:
                    conn.sendall(buf)
            else:
                time.sleep(0.5)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve_https_stream(conn):
    _tail_stream(conn, ACCESS_LOG, parse_access_line)


def serve_body_stream(conn):
    _tail_stream(conn, BODY_LOG, _as_json, hist_limit=BODY_HISTORY)


def log_status(msg):
    try:
        sys.stderr.write("pktcap: " + msg + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def autoclose_monitor():
    """无人看解密页超过 N 分钟 → 关闭解密（清 nft + 停代理），恢复直连、省下 CPU。"""
    while True:
        time.sleep(20)
        try:
            cfg = autoclose_cfg()
            if not cfg["enabled"]:
                continue
            if active_viewers():
                continue
            if idle_seconds() <= cfg["minutes"] * 60:
                continue
            if not (TRANSPARENT or MITM_CTL):
                continue          # 显式代理模式：进程由容器托管，不能在此停
            st = mitm_status()
            if st.get("enabled") or st.get("running"):
                log_status("autoclose: 无人监听超 %d 分钟，自动关闭解密" % cfg["minutes"])
                _ctl("stop")
        except Exception:
            pass


def _sh(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        return (p.stdout or b"").decode("utf-8", "replace")
    except Exception as e:
        return "ERR " + str(e)


def _read_file(p, default=""):
    try:
        with open(p, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return default


# ================================================ 可预览二进制（图片/文档）
def blob_stats():
    n, tot = 0, 0
    try:
        for f in os.listdir(BLOB_DIR):
            try:
                tot += os.path.getsize(os.path.join(BLOB_DIR, f))
                n += 1
            except OSError:
                pass
    except Exception:
        pass
    return {"count": n, "bytes": tot, "dir": BLOB_DIR}


def blob_clear():
    removed = 0
    try:
        for f in os.listdir(BLOB_DIR):
            try:
                os.remove(os.path.join(BLOB_DIR, f))
                removed += 1
            except OSError:
                pass
    except Exception:
        pass
    return removed


_BLOB_IMG_EXT = {"jpeg": "jpg", "jpg": "jpg", "png": "png", "gif": "gif", "webp": "webp",
                 "bmp": "bmp", "svg+xml": "svg", "x-icon": "ico",
                 "vnd.microsoft.icon": "ico", "avif": "avif", "heic": "heic"}


def blob_ext_for(ctype):
    """可预览类型的扩展名；不可预览返回 None。"""
    c = (ctype or "").lower().split(";")[0].strip()
    if not c:
        return None
    if c.startswith("image/"):
        return _BLOB_IMG_EXT.get(c[6:].strip(), "bin")
    if c == "application/pdf":
        return "pdf"
    for t, e in (("msword", "doc"), ("wordprocessingml", "docx"),
                 ("ms-excel", "xls"), ("spreadsheetml", "xlsx"),
                 ("ms-powerpoint", "ppt"), ("presentationml", "pptx")):
        if t in c:
            return e
    return None


def blob_write(data, ctype, max_bytes=1024 * 1024):
    """（主动发请求的响应用）把可预览二进制存起来，返回 id。"""
    ext = blob_ext_for(ctype)
    if not ext or not data or len(data) > max_bytes:
        return None
    bid = hashlib.sha1(data).hexdigest()[:16] + "." + ext
    try:
        if not os.path.isdir(BLOB_DIR):
            os.makedirs(BLOB_DIR, exist_ok=True)
        p = os.path.join(BLOB_DIR, bid)
        if not os.path.exists(p):
            with open(p, "wb") as f:
                f.write(data)
        return bid
    except Exception:
        return None


def serve_blob(conn, bid, download=False):
    """把抓到的图片/文档发给浏览器。id 是内容哈希+扩展名，严格校验防目录穿越。"""
    if not BLOB_ID_RE.match(bid or ""):
        send_json(conn, {"ok": False, "error": "bad blob id"}, "400 Bad Request")
        return
    p = os.path.join(BLOB_DIR, bid)
    try:
        with open(p, "rb") as f:
            data = f.read()
    except Exception:
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\n"
                     b"Cache-Control: no-cache\r\nConnection: close\r\nContent-Length: 17\r\n\r\n"
                     b"blob not found :(")
        return
    ext = bid.rsplit(".", 1)[-1].lower()
    ctype = BLOB_CTYPE.get(ext, "application/octet-stream")
    hdr = ("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
           "Cache-Control: max-age=3600\r\nConnection: close\r\n") % (ctype, len(data))
    if download:
        hdr += "Content-Disposition: attachment; filename=\"%s\"\r\n" % bid
    conn.sendall(hdr.encode("ascii") + b"\r\n" + data)



# 极简 markdown 渲染：只支持本项目手册用到的语法（标题/代码块/表格/列表/引用/加粗/行内码/链接）。
# 不引第三方库——路由器上装不了。
# ======================================================== 速查手册（/doc）
# 极简 markdown 渲染：只支持本项目手册用到的语法（标题/代码块/表格/列表/引用/加粗/行内码/链接）。
# 不引第三方库——路由器上装不了。
def _esc(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;") \
                    .replace(">", "&gt;").replace('"', "&quot;")


def _md_inline(s):
    t = _esc(s)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2" target="_blank">\1</a>', t)
    return t


def _md_to_html(md):
    out, lines = [], (md or "").split("\n")
    i, n = 0, len(lines)
    in_code, code = False, []
    while i < n:
        ln = lines[i]
        if ln.strip().startswith("```"):
            if not in_code:
                in_code, code = True, []
            else:
                in_code = False
                out.append("<pre><code>" + _esc("\n".join(code)) + "</code></pre>")
            i += 1
            continue
        if in_code:
            code.append(ln)
            i += 1
            continue
        s = ln.strip()
        if s.startswith("|") and i + 1 < n and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            head = [c.strip() for c in s.strip("|").split("|")]
            i += 2
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            h = "<table><thead><tr>" + "".join("<th>" + _md_inline(c) + "</th>" for c in head) + \
                "</tr></thead><tbody>"
            for r in rows:
                h += "<tr>" + "".join("<td>" + _md_inline(c) + "</td>" for c in r) + "</tr>"
            out.append(h + "</tbody></table>")
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            lv = len(m.group(1))
            out.append("<h%d>%s</h%d>" % (lv, _md_inline(m.group(2)), lv))
            i += 1
            continue
        if re.match(r"^(-{3,}|\*{3,})$", s):
            out.append("<hr>")
            i += 1
            continue
        if s.startswith(">"):
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip())
                i += 1
            out.append("<blockquote>" + "<br>".join(_md_inline(x) for x in buf) + "</blockquote>")
            continue
        if re.match(r"^([-*]|\d+\.)\s+", s):
            ordered = bool(re.match(r"^\d+\.", s))
            items = []
            while i < n and re.match(r"^([-*]|\d+\.)\s+", lines[i].strip()):
                items.append(re.sub(r"^([-*]|\d+\.)\s+", "", lines[i].strip()))
                i += 1
            tag = "ol" if ordered else "ul"
            out.append("<%s>%s</%s>" % (tag, "".join("<li>" + _md_inline(x) + "</li>" for x in items), tag))
            continue
        if not s:
            i += 1
            continue
        out.append("<p>" + _md_inline(s) + "</p>")
        i += 1
    if in_code and code:
        out.append("<pre><code>" + _esc("\n".join(code)) + "</code></pre>")
    return "\n".join(out)


DOC_TMPL = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kwrt 解密抓包 · 速查手册</title>
<style>
  :root{--bg:#f5f6f8;--card:#fff;--line:#e6e8ee;--txt:#1f2430;--muted:#6b7280;
    --accent:#2f6fed;--accent2:#eaf1ff;--code:#f4f6fa;
    --mono:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
    font:14px/1.68 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
  header{background:var(--card);border-bottom:1px solid var(--line);padding:11px 18px;
    display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:10;flex-wrap:wrap}
  header h1{font-size:15px;margin:0;font-weight:650}
  header .grow{flex:1}
  header a{color:var(--accent);text-decoration:none;font-weight:600;font-size:12.5px;
    padding:6px 11px;border:1px solid var(--line);border-radius:8px;background:#fff}
  header a:hover{background:#f7f9fc}
  .wrap{max-width:960px;margin:0 auto;padding:18px 18px 60px}
  h1,h2,h3,h4{line-height:1.35;margin:22px 0 10px}
  h1{font-size:23px;margin-top:6px}
  h2{font-size:18px;padding-bottom:7px;border-bottom:1px solid var(--line)}
  h3{font-size:15.5px}
  h4{font-size:14px;color:#414a5b}
  p{margin:8px 0}
  a{color:var(--accent)}
  ul,ol{margin:8px 0;padding-left:24px}
  li{margin:3px 0}
  code{font-family:var(--mono);font-size:12.5px;background:var(--code);
    border:1px solid #e7eaf1;border-radius:5px;padding:1px 5px}
  pre{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:12px 14px;
    overflow:auto;margin:10px 0}
  pre code{background:none;border:none;padding:0;font-size:12.5px;line-height:1.65;white-space:pre}
  table{width:100%;border-collapse:separate;border-spacing:0;background:var(--card);
    border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:10px 0;font-size:13px}
  th{background:#fafbfd;color:var(--muted);font-weight:600;font-size:12.5px;text-align:left;
    padding:8px 11px;border-bottom:1px solid var(--line)}
  td{padding:8px 11px;border-bottom:1px solid #eef1f6;vertical-align:top}
  tr:last-child td{border-bottom:none}
  blockquote{margin:10px 0;padding:9px 13px;background:#fff8e6;border:1px solid #f0e0b8;
    border-radius:9px;color:#7a5300}
  hr{border:none;border-top:1px solid var(--line);margin:20px 0}
  .tip{background:var(--accent2);border:1px solid #cdddff;border-radius:9px;padding:9px 12px;
    font-size:12.5px;color:#31527f;margin:0 0 14px}
</style></head><body>
<header>
  <h1>📖 Kwrt 解密抓包 · 速查手册</h1>
  <span class="grow"></span>
  <a href="/">解密内容</a>
  <a href="/packets">抓包表格</a>
  <a href="/panel">控制台</a>
</header>
<div class="wrap">
  <div class="tip">本页内容来自路由器上的 <code>/usr/share/pktcap/CHEATSHEET.md</code>，改完文件刷新即可看到最新版本。</div>
  {{BODY}}
</div>
</body></html>
"""

_doc_cache = {"mtime": None, "html": None}


def serve_doc(conn):
    try:
        mt = os.path.getmtime(CHEAT_FILE)
        if _doc_cache["mtime"] != mt or _doc_cache["html"] is None:
            md = open(CHEAT_FILE, "r", encoding="utf-8", errors="replace").read()
            _doc_cache["html"] = DOC_TMPL.replace("{{BODY}}", _md_to_html(md))
            _doc_cache["mtime"] = mt
        body = _doc_cache["html"].encode("utf-8")
    except Exception as e:
        body = ("<div class='wrap'><h2>速查手册读取失败</h2><pre>" + _esc(repr(e)) +
                "</pre><p>请确认 /usr/share/pktcap/CHEATSHEET.md 存在。</p></div>").encode("utf-8")
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                 b"Cache-Control: no-cache\r\nConnection: close\r\nContent-Length: "
                 + str(len(body)).encode() + b"\r\n\r\n" + body)


def _write_file(p, s):
    try:
        d = os.path.dirname(p)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w") as f:
            f.write(s)
        os.replace(tmp, p)
        return True
    except Exception:
        return False


# =================================================================== 主动发请求
# 用途：解密页的「重放」与简易请求编辑器。
# 注意：python3-light 没有 email 模块，urllib / http.client 都会 import email 而失败，
#       所以这里用裸 socket + ssl 自己拼请求、自己解析响应。
SEND_MAX_BODY = int(os.environ.get("PKTCAP_SEND_MAX", str(2 * 1024 * 1024)))
SEND_TIMEOUT = int(os.environ.get("PKTCAP_SEND_TIMEOUT", "25"))
LOGCFG = os.path.join(MITM_CONF, "logcfg")
LOG_ENABLE_FILE = os.path.join(MITM_CONF, "log-enable")
AUTOCLOSE_FILE = os.path.join(MITM_CONF, "autoclose")
BODY_LOG_DEFAULT = "/tmp/mitm-body.jsonl"


def log_enabled():
    """日志总开关。文件不存在＝启用。关闭后不写记录也不抓正文。"""
    raw = _read_file(LOG_ENABLE_FILE, "")
    v = raw.strip().lower()
    if v == "":
        return True
    return v not in ("0", "off", "false", "no")


def set_log_enabled(on):
    return _write_file(LOG_ENABLE_FILE, "1" if on else "0")


def log_cfg():
    """日志保留配置：第一行大小上限(字节)，第二行保留条数。"""
    raw = _read_file(LOGCFG, "")
    maxb, lines = 4 * 1024 * 1024, 400
    parts = [x.strip() for x in raw.splitlines() if x.strip()]
    try:
        if len(parts) >= 1 and parts[0].isdigit():
            maxb = max(64 * 1024, int(parts[0]))
        if len(parts) >= 2 and parts[1].isdigit():
            lines = max(20, int(parts[1]))
    except Exception:
        pass
    return {"max_bytes": maxb, "keep_lines": lines}


def set_log_cfg(max_bytes, keep_lines):
    return _write_file(LOGCFG, "%d\n%d\n" % (int(max_bytes), int(keep_lines)))


def log_stats():
    p = os.environ.get("PKTCAP_BODYLOG", BODY_LOG_DEFAULT)
    try:
        sz = os.path.getsize(p)
    except Exception:
        sz = 0
    n = 0
    try:
        with open(p, "rb") as f:
            for _ in f:
                n += 1
    except Exception:
        pass
    c = log_cfg()
    return {"path": p, "bytes": sz, "lines": n,
            "enabled": log_enabled(),
            "max_bytes": c["max_bytes"], "keep_lines": c["keep_lines"]}


def log_trim(clear=False):
    p = os.environ.get("PKTCAP_BODYLOG", BODY_LOG_DEFAULT)
    c = log_cfg()
    try:
        if clear:
            _write_file(p, "")
            return {"ok": True, "lines": 0, "bytes": 0}
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            keep = f.readlines()[-c["keep_lines"]:]
        with open(p + ".tmp", "w", encoding="utf-8") as f:
            f.writelines(keep)
        os.replace(p + ".tmp", p)
        try:
            sz = os.path.getsize(p)
        except Exception:
            sz = 0
        return {"ok": True, "lines": len(keep), "bytes": sz}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def autoclose_cfg():
    """无人监听时自动关闭解密：第一行 1/0 启用，第二行 空闲分钟数。"""
    raw = _read_file(AUTOCLOSE_FILE, "")
    parts = [x.strip() for x in raw.splitlines() if x.strip()]
    enabled, minutes = True, 5
    if len(parts) >= 1:
        enabled = parts[0] in ("1", "on", "true", "yes")
    if len(parts) >= 2 and parts[1].isdigit():
        minutes = max(1, min(240, int(parts[1])))
    return {"enabled": enabled, "minutes": minutes}


def set_autoclose(enabled, minutes):
    return _write_file(AUTOCLOSE_FILE, "%d\n%d\n" % (1 if enabled else 0, int(minutes)))


class _SockBuf(object):
    """带缓冲的 socket 读取器（解析响应头/体用）。"""

    def __init__(self, sock, initial=b""):
        self.s = sock
        self.b = initial

    def _fill(self, n=65536):
        try:
            d = self.s.recv(n)
        except Exception:
            d = b""
        self.b += d
        return bool(d)

    def readline(self, limit=65536):
        while b"\n" not in self.b:
            if len(self.b) > limit or not self._fill():
                break
        i = self.b.find(b"\n")
        if i < 0:
            out, self.b = self.b, b""
            return out
        out, self.b = self.b[:i + 1], self.b[i + 1:]
        return out

    def read(self, n):
        while len(self.b) < n:
            if not self._fill(max(1, n - len(self.b))):
                break
        out, self.b = self.b[:n], self.b[n:]
        return out

    def read_until_eof(self, cap):
        while len(self.b) < cap:
            if not self._fill():
                break
        out, self.b = self.b[:cap], self.b[cap:]
        return out


def _split_url(url):
    m = re.match(r"^\s*([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]+)([^#]*)", url or "")
    if not m:
        return None
    scheme = m.group(1).lower()
    if scheme not in ("http", "https"):
        return None
    hostport, path = m.group(2), (m.group(3) or "/")
    if not path.startswith("/"):
        path = "/" + path
    if hostport.startswith("["):
        i = hostport.find("]")
        if i < 0:
            return None
        host = hostport[1:i]
        rest = hostport[i + 1:]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else (443 if scheme == "https" else 80)
    elif ":" in hostport:
        h, _, p = hostport.rpartition(":")
        if not p.isdigit():
            return None
        host, port = h, int(p)
    else:
        host, port = hostport, (443 if scheme == "https" else 80)
    if not host or not (0 < port < 65536):
        return None
    return scheme, host, port, path


def _dechunk(rb, cap):
    out = b""
    while len(out) < cap:
        line = rb.readline().strip()
        if not line:
            break
        try:
            n = int(line.split(b";")[0], 16)
        except Exception:
            break
        if n == 0:
            rb.readline()
            break
        out += rb.read(n)
        rb.readline()
    return out


def _decompress(data, ce):
    ce = (ce or "").lower()
    if "gzip" in ce or "x-gzip" in ce:
        for f in (lambda: zlib.decompress(data, 16 + zlib.MAX_WBITS),
                  lambda: zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data)):
            try:
                return f()
            except Exception:
                pass
    elif "deflate" in ce:
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompressobj(wbits).decompress(data)
            except Exception:
                pass
    return data


def send_request(method, url, headers, body):
    """从路由器直接发出一个请求，返回结构化响应（供重放 / 请求编辑器用）。"""
    t0 = time.time()
    parsed = _split_url(url)
    if not parsed:
        return {"ok": False, "error": "URL 不合法，需要以 http:// 或 https:// 开头"}
    scheme, host, port, path = parsed
    method = (method or "GET").upper().strip()
    if not re.match(r"^[A-Z]{3,10}$", method):
        return {"ok": False, "error": "请求方法不合法"}

    hdrs, seen = [], set()
    for k, v in (headers or {}).items():
        k = str(k).strip()
        if not k or ":" in k or "\n" in k or "\r" in k:
            continue
        hdrs.append((k, str(v).replace("\r", " ").replace("\n", " ").strip()))
        seen.add(k.lower())
    default_port = 443 if scheme == "https" else 80
    if "host" not in seen:
        hdrs.append(("Host", host if port == default_port else "%s:%d" % (host, port)))
    if "connection" not in seen:
        hdrs.append(("Connection", "close"))
    bb = body if isinstance(body, bytes) else (body or "").encode("utf-8")
    if bb and "content-length" not in seen:
        hdrs.append(("Content-Length", str(len(bb))))

    req = ("%s %s HTTP/1.1\r\n" % (method, path)).encode("iso-8859-1", "replace")
    for k, v in hdrs:
        req += ("%s: %s\r\n" % (k, v)).encode("iso-8859-1", "replace")
    req += b"\r\n" + bb

    srv = None
    raw = None
    try:
        # 注意：python3-light 缺 encodings.idna，getaddrinfo 传 str 会抛
        # "LookupError: unknown encoding: idna"，所以主机名要传 bytes。
        raw = socket.create_connection((host.encode("ascii", "ignore"), port), timeout=SEND_TIMEOUT)
        srv = raw
        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except Exception:
                pass
            srv = ctx.wrap_socket(raw, server_hostname=host.encode("ascii", "ignore"))
        srv.settimeout(SEND_TIMEOUT)

        srv.sendall(req)

        rb = _SockBuf(srv)
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 262144:
            d = srv.recv(65536)
            if not d:
                break
            head += d
        if b"\r\n\r\n" not in head:
            return {"ok": False, "error": "未收到完整响应头（可能不是 HTTP 服务）",
                    "ms": int((time.time() - t0) * 1000)}
        hpart, rest = head.split(b"\r\n\r\n", 1)
        lines = hpart.decode("latin-1", "replace").split("\r\n")
        status_line = lines[0] if lines else ""
        sp = status_line.split(" ", 2)
        status = sp[1] if len(sp) > 1 else ""
        rh = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                rh[k.strip()] = v.strip()

        rb = _SockBuf(srv, rest)
        te = (rh.get("Transfer-Encoding") or "").lower()
        cl = rh.get("Content-Length") or ""
        if "chunked" in te:
            raw_body = _dechunk(rb, SEND_MAX_BODY)
        elif cl.isdigit():
            raw_body = rb.read(min(int(cl), SEND_MAX_BODY))
        else:
            raw_body = rb.read_until_eof(SEND_MAX_BODY)

        dec = _decompress(raw_body, rh.get("Content-Encoding"))
        text = None
        try:
            text = dec.decode("utf-8")
        except UnicodeDecodeError:
            try:
                t = dec.decode("latin-1")
                pr = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
                text = t if t and pr / max(1, len(t)) >= 0.9 else None
            except Exception:
                text = None
        snip = text[:MAX_SNIPPET] if text else None
        _ct = rh.get("Content-Type") or ""
        _blob = blob_write(dec, _ct) if text is None else None
        return {
            "ok": True, "status": status, "status_line": status_line,
            "headers": rh, "ctype": _ct,
            "blob": _blob, "blob_ext": blob_ext_for(_ct),
            "body": snip, "binary": text is None,
            "len": len(raw_body), "truncated": bool(text) and len(text) > MAX_SNIPPET,
            "cjk": (list(dict.fromkeys(CJK_RE.findall(text)))[:12] or None) if text else None,
            "ms": int((time.time() - t0) * 1000),
            "sent": {"method": method, "url": url, "headers": {k: v for k, v in hdrs},
                     "body_len": len(bb)},
        }
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e),
                "ms": int((time.time() - t0) * 1000)}
    finally:
        try:
            if srv is not None:
                srv.close()
        except Exception:
            pass


def list_ifaces():
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except Exception:
        names = []
    skip = ("lo", "ip6tnl0", "sit0", "tunl0", "gre0")
    return [n for n in names if n not in skip]


def _find_bin(*names):
    """在常见 bin 目录里找可执行文件（不依赖 shutil，python3-light 也能跑）。"""
    dirs = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin")
    for d in dirs:
        for nm in names:
            p = os.path.join(d, nm)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
    return ""


MITM_CTL = _find_bin("mitm-ctl")
NFT_BIN = _find_bin("nft")
NFT_SH = "/usr/libexec/mitm-nft.sh"
# 透明模式：既要有 nft，也要有规则下发脚本；否则就是显式代理模式（如容器）
TRANSPARENT = bool(NFT_BIN) and os.path.isfile(NFT_SH)


def proxy_running():
    try:
        return int((_sh("ps w 2>/dev/null | grep -c '[m]itm_proxy'").strip() or "0")) > 0
    except Exception:
        return False


def mitm_status():
    running = proxy_running()
    if TRANSPARENT:
        nft = _sh("nft list table inet mitm 2>/dev/null")
        enabled = ("redirect" in nft) or ("drop" in nft)
    else:
        # 显式代理模式（Docker / 手动设代理）：代理在跑就是已开启
        enabled = running
    bypass_raw = _read_file(MITM_BYPASS, "")
    IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    bypass, bypass_ip = [], 0
    for l in bypass_raw.splitlines():
        t = l.strip()
        if not t or t.startswith("#"):
            continue
        if IP_RE.match(t):
            bypass_ip += 1          # IP 也放行，但不在面板里刷屏
        else:
            bypass.append(t)
    return {
        "enabled": bool(enabled),
        "running": bool(running),
        "targets": _read_file(MITM_TARGETS, "10.0.0.0/24").strip(),
        "mode": (_read_file(MITM_MODE, "all").strip() or "all"),
        "domains": _read_file(MITM_DOMAINS, ""),
        "bypass": bypass,
        "bypass_count": len(bypass),
        "bypass_ip_count": bypass_ip,
        "ifaces": _read_file(MITM_IFACES, "").strip(),
        "avail_ifaces": list_ifaces(),
        "autoclose": autoclose_cfg(),
        "log_enabled": log_enabled(),
        "viewers": active_viewers(),
        "ca_url": ca_url(),
    }


def _looks_like_ip(s):
    """只接受纯 IPv4/IPv6 字面量。命令失败时会把报错文本吐回来，绝不能当 IP 用。"""
    s = (s or "").strip()
    if not s or len(s) > 45 or any(c in s for c in " \t\n\r:/\\?"):
        return False
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except Exception:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except Exception:
        return False


def ca_url():
    """内置证书下载页：http://<本机LAN IP>:<端口>/cert
    不再依赖 nginx/uhttpd，Debian / Docker 上同样可用。"""
    cands = []
    try:
        cands.append(_sh("uci get network.lan.ipaddr 2>/dev/null").split("/")[0])
    except Exception:
        pass
    for cmd in (("ip -4 addr show %s 2>/dev/null | awk '/inet /{print $2}' "
                 "| cut -d/ -f1 | head -1") % IFACE,
                "ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}'",
                "hostname -I 2>/dev/null | awk '{print $1}'"):
        try:
            cands.append(_sh(cmd))
        except Exception:
            pass
    # UDP connect 探测（不实际发包）作为兜底
    try:
        s_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_.connect(("8.8.8.8", 80))
        cands.append(s_.getsockname()[0])
        s_.close()
    except Exception:
        pass
    ip = ""
    for c in cands:
        if _looks_like_ip(c):
            ip = c.strip()
            break
    if not ip:
        ip = "127.0.0.1"
    return "http://%s:%d/cert" % (ip, PORT)


def _ctl(*args):
    """调用 mitm-ctl；没有它（容器/显式代理）就直接跳过。"""
    if not MITM_CTL:
        return
    _sh(MITM_CTL + " " + " ".join(args))


def mitm_apply(cfg):
    os.makedirs(MITM_CONF, exist_ok=True)
    # 0) 清空「自动放行」名单（把之前因证书固定被放行的域名重新纳入解密，需重启代理）
    if cfg.get("action") == "clearbypass":
        try:
            with open(MITM_BYPASS, "w") as f:
                f.write("")
        except Exception:
            pass
        if os.path.isfile("/etc/init.d/mitm"):
            _sh("/etc/init.d/mitm restart >/dev/null 2>&1")
            time.sleep(1.5)
        return {"ok": True, "status": mitm_status()}
    cur = mitm_status()
    want_enabled = bool(cfg.get("enabled", cur["enabled"]))
    # 1) 域名模式与列表
    if cfg.get("mode") in ("all", "list", "exclude"):
        with open(MITM_MODE, "w") as f:
            f.write(cfg["mode"])
    if isinstance(cfg.get("domains"), str):
        with open(MITM_DOMAINS, "w") as f:
            f.write(cfg["domains"])
    # 2) 网卡过滤
    if isinstance(cfg.get("ifaces"), str):
        allowed = set(list_ifaces())
        keep = []
        for ln in cfg["ifaces"].replace(",", "\n").splitlines():
            ln = ln.strip()
            if ln and ln in allowed:
                keep.append(ln)
        with open(MITM_IFACES, "w") as f:
            f.write("\n".join(keep) + ("\n" if keep else ""))
    # 3) 抓包范围
    scope = cfg.get("scope")
    if scope == "all":
        _ctl("all")
    elif scope == "ip":
        ip = (cfg.get("ip") or "").strip()
        if not re.match(r"^[0-9A-Fa-f:.]{3,45}(/\d{1,2})?$", ip):
            return {"ok": False, "error": "设备 IP 格式不正确"}
        _ctl("only", ip)
    # 4) 重新下发规则（应用网卡集合）；显式代理模式无需规则
    if TRANSPARENT:
        _sh(NFT_SH + " apply")
    # 4.5) 无人监听自动关闭解密的设置
    if "autoclose_enabled" in cfg or "autoclose_minutes" in cfg:
        cur_ac = autoclose_cfg()
        en = cfg.get("autoclose_enabled", cur_ac["enabled"])
        try:
            mi = int(cfg.get("autoclose_minutes", cur_ac["minutes"]))
        except Exception:
            mi = cur_ac["minutes"]
        mi = max(1, min(240, mi))
        set_autoclose(bool(en), mi)
    # 5) 总开关
    if TRANSPARENT or MITM_CTL:
        if want_enabled:
            _ctl("on")
        else:
            # off  = 只清拦截规则（代理留着，随时秒开）
            # stop = 清规则 + 停代理进程（最省 CPU，默认）
            if (cfg.get("stop_mode") or "").strip() == "off":
                _ctl("off")
            else:
                _ctl("stop")
    # 显式代理模式（容器）：进程由容器托管，无法在此停启；配置改动由代理按 mtime 自行热加载
    return {"ok": True, "status": mitm_status()}


def send_json(conn, obj, code="200 OK"):
    b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    conn.sendall(("HTTP/1.1 " + code + "\r\nContent-Type: application/json; charset=utf-8\r\n"
                  "Cache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\n"
                  "Content-Length: " + str(len(b)) + "\r\n\r\n").encode("utf-8") + b)


def client_thread(conn):
    try:
        conn.settimeout(20)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            ch = conn.recv(4096)
            if not ch:
                return
            data += ch
        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
        lines = head.split("\r\n")
        req = lines[0].split(" ") if lines else ["", "/"]
        method = (req[0].upper() if req else "GET")
        path = req[1] if len(req) > 1 else "/"
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        try:
            clen = int(headers.get("content-length", "0") or 0)
        except Exception:
            clen = 0
        while len(body) < clen:
            ch = conn.recv(65536)
            if not ch:
                break
            body += ch

        # 证书下载页/文件不鉴权：手机装 CA 时无法带 Basic 认证
        if path.startswith("/cert") or path.startswith("/mitm-ca."):
            nm = path.split("?")[0].rsplit("/", 1)[-1]
            if nm in ("mitm-ca.crt", "mitm-ca.pem"):
                serve_ca_file(conn, nm)
            else:
                serve_cert_page(conn)
            return

        if USER:
            ok = False
            a = headers.get("authorization", "")
            if a.startswith("Basic "):
                try:
                    u, p = base64.b64decode(a[6:]).decode("utf-8", "replace").split(":", 1)
                    ok = (u == USER and p == PASS)
                except Exception:
                    ok = False
            if not ok:
                conn.sendall(b"HTTP/1.1 401 Unauthorized\r\n"
                             b"WWW-Authenticate: Basic realm=\"pktcap\"\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                return

        if path.startswith("/doc"):
            serve_doc(conn)
        elif path.startswith("/blob/"):
            # 抓到的图片/文档：/blob/<id> 在线看，/blob/<id>?dl=1 下载
            bid = path[len("/blob/"):].split("?")[0]
            serve_blob(conn, bid, download=("dl=1" in path))
        elif path.startswith("/api/blob"):
            try:
                if method == "POST":
                    cfg = json.loads(body.decode("utf-8", "replace") or "{}")
                    if (cfg.get("action") or "").strip() == "clear":
                        blob_clear()
                res = {"ok": True, "stats": blob_stats()}
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            send_json(conn, res)
        elif path.startswith("/stream"):
            serve_sse(conn)
        elif path.startswith("/api/ping"):
            # 解密页心跳：页面可见时每 30s 来一次；关掉/切后台就停，用于「无人监听自动关闭」
            try:
                key = conn.getpeername()[0]
            except Exception:
                key = "unknown"
            ping_client(key)
            send_json(conn, {"ok": True, "viewers": active_viewers()})
        elif path.startswith("/api/capture"):
            try:
                if method == "POST":
                    cfg = json.loads(body.decode("utf-8", "replace") or "{}")
                    act = (cfg.get("action") or "").strip()
                    if act == "start":
                        CAP.start()
                    elif act == "stop":
                        CAP.stop()
                    if "keepalive" in cfg:
                        set_keepalive(bool(cfg.get("keepalive")))
                    res = {"ok": True, "status": CAP.status()}
                else:
                    res = {"ok": True, "status": CAP.status()}
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            send_json(conn, res)
        elif path.startswith("/api/send"):
            # 重放 / 请求编辑器：由路由器代发请求
            try:
                cfg = json.loads(body.decode("utf-8", "replace") or "{}")
                res = send_request(cfg.get("method"), cfg.get("url"),
                                   cfg.get("headers"), cfg.get("body"))
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            send_json(conn, res)
        elif path.startswith("/api/log"):
            # 日志总开关 / 保留配置 / 立即清理
            try:
                if method == "POST":
                    cfg = json.loads(body.decode("utf-8", "replace") or "{}")
                    act = (cfg.get("action") or "").strip()
                    if act == "enable":
                        set_log_enabled(True)
                    elif act == "disable":
                        # 关闭的同时清空现有记录，把内存盘立刻释放出来
                        set_log_enabled(False)
                        log_trim(clear=True)
                    elif act == "clear":
                        log_trim(clear=True)
                    elif act == "trim":
                        log_trim()
                    elif act == "save":
                        c = log_cfg()
                        mb = cfg.get("max_bytes")
                        kl = cfg.get("keep_lines")
                        set_log_cfg(int(mb) if mb else c["max_bytes"],
                                    int(kl) if kl else c["keep_lines"])
                res = {"ok": True, "stats": log_stats()}
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            send_json(conn, res)
        elif path.startswith("/hstream"):
            serve_https_stream(conn)
        elif path.startswith("/bstream"):
            serve_body_stream(conn)
        elif path.startswith("/body"):
            serve_file(conn, BODY_INDEX, "text/html")
        elif path.startswith("/panel"):
            serve_file(conn, PANEL_INDEX, "text/html")
        elif path.startswith("/packets"):
            serve_file(conn, INDEX, "text/html")
        elif path.startswith("/api/mitm"):
            try:
                if method == "POST":
                    cfg = json.loads(body.decode("utf-8", "replace") or "{}")
                    res = mitm_apply(cfg)
                else:
                    res = {"ok": True, "status": mitm_status()}
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            send_json(conn, res)
        elif path.startswith("/https"):
            # 旧版这一页读的是 squid 的日志，现在引擎已换成自建代理，squid 日志是死的。
            # 统一跳到 /body（同一个数据源），避免「点进去是空的」。
            conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: /body\r\n"
                         b"Cache-Control: no-cache\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
        elif path.startswith("/last"):
            b = json.dumps(CAP.snapshot(), ensure_ascii=False).encode("utf-8")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
                         b"Access-Control-Allow-Origin: *\r\nContent-Length: " +
                         str(len(b)).encode() + b"\r\n\r\n" + b)
        else:
            # 默认入口 = 解密内容页（抓包不是常用功能，放在 /packets）
            conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: /body\r\n"
                         b"Cache-Control: no-cache\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main_server(replay=None):
    # 抓包默认关闭：只有网页上点「开始抓包」才启动 tcpdump（省 CPU/内存）
    if replay:
        CAP.start_replay(replay)
    threading.Thread(target=autoclose_monitor, daemon=True).start()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(64)
    sys.stderr.write("pktcap listening on 0.0.0.0:%d iface=%s (capture off by default)\n"
                     % (PORT, IFACE))
    while True:
        try:
            conn, _ = s.accept()
        except Exception:
            continue
        threading.Thread(target=client_thread, args=(conn,), daemon=True).start()


def main_test(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        endian = "<" if gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        ns = gh[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        n = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_s, ts_u, incl, orig = struct.unpack(endian + "IIII", hdr)
            data = f.read(incl)
            if len(data) < incl:
                break
            ts = ts_s + (ts_u / 1e9 if ns else ts_u / 1e6)
            n += 1
            pkt = parse_packet(data, linktype, ts, n)
            print(json.dumps(pkt, ensure_ascii=False))
            if "--stats" in sys.argv and n % 50 == 0:
                sys.stderr.write("... %d\n" % n)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--test":
        main_test(sys.argv[2])
    elif len(sys.argv) > 2 and sys.argv[1] == "--replay":
        main_server(replay=sys.argv[2])
    else:
        main_server()

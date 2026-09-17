#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
构建 OpenWrt / iStore 安装包（.ipk）+ opkg feed 索引。

产出：
  dist/mitm-ctl_<ver>-1_all.ipk            程序本体（服务 + 网页 + LuCI 入口 + setup 脚本）
  dist/app-meta-mitm-ctl_<ver>-1_all.ipk   iStore 应用元数据（描述 + 图标）
  feed/                                    上述 ipk + Packages / Packages.gz（可直接当 opkg 源）

用法：
  python3 tools/build-pkg.py
  python3 tools/build-pkg.py --version 1.1.0
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PKG_NAME = "mitm-ctl"
APP_PKG = "app-meta-mitm-ctl"
ARCH = "all"
SECTION = "net"
LICENSE = "MIT"
MAINTAINER = "mitm-ctl <https://github.com/ajxdp/mitm-ctl>"
HOMEPAGE = "https://github.com/ajxdp/mitm-ctl"
FEED_URL = "https://raw.githubusercontent.com/ajxdp/mitm-ctl/main/feed"

# 实测该设备存在且在源里的包名：nft 由 nftables-json 提供（没有 nftables 这个包）
DEPENDS = ("python3-light, python3-openssl, python3-cryptography, "
           "openssl-util, nftables-json, tcpdump")

DESC_SHORT = "轻量 HTTPS 解密抓包：透明代理 + 网页控制台"
DESC_LONG = [
    "在路由器上做透明 HTTPS 解密抓包，不依赖 mitmproxy / squid，纯 Python 标准库实现。",
    "功能：请求/响应完整正文、JSON 可折叠树、图片与 PDF 直接预览、请求重放与编辑发送、",
    "流量抓包表格、证书固定自动放行；解密/抓包/日志三个开关按需启停，默认全关不占性能。",
    "网页入口 http://<路由器IP>:7690/ ，证书下载 http://<路由器IP>:7690/cert",
]

MTIME = 1700000000          # 固定时间戳，保证可复现构建


# ============================================================ 打包基础
def tar_gz(entries):
    """entries: [(name, mode, bytes|None)]，None 表示目录；name 以 ./ 开头。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        for name, mode, data in entries:
            ti = tarfile.TarInfo(name)
            ti.mode = mode
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mtime = MTIME
            if data is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.type = tarfile.REGTYPE
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def ar_archive(members):
    """[(name, bytes)] → opkg/Debian 风格的 ar 归档。"""
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        nm = name.encode("ascii")
        if len(nm) > 15:
            raise ValueError("ar 成员名过长: " + name)
        out += (nm + b" " * (16 - len(nm)) +
                b"0".ljust(12) +                  # mtime
                b"0".ljust(6) + b"0".ljust(6) +   # uid / gid
                b"100644".ljust(8) +              # mode
                str(len(data)).encode().ljust(10) + b"`\n")
        out += data
        if len(data) % 2:
            out += b"\n"
    return bytes(out)


def control_text(fields, desc_lines):
    txt = "\n".join("%s: %s" % (k, v) for k, v in fields)
    txt += "\nDescription: " + desc_lines[0] + "\n"
    txt += "".join(" " + ln + "\n" for ln in desc_lines[1:])
    return txt.encode("utf-8")


IPK_FORMAT = "targz"          # targz = OpenWrt 24.10+ / Kwrt 25.x；ar = 23.05 及更早


def build_ipk(ctrl_bytes, scripts, data_entries):
    ctrl = [(".", 0o755, None), ("./control", 0o644, ctrl_bytes)]
    for fname in ("postinst", "prerm", "postrm"):
        body = scripts.get(fname)
        if body:
            ctrl.append(("./" + fname, 0o755,
                         body.replace("\r\n", "\n").encode("utf-8")))
    ctrl_gz = tar_gz(ctrl)
    data_gz = tar_gz(data_entries)

    if IPK_FORMAT == "ar":
        # 经典 Debian 格式（老 opkg）
        return ar_archive([
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", ctrl_gz),
            ("data.tar.gz", data_gz),
        ])
    # 新版格式：外层就是一个 gzip 压缩的 tar
    return tar_gz([
        (".", 0o755, None),
        ("./debian-binary", 0o644, b"2.0\n"),
        ("./data.tar.gz", 0o644, data_gz),
        ("./control.tar.gz", 0o644, ctrl_gz),
    ])


def parse_ar_simple(data):
    """仅用于自检：解析 ar 归档。"""
    assert data[:8] == b"!<arch>\n", "不是 ar 归档"
    pos, out = 8, []
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[0:16].decode("ascii").strip().rstrip("/")
        size = int(hdr[48:58].decode("ascii").strip())
        out.append((name, data[pos + 60:pos + 60 + size]))
        pos += 60 + size + (size % 2)
    return out


def read_text(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.isfile(p):
        raise SystemExit("缺少文件: " + rel)
    with open(p, "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def read_bin(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.isfile(p):
        raise SystemExit("缺少文件: " + rel)
    with open(p, "rb") as f:
        return f.read()


# initd/ 是"模板"：install.sh 会用 sed 填占位符，ipk 里必须填好真实默认值，
# 否则会出现 PKTCAP_PORT=__PORT__ → int("__PORT__") 崩溃（真机踩过）
TEMPLATE_FILES = {"initd/mitm", "initd/pktcap"}
PKG_SUBS = {
    "__CONF__": "/etc/mitm",
    "__PORT__": "7690",
    "__USER__": "root",
    "__PASS__": "root",
    "__LAN_IF__": "br-lan",
    "__CA_CRT__": "/etc/mitm/ca/mitm-ca.crt",
    "__CA_KEY__": "/etc/mitm/ca/mitm-ca.key",
}


def render_template(rel, blob):
    txt = blob.decode("utf-8")
    for k, v in PKG_SUBS.items():
        txt = txt.replace(k, v)
    left = [k for k in PKG_SUBS if k in txt]
    if left:
        raise SystemExit("%s 里还有未替换的占位符：%s" % (rel, left))
    return txt.encode("utf-8")


def pack_tree(mapping):
    """mapping: [(src_rel, dest_rel, mode, is_binary)] → 带父目录的 tar 条目。"""
    entries, seen = [], set()
    for src, dest, mode, binary in mapping:
        parts = dest.strip("/").split("/")[:-1]
        cur = "."
        for p in parts:
            cur = cur + "/" + p
            if cur not in seen:
                seen.add(cur)
                entries.append((cur + "/", 0o755, None))
        if binary:
            blob = read_bin(src)
        else:
            blob = read_text(src)
            if src in TEMPLATE_FILES:
                blob = render_template(src, blob)
        entries.append(("./" + dest, mode, blob))
    return entries


# ============================================================ 安装脚本
POSTINST = """#!/bin/sh
# 安装/升级后：初始化 CA、配置、网络探测，并启用启动服务
if [ -f /etc/openwrt_release ]; then MODE=gateway; else MODE=proxy; fi
if [ -x /usr/libexec/mitm-ctl-setup ]; then
    MITM_MODE="$MODE" sh /usr/libexec/mitm-ctl-setup
fi
exit 0
"""

PRERM = """#!/bin/sh
# 卸载/升级前：先清重定向规则再停服务（否则流量会打到没人监听的端口）
[ -x /usr/libexec/mitm-nft.sh ] && /usr/libexec/mitm-nft.sh clear 2>/dev/null
for s in mitm pktcap; do
    if [ -x /etc/init.d/$s ]; then
        /etc/init.d/$s stop    >/dev/null 2>&1
        /etc/init.d/$s disable >/dev/null 2>&1
    fi
done
exit 0
"""

POSTRM = """#!/bin/sh
# $1 = remove | upgrade
case "$1" in
    remove)
        nft delete table inet mitm 2>/dev/null
        rm -rf /tmp/mitm-certs /tmp/mitm-body.jsonl /tmp/mitm-blobs 2>/dev/null
        rm -f /tmp/luci-indexcache* 2>/dev/null
        # 配置与 CA 有意保留（/etc/mitm、/etc/squid/ssl/mitm-ca.*），
        # 否则重装后所有设备都要重新装证书。彻底清除请执行： mitm-ctl purge
        ;;
esac
exit 0
"""

# uci-defaults：开机自愈，配置被清掉也能恢复
UCI_DEFAULTS = """#!/bin/sh
# mitm-ctl 首次启动/配置自愈（幂等）
[ -x /usr/libexec/mitm-ctl-setup ] || exit 0
if [ -f /etc/openwrt_release ]; then MODE=gateway; else MODE=proxy; fi
MITM_MODE="$MODE" MITM_QUIET=1 sh /usr/libexec/mitm-ctl-setup
exit 0
"""


# ============================================================ 主流程
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--out", default="dist")
    ap.add_argument("--format", default="targz", choices=("targz", "ar"),
                    help="targz=OpenWrt 24.10+/Kwrt 25.x（默认）；ar=OpenWrt 23.05 及更早")
    args = ap.parse_args()

    global IPK_FORMAT
    IPK_FORMAT = args.format

    ver = args.version
    pkgver = "%s-1" % ver
    out = os.path.join(ROOT, args.out)
    feed = os.path.join(ROOT, "feed")
    os.makedirs(out, exist_ok=True)
    os.makedirs(feed, exist_ok=True)

    # ---------------- 主包
    main_files = [
        ("pktcap_server.py",                    "usr/share/pktcap/pktcap_server.py", 0o755, 0),
        ("body.html",                           "usr/share/pktcap/body.html", 0o644, 0),
        ("panel.html",                          "usr/share/pktcap/panel.html", 0o644, 0),
        ("index.html",                          "usr/share/pktcap/index.html", 0o644, 0),
        ("CHEATSHEET.md",                       "usr/share/pktcap/CHEATSHEET.md", 0o644, 0),
        ("mitm_proxy.py",                       "usr/share/mitm/mitm_proxy.py", 0o755, 0),
        ("bin/auto-bypass.default.txt",         "usr/share/mitm/auto-bypass.default.txt", 0o644, 0),
        ("bin/mitm-ctl",                        "usr/bin/mitm-ctl", 0o755, 0),
        ("bin/mitm-nft.sh",                     "usr/libexec/mitm-nft.sh", 0o755, 0),
        ("bin/mitm-ctl-setup",                  "usr/libexec/mitm-ctl-setup", 0o755, 0),
        ("initd/mitm",                          "etc/init.d/mitm", 0o755, 0),
        ("initd/pktcap",                        "etc/init.d/pktcap", 0o755, 0),
        ("luci/menu.d/luci-app-mitmctl.json",   "usr/share/luci/menu.d/luci-app-mitmctl.json", 0o644, 0),
        ("luci/acl.d/luci-app-mitmctl.json",    "usr/share/rpcd/acl.d/luci-app-mitmctl.json", 0o644, 0),
        ("luci/view/mitmctl/decrypt.js",        "www/luci-static/resources/view/mitmctl/decrypt.js", 0o644, 0),
        ("luci/view/mitmctl/panel.js",          "www/luci-static/resources/view/mitmctl/panel.js", 0o644, 0),
        ("luci/view/mitmctl/packets.js",        "www/luci-static/resources/view/mitmctl/packets.js", 0o644, 0),
        ("icon/mitm-ctl.png",                   "www/luci-static/resources/app-icons/mitm-ctl.png", 0o644, 1),
    ]
    main_data = pack_tree(main_files)
    # uci-defaults 由脚本生成（内容在仓库里没有独立文件）
    main_data.append(("./etc/uci-defaults/99-mitm-ctl", 0o755,
                      UCI_DEFAULTS.replace("\r\n", "\n").encode("utf-8")))

    installed = sum(len(d) for _, _, d in main_data if d) // 1024
    ctrl_main = control_text([
        ("Package", PKG_NAME),
        ("Version", pkgver),
        ("Depends", DEPENDS),
        ("Source", HOMEPAGE),
        ("SourceName", PKG_NAME),
        ("License", LICENSE),
        ("Section", SECTION),
        ("Priority", "optional"),
        ("Architecture", ARCH),
        ("Installed-Size", installed),
        ("Maintainer", MAINTAINER),
    ], [DESC_SHORT] + DESC_LONG)
    ipk_main = build_ipk(ctrl_main,
                         {"postinst": POSTINST, "prerm": PRERM, "postrm": POSTRM},
                         main_data)
    name_main = "%s_%s_%s.ipk" % (PKG_NAME, pkgver, ARCH)

    # ---------------- iStore 元数据包
    meta = {
        "name": PKG_NAME,
        "title": "HTTPS 解密抓包",
        "title_en": "HTTPS Decrypt Capture",
        "entry": "/cgi-bin/luci/admin/services/mitmctl/decrypt",
        "author": "ajxdp",
        "website": HOMEPAGE,
        "tutorial": HOMEPAGE,
        "version": ver,
        "release": 1,
        "arch": [ARCH],
        "description": ("轻量 HTTPS 解密抓包。可看请求/返回完整正文、折叠 JSON、"
                        "直接预览图片与 PDF，支持重放和编辑发送请求；"
                        "解密/抓包/日志默认全关，按需开启不占性能。"),
        "description_en": ("Lightweight transparent HTTPS MITM capture for routers. "
                           "Full request/response bodies, collapsible JSON, inline "
                           "image/PDF preview, request replay & editor. Everything "
                           "is off by default and enabled on demand."),
        "tags": ["networking", "tools"],
        "depends": [PKG_NAME],
    }
    meta_bytes = (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    app_data, seen = [], set()
    for dest, blob in (("usr/lib/opkg/meta/%s.json" % PKG_NAME, meta_bytes),
                       ("www/luci-static/resources/app-icons/%s.png" % PKG_NAME,
                        read_bin("icon/mitm-ctl.png"))):
        parts, cur = dest.split("/")[:-1], "."
        for p in parts:
            cur = cur + "/" + p
            if cur not in seen:
                seen.add(cur)
                app_data.append((cur + "/", 0o755, None))
        app_data.append(("./" + dest, 0o644, blob))

    ctrl_app = control_text([
        ("Package", APP_PKG),
        ("Version", pkgver),
        ("Depends", PKG_NAME),
        ("Source", HOMEPAGE),
        ("SourceName", APP_PKG),
        ("License", LICENSE),
        ("Section", SECTION),
        ("Priority", "optional"),
        ("Architecture", ARCH),
        ("Installed-Size", (len(meta_bytes) + len(read_bin("icon/mitm-ctl.png"))) // 1024),
        ("Maintainer", MAINTAINER),
    ], ["iStore 应用信息：" + DESC_SHORT,
        "提供给 iStore / LuCI 应用列表的描述与图标；安装本包会自动装上 " + PKG_NAME + "。"])
    ipk_app = build_ipk(ctrl_app, {}, app_data)
    name_app = "%s_%s_%s.ipk" % (APP_PKG, pkgver, ARCH)

    # ---------------- feed 索引
    def entry(pkg, depends, blob, desc_lines):
        return "\n".join([
            "Package: " + pkg,
            "Version: " + pkgver,
            "Depends: " + depends,
            "Architecture: " + ARCH,
            "Section: " + SECTION,
            "Priority: optional",
            "License: " + LICENSE,
            "Maintainer: " + MAINTAINER,
            "Source: " + HOMEPAGE,
            "Filename: " + NAME_OF[pkg],
            "Size: %d" % len(blob),
            "SHA256sum: " + hashlib.sha256(blob).hexdigest(),
            "MD5Sum: " + hashlib.md5(blob).hexdigest(),
            "Description: " + desc_lines[0],
        ] + [" " + ln for ln in desc_lines[1:]]) + "\n"

    NAME_OF = {PKG_NAME: name_main, APP_PKG: name_app}
    idx = entry(PKG_NAME, DEPENDS, ipk_main, [DESC_SHORT] + DESC_LONG)
    idx += "\n"
    idx += entry(APP_PKG, PKG_NAME, ipk_app,
                 ["iStore 应用信息：" + DESC_SHORT, "元数据与图标。"])
    idx_b = idx.encode("utf-8")

    for nm, blob in ((name_main, ipk_main), (name_app, ipk_app)):
        open(os.path.join(feed, nm), "wb").write(blob)
        open(os.path.join(out, nm), "wb").write(blob)
    open(os.path.join(feed, "Packages"), "wb").write(idx_b)
    open(os.path.join(feed, "Packages.gz"), "wb").write(gzip.compress(idx_b, 9))

    # ---- 出厂自检：解回 data.tar.gz，确认模板占位符没漏网
    def _selfcheck(blob, label):
        inner = blob
        if IPK_FORMAT == "targz":
            outer = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
            names = [m.name for m in outer.getmembers()]
            if "./debian-binary" not in names:
                raise SystemExit("自检失败：外层缺 debian-binary")
            inner = outer.extractfile("./data.tar.gz").read()
        else:
            members = dict(parse_ar_simple(blob))
            inner = members["data.tar.gz"]
        tf = tarfile.open(fileobj=io.BytesIO(inner), mode="r:gz")
        for m in tf.getmembers():
            if not m.isfile():
                continue
            head = tf.extractfile(m).read(4096).decode("utf-8", "replace")
            for ph in ("__PORT__", "__LAN_IF__", "__CA_CRT__", "__CA_KEY__",
                       "__USER__", "__PASS__", "__CONF__"):
                if ph in head:
                    raise SystemExit("自检失败：%s 的 %s 里残留 %s" % (label, m.name, ph))
        print("  自检通过：%s（%d 个条目，无占位符残留）" % (label, len(tf.getmembers())))

    _selfcheck(ipk_main, name_main)

    print("构建完成  版本 %s  架构 %s  格式 %s\n" % (pkgver, ARCH, IPK_FORMAT))
    for p in (os.path.join(out, name_main), os.path.join(out, name_app),
              os.path.join(feed, "Packages"), os.path.join(feed, "Packages.gz")):
        print("  %-52s %7d B" % (os.path.relpath(p, ROOT), os.path.getsize(p)))
    print("\n  安装：opkg install %s" % name_main)
    print("  加源：echo 'src/gz mitmctl %s' >> /etc/opkg/customfeeds.conf && opkg update" % FEED_URL)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mitm-ctl Windows 启动器
────────────────────────────────────────────────────────────
打包成单文件 exe：
    python tools/build-exe.py            # 产物 dist/mitm-ctl.exe
直接跑：
    python windows/mitmctl.py

在 Windows 上没有 nftables，所以是「显式代理」模式：
  · 启动后自动把系统代理设为 127.0.0.1:8080（退出时还原）
  · 首次运行生成 CA 证书，可用 --install-ca 装进 Windows 受信任根
  · 浏览器打开 http://127.0.0.1:7690/ 看解密内容

注意：Windows 版**只能抓本机通过系统代理走的流量**。
要抓整个局域网（其他手机/电脑），需要把本机配成网关 + 用 WinDivert 之类做重定向，
那是另一个量级的工作，本启动器不做（见 README 的可行性说明）。
"""
import argparse
import os
import subprocess
import sys
import threading
import time

BANNER = r"""
  ┌──────────────────────────────────────────────────────────┐
  │  mitm-ctl · Windows 显式代理模式                          │
  └──────────────────────────────────────────────────────────┘
"""


# ============================================================ 环境
def app_dirs():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    root = os.path.join(base, "mitm-ctl")
    conf = os.path.join(root, "conf")
    ca = os.path.join(root, "ca")
    tmp = os.path.join(root, "tmp")
    for d in (conf, ca, tmp, os.path.join(tmp, "certs"), os.path.join(tmp, "blobs")):
        os.makedirs(d, exist_ok=True)
    return root, conf, ca, tmp


def prepare_env(port, user, pwd, iface="eth0", proxy_port=8080, proxy_tls_port=8443):
    root, conf, ca, tmp = app_dirs()
    # 必须把代理端口也传下去，否则 mitm_proxy 会用内置默认值，
    # 自定义 --proxy-port 时客户端就连不上了
    os.environ["MITM_HTTP_PORT"] = str(proxy_port)
    os.environ["MITM_HTTPS_PORT"] = str(proxy_tls_port)
    os.environ["MITM_CONF"] = conf
    os.environ["MITM_CA_CERT"] = os.path.join(ca, "mitm-ca.crt")
    os.environ["MITM_CA_KEY"] = os.path.join(ca, "mitm-ca.key")
    os.environ["MITM_CERT_DIR"] = os.path.join(tmp, "certs")
    os.environ["MITM_BLOB_DIR"] = os.path.join(tmp, "blobs")
    # 注意两个变量名不一样：pktcap_server 用 PKTCAP_BODYLOG，
    # mitm_proxy 用 MITM_OUT（默认 /tmp/mitm-body.jsonl，Windows 上那个目录不存在，
    # 不设的话记录会静默丢失）
    body_log = os.path.join(tmp, "body.jsonl")
    os.environ["PKTCAP_BODYLOG"] = body_log
    os.environ["MITM_OUT"] = body_log
    os.environ["PKTCAP_PORT"] = str(port)
    os.environ["PKTCAP_USER"] = user
    os.environ["PKTCAP_PASS"] = pwd
    os.environ["PKTCAP_IFACE"] = iface
    return root, conf, ca, tmp


def ensure_ca(ca_dir):
    """没有 CA 就用 cryptography 现生成一个（Windows 上不一定有 openssl）。"""
    crt = os.path.join(ca_dir, "mitm-ca.crt")
    key = os.path.join(ca_dir, "mitm-ca.key")
    if os.path.isfile(crt) and os.path.isfile(key):
        print("  沿用已有 CA：%s" % crt)
        return crt, key
    try:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        sys.exit("  ✗ 缺少 cryptography，请先 pip install cryptography")
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mitm-ctl CA"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mitm-ctl")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(k, hashes.SHA256()))
    with open(key, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()))
    with open(crt, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("  已生成 CA 证书：%s" % crt)
    return crt, key


# ============================================================ 系统代理
PROXY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def get_sys_proxy():
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_KEY) as k:
        def g(name):
            try:
                return winreg.QueryValueEx(k, name)[0]
            except OSError:
                return None
        return {"enable": g("ProxyEnable"), "server": g("ProxyServer"),
                "override": g("ProxyOverride")}


def set_sys_proxy(server=None, restore=None):
    """server='127.0.0.1:8080' 开启；restore=dict 还原。"""
    import ctypes
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if server:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server)
            winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ,
                              "localhost;127.*;10.*;172.16.*;192.168.*;<local>")
        elif restore is not None:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD,
                              int(restore.get("enable") or 0))
            if restore.get("server") is not None:
                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, restore["server"])
            if restore.get("override") is not None:
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, restore["override"])
    # 通知已运行的程序设置变了
    try:
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, 37, 0, 0)      # REFRESH
    except Exception:
        pass


def install_ca(crt):
    r = subprocess.run(["certutil", "-user", "-addstore", "Root", crt],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print("  ✓ CA 已导入 Windows 受信任根证书（当前用户）")
        return True
    print("  ✗ 导入失败：%s" % (r.stderr or r.stdout).strip()[:200])
    print("    也可以手动：双击 %s → 安装证书 → 受信任的根证书颁发机构" % crt)
    return False


# ============================================================ 角色进程
def run_role(role):
    """子进程入口：只跑其中一个服务。"""
    if role == "proxy":
        import mitm_proxy
        mitm_proxy.main()
    elif role == "web":
        import pktcap_server
        pktcap_server.main()
    else:
        sys.exit("未知角色: %s" % role)


# ============================================================ 主流程
def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--role", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--port", type=int, default=7690, help="网页端口（默认 7690）")
    ap.add_argument("--proxy-port", type=int, default=8080, help="HTTP 代理端口（默认 8080）")
    ap.add_argument("--proxy-tls-port", type=int, default=8443, help="HTTPS 代理端口（默认 8443）")
    ap.add_argument("--user", default="root")
    ap.add_argument("--passwd", default="root", dest="pwd")
    ap.add_argument("--no-proxy", action="store_true", help="不修改系统代理设置")
    ap.add_argument("--install-ca", action="store_true", help="把 CA 装进 Windows 受信任根")
    ap.add_argument("--no-browser", action="store_true", help="不自动开浏览器")
    args = ap.parse_args()

    if args.role:
        run_role(args.role)
        return

    print(BANNER)
    root, conf, ca, tmp = prepare_env(args.port, args.user, args.pwd,
                                     proxy_port=args.proxy_port,
                                     proxy_tls_port=args.proxy_tls_port)
    crt, _ = ensure_ca(ca)
    print("  数据目录：%s" % root)

    if args.install_ca:
        install_ca(crt)

    base = os.environ.get("PKTCAP_BASE") or ("http://127.0.0.1:%d" % args.port)
    exe = sys.executable
    env = dict(os.environ)
    children = []
    for role, label in (("proxy", "解密代理"), ("web", "网页控制台")):
        p = subprocess.Popen([exe, "--role", role], env=env)
        children.append((label, p))
        print("  已启动 %s（pid %d）" % (label, p.pid))
        time.sleep(0.6)

    proxy_server = "127.0.0.1:%d" % args.proxy_port
    saved = None
    if not args.no_proxy:
        try:
            saved = get_sys_proxy()
            set_sys_proxy(server=proxy_server)
            print("  ✓ 系统代理已设为 %s（退出时自动还原）" % proxy_server)
        except Exception as e:
            print("  ! 设置系统代理失败（可手动设置）：%s" % e)
    else:
        print("  未修改系统代理，请自行把 HTTP/HTTPS 代理设为 %s" % proxy_server)

    print()
    print("  ┌─ 现在可以做的事 ─────────────────────────────────────")
    print("  │ 看解密内容   %s/body" % base)
    print("  │ 控制台       %s/panel     （账号 %s / %s）" % (base, args.user, args.pwd))
    print("  │ 装证书       %s/cert" % base)
    print("  │ 代理地址     %s（HTTP 与 HTTPS 都填这个；也支持 %s）"
          % (proxy_server, args.proxy_tls_port))
    print("  └──────────────────────────────────────────────────────")
    print()
    print("  提示：微信/支付宝/银行等做了证书固定的 App 解不开，这是 TLS 本身的限制。")
    print("  按 Ctrl+C 停止（会自动还原系统代理）。")
    print()

    if not args.no_browser:
        try:
            import webbrowser
            threading.Timer(1.2, lambda: webbrowser.open(base + "/body")).start()
        except Exception:
            pass

    try:
        while True:
            time.sleep(1)
            for label, p in children:
                if p.poll() is not None:
                    print("  ! %s 已退出（返回码 %s），全部停止" % (label, p.returncode))
                    raise KeyboardInterrupt
    except KeyboardInterrupt:
        print("\n  正在停止…")
    finally:
        for label, p in children:
            try:
                p.terminate()
            except Exception:
                pass
        for label, p in children:
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        if saved is not None:
            try:
                set_sys_proxy(restore=saved)
                print("  ✓ 系统代理已还原")
            except Exception as e:
                print("  ! 还原系统代理失败：%s" % e)
        print("  已退出")


if __name__ == "__main__":
    main()

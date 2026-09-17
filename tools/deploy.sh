#!/bin/sh
# ============================================================================
#  开发时把改动部署到设备（OpenWrt / Debian 通用）
#
#  为什么需要它：在 Windows 上写代码时，编辑器/工具很容易写入 CRLF 换行，
#  而 CRLF 的 shell 脚本拷到 busybox 上会直接报 "not found" / 语法错误。
#  本脚本会先把文本文件统一成 LF，再上传、重启、校验。
#
#  用法：
#    sh tools/deploy.sh root@10.0.0.1
#    HOST=root@10.0.0.1 sh tools/deploy.sh
#    sh tools/deploy.sh root@10.0.0.1 --no-restart
# ============================================================================
set -e

HOST="${1:-$HOST}"
[ -n "$HOST" ] || { echo "用法: sh tools/deploy.sh <user@host>"; exit 1; }
case "$2" in --no-restart) RESTART=0 ;; *) RESTART=1 ;; esac

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

say() { printf "==> %s\n" "$1"; }

# ---------------------------------------------------------------- 1) 统一 LF
say "统一换行为 LF"
if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PYEOF'
import os
BIN = (".pcap", ".pcapng", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".gz", ".zip", ".pdf")
fixed = []
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
    for fn in files:
        p = os.path.join(root, fn)
        if p.lower().endswith(BIN):
            continue
        try:
            b = open(p, "rb").read()
        except OSError:
            continue
        n = b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if n != b:
            open(p, "wb").write(n)
            fixed.append(p)
print("   修正 %d 个文件" % len(fixed) if fixed else "   全部已是 LF")
PYEOF
else
    # 无 python 时用 tr 兜底
    n=0
    for f in $(find . -type f ! -path "./.git/*" ! -name "*.pcap" ! -name "*.png" ! -name "*.gz"); do
        if [ "$(tr -d '\r' < "$f" | wc -c)" != "$(wc -c < "$f")" ]; then
            tr -d '\r' < "$f" > "$f.tmp" && mv "$f.tmp" "$f"
            n=$((n+1))
        fi
    done
    echo "   修正 $n 个文件"
fi

# ---------------------------------------------------------------- 2) 语法自检
say "本地语法自检"
if command -v python3 >/dev/null 2>&1; then
    python3 -m py_compile pktcap_server.py mitm_proxy.py && echo "   ✓ Python 编译通过"
fi
for f in install.sh uninstall.sh bin/mitm-ctl bin/mitm-nft.sh initd/mitm initd/pktcap; do
    sh -n "$f" && echo "   ✓ $f"
done

# ---------------------------------------------------------------- 3) 上传
say "上传到 $HOST"
for f in pktcap_server.py body.html panel.html index.html CHEATSHEET.md; do
    ssh -o StrictHostKeyChecking=no "$HOST" "cat > /usr/share/pktcap/$f" < "$f"
done
ssh -o StrictHostKeyChecking=no "$HOST" 'cat > /usr/share/mitm/mitm_proxy.py' < mitm_proxy.py
ssh -o StrictHostKeyChecking=no "$HOST" 'cat > /usr/bin/mitm-ctl' < bin/mitm-ctl
ssh -o StrictHostKeyChecking=no "$HOST" 'cat > /usr/libexec/mitm-nft.sh' < bin/mitm-nft.sh
ssh -o StrictHostKeyChecking=no "$HOST" 'chmod 755 /usr/bin/mitm-ctl /usr/libexec/mitm-nft.sh'
echo "   已上传 8 个文件"

# ---------------------------------------------------------------- 4) md5 校验
say "md5 校验（cat > 上传偶尔会静默失败，必须比对）"
# 本地 hash：优先 md5sum；Windows Git Bash 没有，就用 python 兜底
lmd5() {
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$1" | cut -c1-12
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import hashlib,sys;print(hashlib.md5(open(sys.argv[1],'rb').read()).hexdigest()[:12])" "$1"
    else
        echo "?"
    fi
}
rmd5() {
    ssh -o StrictHostKeyChecking=no "$HOST" "md5sum '$1' 2>/dev/null | cut -c1-12"
}
FAIL=0
for f in pktcap_server.py body.html panel.html index.html CHEATSHEET.md; do
    L=$(lmd5 "$f"); R=$(rmd5 "/usr/share/pktcap/$f")
    if [ -n "$L" ] && [ "$L" != "?" ] && [ "$L" = "$R" ]; then
        printf "   ✓ %-22s %s\n" "$f" "$L"
    else
        printf "   ✗ %-22s 本地 %s / 远端 %s\n" "$f" "$L" "$R"; FAIL=1
    fi
done
L=$(lmd5 mitm_proxy.py); R=$(rmd5 "/usr/share/mitm/mitm_proxy.py")
if [ -n "$L" ] && [ "$L" != "?" ] && [ "$L" = "$R" ]; then
    printf "   ✓ %-22s %s\n" "mitm_proxy.py" "$L"
else
    printf "   ✗ %-22s 本地 %s / 远端 %s\n" "mitm_proxy.py" "$L" "$R"; FAIL=1
fi
if [ "$FAIL" = "1" ]; then
    echo "   ⚠ 有不一致的文件 —— 远端可能仍是旧版，请重试上传"
fi

# ---------------------------------------------------------------- 5) 重启
if [ "$RESTART" = "1" ]; then
    say "重启服务"
    ssh -o StrictHostKeyChecking=no "$HOST" '
        if [ -f /etc/init.d/pktcap ]; then
            /etc/init.d/pktcap restart >/dev/null 2>&1 || /etc/init.d/pktcap start >/dev/null 2>&1
            /etc/init.d/mitm restart   >/dev/null 2>&1 || /etc/init.d/mitm start   >/dev/null 2>&1
        elif command -v systemctl >/dev/null 2>&1; then
            systemctl restart pktcap mitm >/dev/null 2>&1 || true
        fi
        sleep 4
        echo "   页面: $(for u in / /body /panel /packets /doc /cert; do printf "%s=%s " $u $(curl -s -o /dev/null -w "%{http_code}" -u root:root http://127.0.0.1:7690$u); done)"
        echo "   进程: mitm=$(ps w 2>/dev/null | grep -v grep | grep -c mitm_proxy) pktcap=$(ps w 2>/dev/null | grep -v grep | grep -c pktcap_server)"
    '
fi

say "完成"

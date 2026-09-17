#!/bin/sh
# mitm-ctl 卸载
#   sh uninstall.sh            停止服务并删除程序（保留配置与 CA）
#   sh uninstall.sh --purge    连配置和 CA 证书一起删
set -e

PURGE=0
if [ "$1" = "--purge" ]; then
    PURGE=1
fi

if [ -t 1 ]; then
    C_OK=$(printf '\033[32m'); C_INFO=$(printf '\033[36m'); C_RST=$(printf '\033[0m')
else
    C_OK=""; C_INFO=""; C_RST=""
fi
say() { printf "%s==>%s %s\n" "$C_INFO" "$C_RST" "$1"; }
ok()  { printf "    %s✓%s %s\n" "$C_OK" "$C_RST" "$1"; }

[ "$(id -u)" = "0" ] || { echo "请用 root 运行"; exit 1; }

HAS_SYSTEMD=0
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && HAS_SYSTEMD=1

say "停止服务并清除重定向规则"
[ -x /usr/libexec/mitm-nft.sh ] && /usr/libexec/mitm-nft.sh clear >/dev/null 2>&1 || true
nft delete table inet mitm 2>/dev/null || true

if [ "$HAS_SYSTEMD" = "1" ]; then
    systemctl stop mitm   >/dev/null 2>&1 || true
    systemctl stop pktcap >/dev/null 2>&1 || true
    systemctl disable mitm   >/dev/null 2>&1 || true
    systemctl disable pktcap >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/mitm.service /etc/systemd/system/pktcap.service
    systemctl daemon-reload >/dev/null 2>&1 || true
else
    [ -x /etc/init.d/mitm ]   && /etc/init.d/mitm disable   >/dev/null 2>&1 || true
    [ -x /etc/init.d/pktcap ] && /etc/init.d/pktcap disable >/dev/null 2>&1 || true
    [ -x /etc/init.d/mitm ]   && /etc/init.d/mitm stop      >/dev/null 2>&1 || true
    [ -x /etc/init.d/pktcap ] && /etc/init.d/pktcap stop    >/dev/null 2>&1 || true
fi
# 兜底杀残留
for d in /proc/[0-9]*; do
    c=$(cat "$d/comm" 2>/dev/null) || continue
    [ "$c" = "python3" ] || continue
    cl=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
    case "$cl" in
        *mitm_proxy*|*pktcap_server*) kill "$(basename "$d")" 2>/dev/null || true ;;
    esac
done
ok "已停止"

say "删除程序文件"
rm -f /etc/init.d/mitm /etc/init.d/pktcap
rm -f /usr/bin/mitm-ctl /usr/libexec/mitm-nft.sh
rm -rf /usr/share/pktcap /usr/share/mitm
rm -f /www/luci-static/resources/view/capture/decrypt.js
rm -f /www/luci-static/resources/view/capture/table.js
rmdir /www/luci-static/resources/view/capture 2>/dev/null || true
rm -f /usr/share/luci/menu.d/luci-app-capture.json
rm -f /tmp/luci-indexcache* 2>/dev/null || true
rm -rf /tmp/mitm-certs /tmp/mitm-body.jsonl /tmp/mitm-blobs 2>/dev/null || true
ok "程序已删除"

if [ "$PURGE" = "1" ]; then
    say "清除配置与 CA 证书（--purge）"
    rm -rf /etc/mitm /etc/squid/ssl/mitm-ca.crt /etc/squid/ssl/mitm-ca.key
    rm -f /www/cert.html /www/mitm-ca.crt /www/mitm-ca.pem
    rm -f /etc/sysctl.d/99-mitm-ctl.conf
    ok "已清除"
else
    echo "    配置与 CA 已保留：/etc/mitm、/etc/squid/ssl/mitm-ca.*"
    echo "    彻底清除：sh uninstall.sh --purge"
fi

echo
printf "%s==> 卸载完成%s\n" "$C_OK" "$C_RST"

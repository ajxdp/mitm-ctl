#!/bin/sh
# mitm-ctl 卸载（保留 /etc/mitm 配置，除非加 --purge）
set -e

say() { printf "\033[36m==>\033[0m %s\n" "$1"; }
[ "$(id -u)" = "0" ] || { echo "请用 root 运行"; exit 1; }

say "停止服务并清除 nft 规则"
/etc/init.d/mitm stop    >/dev/null 2>&1 || true
/etc/init.d/pktcap stop  >/dev/null 2>&1 || true
/etc/init.d/mitm disable   >/dev/null 2>&1 || true
/etc/init.d/pktcap disable >/dev/null 2>&1 || true
/usr/libexec/mitm-nft.sh clear >/dev/null 2>&1 || nft delete table inet mitm 2>/dev/null || true

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

if [ "$1" = "--purge" ]; then
    say "清除配置与 CA 证书（--purge）"
    rm -rf /etc/mitm /etc/squid/ssl/mitm-ca.crt /etc/squid/ssl/mitm-ca.key
    rm -f /www/cert.html /www/mitm-ca.crt /www/mitm-ca.pem
else
    echo "    （配置与 CA 已保留：/etc/mitm、/etc/squid/ssl/mitm-ca.*）"
    echo "     彻底清除请执行： sh uninstall.sh --purge"
fi

say "卸载完成"

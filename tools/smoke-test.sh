#!/bin/sh
# 通用安装后回归验证
# 日志文件可能还没生成（或装在别的路径），统一用这个读行数，避免冒出一句
# "No such file or directory" 干扰判断。
lines() {
	if [ -f "$1" ]; then
		wc -l < "$1" 2>/dev/null | tr -d ' '
	else
		echo 0
	fi
}

echo "== 1) 页面（含不鉴权的证书页）=="
for u in / /body /panel /packets /doc; do
    printf "  %-12s " "$u"
    curl -s -u root:root -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:7690$u"
done
printf "  %-12s " "/cert"
curl -s -o /dev/null -w "%{http_code}  (不鉴权)\n" http://127.0.0.1:7690/cert
printf "  %-12s " "/mitm-ca.crt"
curl -s -o /dev/null -w "%{http_code}  %{content_type}  %{size_download}B\n" http://127.0.0.1:7690/mitm-ca.crt

echo
echo "== 2) ca_url 指向内置证书页（应带端口）=="
curl -s -u root:root http://127.0.0.1:7690/api/mitm | python3 -c "
import sys, json
s = json.load(sys.stdin)['status']
print('  ca_url =', s['ca_url'])
print('  enabled=%s running=%s mode=%s log=%s' % (s['enabled'], s['running'], s['mode'], s['log_enabled']))
print('  放行: %d 域名 + %d IP' % (s['bypass_count'], s.get('bypass_ip_count', 0)))
"

echo
echo "== 3) mitm-ctl 三态（新版脚本）=="
mitm-ctl on >/dev/null 2>&1; sleep 2
echo "  on   -> nft=$(nft list table inet mitm 2>/dev/null | grep -c redirect)"
mitm-ctl off >/dev/null 2>&1; sleep 1
echo "  off  -> nft=$(nft list table inet mitm 2>/dev/null | grep -c redirect)  (代理应仍在)"
mitm-ctl stop >/dev/null 2>&1; sleep 2
echo "  stop -> nft=$(nft list table inet mitm 2>/dev/null | grep -c redirect)  python3=$(for d in /proc/[0-9]*; do cat $d/comm 2>/dev/null; done | grep -c '^python3$')"
mitm-ctl on >/dev/null 2>&1; sleep 3
echo "  on   -> 已恢复  nft=$(nft list table inet mitm 2>/dev/null | grep -c redirect)"

echo
echo "== 4) status 子命令 =="
mitm-ctl status 2>&1 | sed 's/^/  /'

echo
echo "== 5) 解密链路（走代理抓一条）=="
curl -s -u root:root -X POST -H 'Content-Type: application/json' \
     -d '{"action":"enable"}' http://127.0.0.1:7690/api/log >/dev/null
B=$(lines /tmp/mitm-body.jsonl)
curl -s -x http://127.0.0.1:8080 -k -o /dev/null --max-time 25 'https://example.com/' 2>/dev/null
sleep 1
A=$(lines /tmp/mitm-body.jsonl)
echo "  记录 $B -> $A  $([ "$A" -gt "$B" ] && echo '✓' || echo '✗')"

echo
echo "== 6) 主动发包 / 抓包开关 =="
curl -s -u root:root -X POST -H 'Content-Type: application/json' \
     -d '{"method":"GET","url":"https://example.com/","headers":{},"body":""}' \
     http://127.0.0.1:7690/api/send | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('  /api/send ok=%s status=%s len=%s' % (d.get('ok'), d.get('status'), d.get('len')))
"
curl -s -u root:root -X POST -H 'Content-Type: application/json' \
     -d '{"action":"start"}' http://127.0.0.1:7690/api/capture >/dev/null
sleep 3
echo "  抓包 start -> tcpdump=$(for d in /proc/[0-9]*; do cat $d/comm 2>/dev/null; done | grep -c '^tcpdump$')"
curl -s -u root:root -X POST -H 'Content-Type: application/json' \
     -d '{"action":"stop"}' http://127.0.0.1:7690/api/capture >/dev/null
sleep 2
echo "  抓包 stop  -> tcpdump=$(for d in /proc/[0-9]*; do cat $d/comm 2>/dev/null; done | grep -c '^tcpdump$')"

echo
echo "== 7) 资源 =="
free | awk "/Mem:/{printf \"  内存 已用 %.0fMB / 可用 %.0fMB\n\", \$3/1024, \$7/1024}"

#!/bin/sh
# 容器入口：生成 CA（首次）→ 写默认配置 → 同时拉起解密代理与网页控制台
set -e

CONF="${MITM_CONF:-/data/conf}"
CA_CRT="${MITM_CA_CERT:-/data/ca/mitm-ca.crt}"
CA_KEY="${MITM_CA_KEY:-/data/ca/mitm-ca.key}"

log() { printf "==> %s\n" "$1"; }

mkdir -p "$CONF" "$(dirname "$CA_CRT")" \
         "${MITM_CERT_DIR:-/tmp/mitm-certs}" "${MITM_BLOB_DIR:-/tmp/mitm-blobs}" /tmp

# ---------------------------------------------------------------- CA 证书
if [ ! -f "$CA_CRT" ] || [ ! -f "$CA_KEY" ]; then
    log "生成 CA 证书 -> $CA_CRT"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CA_KEY" -out "$CA_CRT" \
        -subj "/CN=mitm-ctl CA/O=mitm-ctl" >/dev/null 2>&1
    chmod 600 "$CA_KEY"
    chmod 644 "$CA_CRT"
else
    log "沿用已有 CA：$CA_CRT"
fi

# ---------------------------------------------------------------- 默认配置（幂等）
[ -f "$CONF/mode" ]        || echo "all"     > "$CONF/mode"
[ -f "$CONF/domains.txt" ] || :              > "$CONF/domains.txt"
[ -f "$CONF/logcfg" ]      || printf "2097152\n400\n" > "$CONF/logcfg"
[ -f "$CONF/autoclose" ]   || printf "0\n5\n" > "$CONF/autoclose"   # 容器由编排托管，不自动停
[ -f "$CONF/log-enable" ]  || echo "1"       > "$CONF/log-enable"
[ -f "$CONF/ifaces" ]      || :              > "$CONF/ifaces"
if [ ! -s "$CONF/auto-bypass.txt" ]; then
    cp /opt/mitm-ctl/auto-bypass.default.txt "$CONF/auto-bypass.txt" 2>/dev/null \
        || : > "$CONF/auto-bypass.txt"
fi
mkdir -p /etc/squid
[ -f /etc/squid/mitm-targets ] || echo "10.0.0.0/24" > /etc/squid/mitm-targets

# ---------------------------------------------------------------- 启动
log "解密代理        0.0.0.0:8080 (HTTP) / 0.0.0.0:8443 (HTTPS)"
python3 /opt/mitm-ctl/mitm_proxy.py &
PROXY_PID=$!

log "网页控制台      0.0.0.0:${PKTCAP_PORT:-7690}"
python3 /opt/mitm-ctl/pktcap_server.py &
WEB_PID=$!

log "控制台   http://<宿主机IP>:${PKTCAP_PORT:-7690}/panel"
log "装证书   http://<宿主机IP>:${PKTCAP_PORT:-7690}/cert"
log "代理地址 <宿主机IP>:8080 （HTTP 与 HTTPS 都填这个）"

trap 'log "收到停止信号，正在退出"; kill $PROXY_PID $WEB_PID 2>/dev/null; wait; exit 0' TERM INT

# 任一进程退出就整体退出，交给 compose 的 restart 策略
while kill -0 "$PROXY_PID" 2>/dev/null && kill -0 "$WEB_PID" 2>/dev/null; do
    sleep 2
done
log "有服务已退出，容器结束"
kill $PROXY_PID $WEB_PID 2>/dev/null || true
wait

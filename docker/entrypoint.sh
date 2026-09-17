#!/bin/sh
# 容器内启动两个服务；首次运行自动生成 CA 证书
set -e

CA_CRT="${MITM_CA_CERT:-/data/ca/mitm-ca.crt}"
CA_KEY="${MITM_CA_KEY:-/data/ca/mitm-ca.key}"

mkdir -p "$(dirname "$CA_CRT")" "${MITM_CERT_DIR:-/data/certs}" \
         "${MITM_CONF:-/data/conf}" "${MITM_BLOB_DIR:-/data/blobs}" /tmp

if [ ! -f "$CA_CRT" ] || [ ! -f "$CA_KEY" ]; then
    echo "==> 生成 CA 证书"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CA_KEY" -out "$CA_CRT" \
        -subj "/CN=mitm-ctl CA/O=mitm-ctl" >/dev/null 2>&1
    chmod 600 "$CA_KEY"
fi

# 默认配置
[ -f "${MITM_CONF}/mode" ]        || echo "all"      > "${MITM_CONF}/mode"
[ -f "${MITM_CONF}/domains.txt" ] || : > "${MITM_CONF}/domains.txt"
[ -f "${MITM_CONF}/logcfg" ]      || printf "2097152\n400\n" > "${MITM_CONF}/logcfg"
[ -f "${MITM_CONF}/autoclose" ]   || printf "1\n5\n" > "${MITM_CONF}/autoclose"
[ -f "${MITM_CONF}/log-enable" ]  || echo "1"        > "${MITM_CONF}/log-enable"
[ -s "${MITM_CONF}/auto-bypass.txt" ] || cp /opt/mitm-ctl/auto-bypass.default.txt "${MITM_CONF}/auto-bypass.txt" 2>/dev/null || : > "${MITM_CONF}/auto-bypass.txt"

echo "==> 解密代理 :8080 / :8443"
python3 /opt/mitm-ctl/mitm_proxy.py &
PROXY_PID=$!

echo "==> 网页控制台 :${PKTCAP_PORT:-7690}"
python3 /opt/mitm-ctl/pktcap_server.py &
WEB_PID=$!

# 任一进程退出就整体退出，交给容器编排重启
trap 'kill $PROXY_PID $WEB_PID 2>/dev/null; exit 0' TERM INT
while kill -0 $PROXY_PID 2>/dev/null && kill -0 $WEB_PID 2>/dev/null; do
    sleep 2
done
echo "==> 有服务退出，容器结束"
wait

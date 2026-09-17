# ============================================================================
#  mitm-ctl —— 容器镜像（显式代理模式）
#
#  构建：  docker build -t mitm-ctl .
#  运行：  docker compose up -d --build
#  说明：  容器内没有 nftables，无法做透明重定向 —— 属于「显式代理」模式，
#         把客户端/浏览器的 HTTP+HTTPS 代理指向 宿主机IP:8080 即可解密。
# ============================================================================
FROM python:3.13-slim

LABEL org.opencontainers.image.title="mitm-ctl" \
      org.opencontainers.image.description="轻量 HTTPS 解密抓包代理 + 网页控制台" \
      org.opencontainers.image.source="https://github.com/ajxdp/mitm-ctl" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PKTCAP_PORT=7690 \
    PKTCAP_USER=root \
    PKTCAP_PASS=root \
    PKTCAP_IFACE=eth0 \
    MITM_CONF=/data/conf \
    MITM_CA_CERT=/data/ca/mitm-ca.crt \
    MITM_CA_KEY=/data/ca/mitm-ca.key \
    MITM_CERT_DIR=/tmp/mitm-certs \
    MITM_BLOB_DIR=/tmp/mitm-blobs \
    PKTCAP_BODYLOG=/tmp/mitm-body.jsonl

# openssl 用于生成/查看 CA；tzdata 让日志时间是本地时区；tcpdump 供「流量抓包」页使用
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssl curl tzdata tcpdump ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# cryptography 用于动态签发叶子证书（mitm_proxy.py 必需）。
# 网络受限时可换源：docker compose build --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir --index-url "$PIP_INDEX_URL" cryptography

WORKDIR /opt/mitm-ctl

COPY pktcap_server.py mitm_proxy.py body.html panel.html index.html CHEATSHEET.md ./
COPY bin/auto-bypass.default.txt ./auto-bypass.default.txt
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh && mkdir -p /data

EXPOSE 8080 8443 7690
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fs -u "$PKTCAP_USER:$PKTCAP_PASS" "http://127.0.0.1:$PKTCAP_PORT/body" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

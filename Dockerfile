# mitm-ctl —— 容器版（显式代理模式）
# 透明重定向依赖 nftables，容器内不可用；请把客户端代理指向 <主机IP>:8080
FROM python:3.13-slim

LABEL org.opencontainers.image.title="mitm-ctl" \
      org.opencontainers.image.description="Lightweight HTTPS MITM capture with web console" \
      org.opencontainers.image.licenses="MIT"

RUN pip install --no-cache-dir cryptography==43.0.3

WORKDIR /opt/mitm-ctl
COPY pktcap_server.py body.html panel.html index.html CHEATSHEET.md ./
COPY mitm_proxy.py ./
COPY bin/auto-bypass.default.txt ./
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV MITM_CA_CERT=/data/ca/mitm-ca.crt \
    MITM_CA_KEY=/data/ca/mitm-ca.key \
    MITM_CERT_DIR=/data/certs \
    MITM_CONF=/data/conf \
    MITM_BLOB_DIR=/data/blobs \
    PKTCAP_BODYLOG=/data/mitm-body.jsonl \
    PKTCAP_PORT=7690 \
    PKTCAP_USER=root \
    PKTCAP_PASS=root

VOLUME ["/data"]
EXPOSE 8080 8443 7690

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python3 -c "import socket;socket.create_connection(('127.0.0.1',7690),3).close()" || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

#!/bin/sh
# 应用/清除 MITM 流量重定向（支持按来源网卡过滤）
#   apply   下发规则：把 LAN 的 80/443 重定向到本机代理端口，并丢弃 QUIC(UDP/443)
#   clear   删除整张表，恢复直连
#
# 依赖：nftables。非透明模式（显式代理）不需要本脚本。
TARGETS=/etc/squid/mitm-targets
IFACES=/etc/mitm/ifaces
SELFIP_FILE=/etc/mitm/self-ip

# 「访问本机自己」的流量不重定向，否则路由器/主机的 Web 管理页会被代理拦下
SELF=""
[ -f "$SELFIP_FILE" ] && SELF=$(head -1 "$SELFIP_FILE" 2>/dev/null)
[ -n "$SELF" ] || SELF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
[ -n "$SELF" ] || SELF="10.0.0.1"

apply() {
	nft add table inet mitm 2>/dev/null
	nft add chain inet mitm prerouting '{ type nat hook prerouting priority dstnat ; }' 2>/dev/null
	nft add chain inet mitm forward '{ type filter hook forward priority filter ; }' 2>/dev/null
	nft flush chain inet mitm prerouting
	nft flush chain inet mitm forward
	nft add set inet mitm src_addrs '{ type ipv4_addr; flags interval; }' 2>/dev/null
	nft flush set inet mitm src_addrs 2>/dev/null
	nft add set inet mitm src_ifaces '{ type ifname; }' 2>/dev/null
	nft flush set inet mitm src_ifaces 2>/dev/null

	[ -f "$TARGETS" ] || echo 10.0.0.0/24 > "$TARGETS"
	while read -r t; do
		case "$t" in ""|\#*) continue;; esac
		nft add element inet mitm src_addrs { $t } 2>/dev/null
	done < "$TARGETS"

	ni=0
	if [ -f "$IFACES" ]; then
		while read -r f; do
			case "$f" in ""|\#*) continue;; esac
			nft add element inet mitm src_ifaces { "$f" } 2>/dev/null
			ni=$((ni+1))
		done < "$IFACES"
	fi
	IIF=""
	[ "$ni" -gt 0 ] && IIF="iifname @src_ifaces"

	# 局域网设备 -> 本机代理（访问本机自身的不拦，避免管理页被代理）
	nft add rule inet mitm prerouting ip saddr @src_addrs $IIF ip daddr != "$SELF" tcp dport 80  counter redirect to :8080
	nft add rule inet mitm prerouting ip saddr @src_addrs $IIF ip daddr != "$SELF" tcp dport 443 counter redirect to :8443
	# 丢弃 QUIC(UDP 443)，逼客户端回落到 TCP，否则 HTTPS/3 会绕过代理
	nft add rule inet mitm forward ip saddr @src_addrs $IIF udp dport 443 counter drop
}

clear() { nft delete table inet mitm 2>/dev/null; }

case "$1" in
	apply) apply ;;
	clear) clear ;;
	*) echo "usage: mitm-nft.sh apply|clear" ;;
esac

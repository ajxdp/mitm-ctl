#!/bin/sh
# 应用/清除 MITM 流量重定向（支持按来源网卡过滤）
TARGETS=/etc/squid/mitm-targets
IFACES=/etc/mitm/ifaces

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

	nft add rule inet mitm prerouting ip saddr @src_addrs $IIF ip daddr != 10.0.0.1 tcp dport 80 counter redirect to :8080
	nft add rule inet mitm prerouting ip saddr @src_addrs $IIF ip daddr != 10.0.0.1 tcp dport 443 counter redirect to :8443
	nft add rule inet mitm forward ip saddr @src_addrs $IIF udp dport 443 counter drop
}
clear() { nft delete table inet mitm 2>/dev/null; }
case "$1" in apply) apply ;; clear) clear ;; *) echo "usage: mitm-nft.sh apply|clear" ;; esac

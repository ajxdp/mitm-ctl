#!/bin/sh
# 确定性重启 pktcap / mitm —— 设备侧脚本（tools/deploy.sh 会推送到 /tmp 执行）。
#
# 为什么不能简单用 `restart`：
#   procd 的记账可能与实际情况脱节（进程曾被直接 kill、上一轮重启时旧进程还没退出），
#   于是新实例 bind 失败 → 日志出现 `OSError: [Errno 98] Address in use` → procd
#   陷入 crash loop，而网页/流量却仍由那个**脱管的旧进程**在服务（系统看起来"正常"，
#   其实服务已经不受管理，改配置、重启都不会生效）。
#
# 所以这里按「停干净 → 等端口释放 → 起 → 校验单实例」的顺序做，并在最后核对数量。
PKTCAP_PORT="${PKTCAP_PORT:-7690}"

procs() {          # $1 = 脚本名，输出匹配到的 pid
	for d in /proc/[0-9]*; do
		c=$(cat "$d/comm" 2>/dev/null) || continue
		[ "$c" = "python3" ] || continue
		tr '\0' ' ' < "$d/cmdline" 2>/dev/null | grep -q "$1" && basename "$d"
	done
}
cnt() { procs "$1" | wc -l | tr -d ' '; }
all_down() {
	[ "$(cnt pktcap_server.py)" = "0" ] && [ "$(cnt mitm_proxy.py)" = "0" ]
}

wait_down() {      # $1 = 最多等几秒
	i=0
	while [ $i -lt "$1" ]; do
		all_down && return 0
		sleep 1
		i=$((i + 1))
	done
	return 1
}

stop_all() {
	if [ -f /etc/init.d/pktcap ]; then
		/etc/init.d/pktcap stop >/dev/null 2>&1
		/etc/init.d/mitm   stop >/dev/null 2>&1
	elif command -v systemctl >/dev/null 2>&1; then
		systemctl stop pktcap mitm >/dev/null 2>&1
	fi
	wait_down 10 && return 0
	# 服务框架没收拾干净 → 残留实例会一直占着端口，必须清掉
	for p in $(procs pktcap_server.py) $(procs mitm_proxy.py); do kill "$p" 2>/dev/null; done
	wait_down 6 && return 0
	for p in $(procs pktcap_server.py) $(procs mitm_proxy.py); do kill -9 "$p" 2>/dev/null; done
	wait_down 4
	return 0
}

start_all() {
	if [ -f /etc/init.d/mitm ]; then
		/etc/init.d/mitm   start >/dev/null 2>&1
		/etc/init.d/pktcap start >/dev/null 2>&1
	elif command -v systemctl >/dev/null 2>&1; then
		systemctl start mitm pktcap >/dev/null 2>&1
	fi
	# 等 7690 真的能连上（最多 15s）
	i=0
	while [ $i -lt 15 ]; do
		curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$PKTCAP_PORT/panel" && return 0
		sleep 1
		i=$((i + 1))
	done
	return 1
}

stop_all
start_all

echo "   进程: pktcap=$(cnt pktcap_server.py) mitm=$(cnt mitm_proxy.py)"
echo "   自启: $(ls /etc/rc.d/ 2>/dev/null | grep -E '^S[0-9]+(mitm|pktcap)$' | tr '\n' ' ')"
echo "   页面: $(for u in / /body /panel /packets /doc /cert; do printf "%s=%s " "$u" "$(curl -s -o /dev/null -w '%{http_code}' -u root:root --max-time 5 http://127.0.0.1:$PKTCAP_PORT$u)"; done)"

# 数量不对要说出来，别让"看起来正常"骗过去
P=$(cnt pktcap_server.py); M=$(cnt mitm_proxy.py)
if [ "$P" != "1" ] || [ "$M" != "1" ]; then
	echo "   ⚠ 期望各 1 个进程，实际 pktcap=$P mitm=$M（可能有残留实例）"
fi

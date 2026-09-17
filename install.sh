#!/bin/sh
# mitm-ctl 一键安装（OpenWrt / Kwrt）
# 用法：  sh install.sh            # 默认端口 7690，账号 root/root
#        PKTCAP_PORT=7790 sh install.sh
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
PKTCAP_PORT="${PKTCAP_PORT:-7690}"
PKTCAP_USER="${PKTCAP_USER:-root}"
PKTCAP_PASS="${PKTCAP_PASS:-root}"
IFACE="${PKTCAP_IFACE:-br-lan}"

CA_DIR=/etc/squid/ssl
CA_CRT=$CA_DIR/mitm-ca.crt
CA_KEY=$CA_DIR/mitm-ca.key

say() { printf "\033[36m==>\033[0m %s\n" "$1"; }
warn() { printf "\033[33m[!]\033[0m %s\n" "$1"; }
die() { printf "\033[31m[x]\033[0m %s\n" "$1" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "请用 root 运行（ssh root@路由器）"
[ -f /etc/openwrt_release ] || warn "没检测到 OpenWrt 发行版标识，继续尝试安装…"

# ---------------------------------------------------------------- 1) 依赖
say "检查依赖"
MISSING=""
for b in python3 openssl nft tcpdump; do
    command -v "$b" >/dev/null 2>&1 || MISSING="$MISSING $b"
done
python3 -c "import ssl, cryptography" 2>/dev/null || MISSING="$MISSING python3-cryptography"

if [ -n "$MISSING" ]; then
    warn "缺失:$MISSING —— 尝试 opkg 安装"
    opkg update >/dev/null 2>&1 || true
    for pkg in python3-light python3-openssl python3-cryptography openssl-util nftables tcpdump; do
        opkg list-installed 2>/dev/null | grep -q "^$pkg " && continue
        opkg install "$pkg" >/dev/null 2>&1 && printf "    装好 %s\n" "$pkg" || printf "    跳过 %s（可能已内置或名称不同）\n" "$pkg"
    done
fi

command -v python3 >/dev/null 2>&1 || die "python3 装不上，请手动 opkg install python3-light"
python3 -c "import ssl" 2>/dev/null || die "python3 缺 ssl 模块，请装 python3-openssl"
python3 -c "import cryptography" 2>/dev/null || die "python3 缺 cryptography 模块，请装 python3-cryptography"
say "依赖 OK（$(python3 -V 2>&1)）"

# ---------------------------------------------------------------- 2) 程序文件
say "安装程序文件"
mkdir -p /usr/share/pktcap /usr/share/mitm /etc/mitm "$CA_DIR"
cp "$HERE/pktcap_server.py" "$HERE/body.html" "$HERE/panel.html" \
   "$HERE/index.html" "$HERE/CHEATSHEET.md" /usr/share/pktcap/
cp "$HERE/mitm_proxy.py" /usr/share/mitm/
cp "$HERE/bin/mitm-ctl" /usr/bin/mitm-ctl
cp "$HERE/bin/mitm-nft.sh" /usr/libexec/mitm-nft.sh
cp "$HERE/initd/mitm" "$HERE/initd/pktcap" /etc/init.d/
[ -d "$HERE/legacy" ] && mkdir -p /usr/share/pktcap/legacy && cp "$HERE/legacy/"* /usr/share/pktcap/legacy/ 2>/dev/null || true
chmod +x /usr/bin/mitm-ctl /usr/libexec/mitm-nft.sh /etc/init.d/mitm /etc/init.d/pktcap
rm -rf /usr/share/pktcap/__pycache__ /usr/share/mitm/__pycache__ 2>/dev/null || true

# 端口/账号写进 procd 服务
sed -i "s|PKTCAP_IFACE=[^ ]*|PKTCAP_IFACE=$IFACE|; \
        s|PKTCAP_PORT=[^ ]*|PKTCAP_PORT=$PKTCAP_PORT|; \
        s|PKTCAP_USER=[^ ]*|PKTCAP_USER=$PKTCAP_USER|; \
        s|PKTCAP_PASS=[^ ]*|PKTCAP_PASS=$PKTCAP_PASS|" /etc/init.d/pktcap

# ---------------------------------------------------------------- 3) CA
if [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ]; then
    say "CA 证书已存在，沿用（指纹 $(openssl x509 -in $CA_CRT -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | cut -c1-16)…）"
else
    say "生成 CA 证书（10 年有效）"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CA_KEY" -out "$CA_CRT" \
        -subj "/CN=Kwrt MITM CA/O=Kwrt Home" >/dev/null 2>&1 \
        || die "CA 生成失败"
    chmod 600 "$CA_KEY"
fi

# 证书下载页（80 端口，由 uhttpd/nginx 托管 /www）
if [ -d /www ]; then
    cp "$CA_CRT" /www/mitm-ca.crt
    cp "$CA_CRT" /www/mitm-ca.pem
    if [ ! -f /www/cert.html ]; then
        cat > /www/cert.html <<'HTMLEOF'
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>安装 CA 证书</title>
<style>body{font:16px/1.7 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;padding:24px;background:#f5f6f8;color:#1f2430}
h1{font-size:18px;margin:0 0 4px}p.sub{color:#6b7280;font-size:13px;margin:0 0 18px}
a.btn{display:block;padding:16px;margin:12px 0;background:#2f6fed;color:#fff;text-decoration:none;border-radius:10px;text-align:center;font-weight:600}
a.alt{background:#fff;color:#1f2430;border:1px solid #d7dbe3}
.note{color:#6b7280;font-size:13px;margin-top:18px;background:#fff;border:1px solid #eef0f4;border-radius:10px;padding:14px}
.note b{color:#1f2430}</style></head><body>
<h1>安装解密 CA 证书</h1><p class="sub">装好后浏览器访问的 HTTPS 即可看到明文</p>
<a class="btn" href="/mitm-ca.crt">① 下载证书 .crt（推荐）</a>
<a class="btn alt" href="/mitm-ca.pem">② 备用格式 .pem</a>
<div class="note">下载后：<b>设置 → 安全/密码与安全 → 加密与凭据 → 安装证书 → CA 证书</b>，选择刚下载的文件。<br>
CA 名称：<b>Kwrt MITM CA</b><br>若提示"无效"，改用另一个格式再试。</div>
</body></html>
HTMLEOF
    fi
fi

# ---------------------------------------------------------------- 4) 配置
say "初始化配置"
[ -f /etc/mitm/mode ]          || echo "list"       > /etc/mitm/mode
[ -f /etc/mitm/domains.txt ]   || printf "# 每行一个域名；填 example.com 会匹配它所有子域\n# 下面这些是证书固定、被解密就会崩的 App —— 放行它们\npinduoduo.com\nyangkeduo.com\n" > /etc/mitm/domains.txt
[ -f /etc/mitm/ifaces ]        || echo "$IFACE"    > /etc/mitm/ifaces
[ -f /etc/mitm/logcfg ]        || printf "2097152\n400\n" > /etc/mitm/logcfg
[ -f /etc/mitm/autoclose ]     || printf "1\n5\n"   > /etc/mitm/autoclose
[ -f /etc/mitm/log-enable ]    || echo "1"          > /etc/mitm/log-enable
[ -f /etc/squid/mitm-targets ] || echo "10.0.0.0/24" > /etc/squid/mitm-targets
if [ ! -s /etc/mitm/auto-bypass.txt ]; then
    cp "$HERE/bin/auto-bypass.default.txt" /etc/mitm/auto-bypass.txt 2>/dev/null \
        || : > /etc/mitm/auto-bypass.txt
fi

# ---------------------------------------------------------------- 5) 启动
say "设置开机自启并启动"
/etc/init.d/mitm enable >/dev/null 2>&1 || true
/etc/init.d/pktcap enable >/dev/null 2>&1 || true
/etc/init.d/mitm start >/dev/null 2>&1 || true
/etc/init.d/pktcap start >/dev/null 2>&1 || true
sleep 3

# LuCI 菜单（服务 → 流量抓包）
if [ -d /usr/share/luci/menu.d ]; then
    cat > /usr/share/luci/menu.d/luci-app-capture.json <<'JSONEOF'
{
	"admin/services/capture": {
		"title": "流量抓包",
		"action": { "type": "firstchild" }
	},
	"admin/services/capture/decrypt": {
		"title": "解密内容（请求/返回）",
		"order": 1,
		"action": { "type": "view", "path": "capture/decrypt" }
	},
	"admin/services/capture/table": {
		"title": "抓包表格",
		"order": 2,
		"action": { "type": "view", "path": "capture/table" }
	}
}
JSONEOF
    mkdir -p /www/luci-static/resources/view/capture
    for pair in "decrypt:body:解密内容" "table:packets:抓包表格"; do
        name=$(echo "$pair" | cut -d: -f1)
        route=$(echo "$pair" | cut -d: -f2)
        cat > "/www/luci-static/resources/view/capture/$name.js" <<EOF
'use strict';
'require view';
return view.extend({
	render: function() {
		return E('iframe', {
			src: 'http://' + window.location.hostname + ':$PKTCAP_PORT/$route',
			style: 'width: 100%; min-height: 700px; border: none; border-radius: 3px; resize: vertical;'
		});
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
EOF
    done
    rm -f /tmp/luci-indexcache* 2>/dev/null || true
    rm -rf /tmp/luci-modulecache 2>/dev/null || true
fi

# ---------------------------------------------------------------- 6) 自检
say "自检"
/etc/init.d/mitm status >/dev/null 2>&1 && echo "    mitm    运行中" || warn "mitm 未运行"
/etc/init.d/pktcap status >/dev/null 2>&1 && echo "    pktcap  运行中" || warn "pktcap 未运行"
HOST=$(uci get network.lan.ipaddr 2>/dev/null | cut -d/ -f1)
[ -n "$HOST" ] || HOST=$(ip -4 addr show br-lan 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
[ -n "$HOST" ] || HOST=192.168.1.1
echo ""
echo "  控制台   http://$HOST:$PKTCAP_PORT/panel   （默认 $PKTCAP_USER / $PKTCAP_PASS）"
echo "  解密内容 http://$HOST:$PKTCAP_PORT/body"
echo "  装证书   http://$HOST/cert.html"
echo "  速查手册 http://$HOST:$PKTCAP_PORT/doc"
echo ""
say "完成。抓包默认关闭，用 mitm-ctl on 或控制台开启。"

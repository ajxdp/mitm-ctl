#!/bin/sh
# ============================================================================
#  mitm-ctl 一键安装脚本
#  支持：OpenWrt / Kwrt（procd）· Debian / Ubuntu（systemd）· 其他 Linux
#
#  用法：
#    sh install.sh                         # 自动识别系统
#    sh install.sh --mode=proxy            # 显式代理模式（不装 nft 规则）
#    sh install.sh --mode=gateway          # 透明模式（本机当网关/路由器）
#    PKTCAP_PORT=8080 PKTCAP_PASS=xxx sh install.sh
#    sh install.sh --check                 # 只做依赖自检，不安装
#    sh install.sh --help
#
#  从 GitHub 直接装（无需先 clone）：
#    curl -fsSL https://raw.githubusercontent.com/ajxdp/mitm-ctl/main/install.sh | sh
# ============================================================================
set -e

REPO="ajxdp/mitm-ctl"
BRANCH="${MITM_BRANCH:-main}"

APPDIR="/usr/share/pktcap"
MITMDIR="/usr/share/mitm"
CONFDIR="/etc/mitm"
NFT_SH="/usr/libexec/mitm-nft.sh"
CTL_BIN="/usr/bin/mitm-ctl"

MODE=""                    # gateway | proxy   （留空=自动）
PORT="${PKTCAP_PORT:-7690}"
USER_="${PKTCAP_USER:-root}"
PASS_="${PKTCAP_PASS:-root}"
WANT_UNINSTALL=0
CHECK_ONLY=0
SKIP_DEPS=0

# ---------------------------------------------------------------- 输出helpers
if [ -t 1 ]; then
    C_OK=$(printf '\033[32m'); C_INFO=$(printf '\033[36m'); C_WARN=$(printf '\033[33m')
    C_ERR=$(printf '\033[31m'); C_DIM=$(printf '\033[2m'); C_RST=$(printf '\033[0m')
else
    C_OK=""; C_INFO=""; C_WARN=""; C_ERR=""; C_DIM=""; C_RST=""
fi
say()  { printf "%s==>%s %s\n" "$C_INFO" "$C_RST" "$1"; }
ok()   { printf "    %s✓%s %s\n" "$C_OK" "$C_RST" "$1"; }
warn() { printf "    %s!%s %s\n" "$C_WARN" "$C_RST" "$1"; }
die()  { printf "%s==> 错误：%s%s\n" "$C_ERR" "$1" "$C_RST" >&2; exit 1; }
dim()  { printf "      %s%s%s\n" "$C_DIM" "$1" "$C_RST"; }

# ---------------------------------------------------------------- 参数
for a in "$@"; do
    case "$a" in
        --mode=gateway|--gateway) MODE="gateway" ;;
        --mode=proxy|--proxy)     MODE="proxy" ;;
        --mode=*)                 die "未知模式：$a（可选 gateway / proxy）" ;;
        --uninstall)              WANT_UNINSTALL=1 ;;
        --check)                  CHECK_ONLY=1 ;;
        --no-deps)                SKIP_DEPS=1 ;;
        --port=*)                 PORT="${a#--port=}" ;;
        --pass=*)                 PASS_="${a#--pass=}" ;;
        -h|--help)
            cat <<'USAGE'
mitm-ctl 一键安装（OpenWrt / Kwrt · Debian / Ubuntu · 其他 Linux）

  sh install.sh                  自动识别系统并安装
  sh install.sh --mode=proxy     显式代理模式（客户端手动填代理，零副作用）
  sh install.sh --mode=gateway   透明模式（本机当网关，自动重定向 80/443）
  sh install.sh --check          只做依赖自检，不安装
  sh install.sh --no-deps        跳过自动装依赖
  sh install.sh --uninstall      卸载

  可用环境变量覆盖：
    PKTCAP_PORT=7690     控制台端口
    PKTCAP_USER=root     控制台账号
    PKTCAP_PASS=root     控制台密码
    MITM_BRANCH=main     在线安装时使用的分支

  在线安装（无需 clone）：
    curl -fsSL https://raw.githubusercontent.com/ajxdp/mitm-ctl/main/install.sh | sh
    # 下载不通时走代理： https_proxy=http://127.0.0.1:8080 sh install.sh

  可用环境变量覆盖下载源：
    MITM_BRANCH=main            分支
    MITM_RAW=<raw 镜像地址>     逐文件下载用的基地址
    MITM_TARBALL=<整包地址>     整包下载用的地址

  安装后：
    控制台 http://<本机IP>:7690/panel     装证书 http://<本机IP>:7690/cert
USAGE
            exit 0 ;;
        *) die "未知参数：$a（用 --help 查看用法）" ;;
    esac
done

[ "$(id -u)" = "0" ] || die "请用 root 运行（sudo sh install.sh）"

# 任何 set -e 中断都给出明确提示（否则只会静默退出，很难查）
trap 'rc=$?; if [ "$rc" != "0" ]; then printf "\n%s==> 安装中断（退出码 %s）%s\n" "$C_ERR" "$rc" "$C_RST" >&2; printf "    可加 --check 只做自检，或用 sh -x install.sh 跟踪执行\n" >&2; fi' EXIT

if [ "$WANT_UNINSTALL" = "1" ]; then
    HERE=$(dirname "$0")
    if [ -f "$HERE/uninstall.sh" ]; then
        exec sh "$HERE/uninstall.sh"
    fi
    die "找不到 uninstall.sh，请从仓库目录运行"
fi

# ---------------------------------------------------------------- 下载封装
# 优先 curl，其次 wget；失败返回非零（供回退逻辑判断）
fetch() {                       # fetch <url> <outfile>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 15 --max-time 180 "$1" -o "$2" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 30 -O "$2" "$1" 2>/dev/null
    else
        return 1
    fi
}


# ============================================================================
# 1. 识别系统
# ============================================================================
OS="generic"
if [ -f /etc/openwrt_release ]; then
    OS="openwrt"
elif [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/redhat-release ] || [ -f /etc/fedora-release ]; then
    OS="rhel"
fi

HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=1
fi
HAS_PROCD=0
[ -d /etc/init.d ] && [ -f /etc/rc.common ] && HAS_PROCD=1

say "检查环境"
case "$OS" in
    openwrt) ok "系统：OpenWrt / Kwrt" ;;
    debian)  ok "系统：Debian / Ubuntu" ;;
    rhel)    ok "系统：RHEL 系" ;;
    *)       warn "未识别的发行版，按通用 Linux 处理" ;;
esac
if [ "$HAS_PROCD" = "1" ]; then ok "init：procd"; fi
if [ "$HAS_SYSTEMD" = "1" ]; then ok "init：systemd"; fi
if [ "$HAS_PROCD" = "0" ] && [ "$HAS_SYSTEMD" = "0" ]; then
    warn "既没有 procd 也没有 systemd，将只装程序不装自启服务"
    dim "可手动启动：python3 $MITMDIR/mitm_proxy.py  /  python3 $APPDIR/pktcap_server.py"
fi

# 自动决定模式：路由器默认透明，其它系统默认显式代理（最省事、零副作用）
if [ -z "$MODE" ]; then
    if [ "$OS" = "openwrt" ]; then MODE="gateway"; else MODE="proxy"; fi
fi

# ============================================================================
# 2. 依赖
# ============================================================================
PKGS_MISSING=""

check_deps() {
    say "检查依赖"
    command -v python3 >/dev/null 2>&1 || die "缺少 python3，请先安装"
    PYV=$(python3 -V 2>&1)
    ok "$PYV"

    python3 -c "import ssl" 2>/dev/null && ok "python3 ssl 模块" \
        || { warn "python3 缺少 ssl 模块"; PKGS_MISSING="$PKGS_MISSING ssl"; }
    python3 -c "import cryptography" 2>/dev/null && ok "python3 cryptography 模块" \
        || { warn "python3 缺少 cryptography（动态签发证书必需）"; PKGS_MISSING="$PKGS_MISSING cryptography"; }
    command -v openssl >/dev/null 2>&1 && ok "openssl $(openssl version 2>/dev/null | awk '{print $2}')" \
        || { warn "缺少 openssl（生成 CA 必需）"; PKGS_MISSING="$PKGS_MISSING openssl"; }
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
        || dim "缺少 curl/wget（仅「在线安装」需要）"

    if [ "$MODE" = "gateway" ]; then
        command -v nft >/dev/null 2>&1 || { warn "缺少 nft（透明模式必需）"; PKGS_MISSING="$PKGS_MISSING nft"; }
    fi
    # tcpdump 只影响「流量抓包表格」这一页，缺了其它功能照常
    command -v tcpdump >/dev/null 2>&1 || dim "未装 tcpdump —— 流量抓包表格页不可用（其它功能正常）"
    if [ -n "$PKGS_MISSING" ]; then
        dim "待安装：$PKGS_MISSING"
    fi
    return 0
}

install_deps() {
    [ -z "$PKGS_MISSING" ] && return 0
    say "安装缺失依赖：$PKGS_MISSING"
    case "$OS" in
        openwrt)
            opkg update >/dev/null 2>&1 || true
            for p in $PKGS_MISSING; do
                case "$p" in
                    ssl)          opkg install python3-openssl >/dev/null 2>&1 || true ;;
                    cryptography) opkg install python3-cryptography >/dev/null 2>&1 || true ;;
                    openssl)      opkg install openssl-util >/dev/null 2>&1 || true ;;
                    nft)          opkg install nftables-json >/dev/null 2>&1 \
                                      || opkg install nftables >/dev/null 2>&1 || true ;;
                    tcpdump)      opkg install tcpdump >/dev/null 2>&1 || true ;;
                esac
            done
            ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq >/dev/null 2>&1 || true
                apt-get install -y -qq curl ca-certificates >/dev/null 2>&1 || true
                for p in $PKGS_MISSING; do
                    case "$p" in
                        openssl)      apt-get install -y -qq openssl >/dev/null 2>&1 || true ;;
                        nft)          apt-get install -y -qq nftables >/dev/null 2>&1 || true ;;
                        tcpdump)      apt-get install -y -qq tcpdump >/dev/null 2>&1 || true ;;
                        ssl|cryptography)
                            apt-get install -y -qq python3 >/dev/null 2>&1 || true
                            apt-get install -y -qq python3-cryptography >/dev/null 2>&1 \
                                || { warn "apt 装不上 python3-cryptography，改用 pip";
                                     pip3 install --quiet --break-system-packages cryptography 2>/dev/null \
                                         || pip3 install --quiet cryptography 2>/dev/null || true; } ;;
                    esac
                done
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y -q python3 python3-cryptography openssl curl >/dev/null 2>&1 || true
                [ "$MODE" = "gateway" ] && { dnf install -y -q nftables >/dev/null 2>&1 || true; }
            elif command -v yum >/dev/null 2>&1; then
                yum install -y -q python3 python3-cryptography openssl curl >/dev/null 2>&1 || true
                [ "$MODE" = "gateway" ] && { yum install -y -q nftables >/dev/null 2>&1 || true; }
            else
                warn "没有可用包管理器，请手动安装：$PKGS_MISSING"
            fi
            ;;
    esac
    # 复检（只校验硬性要求，装了才算过）
    python3 -c "import ssl" 2>/dev/null || die "python3 ssl 模块仍不可用"
    python3 -c "import cryptography" 2>/dev/null || die "python3 cryptography 模块仍不可用（动态签发证书必需）"
    command -v openssl >/dev/null 2>&1 || die "openssl 仍不可用"
    ok "依赖就绪"
}

check_deps
if [ "$CHECK_ONLY" = "1" ]; then
    [ -n "$PKGS_MISSING" ] && { echo; warn "缺失：$PKGS_MISSING"; exit 1; }
    echo; ok "自检通过，可以安装"; exit 0
fi
if [ "$SKIP_DEPS" != "1" ]; then
    install_deps
fi

# ============================================================================
# 3. 准备源码（本地目录 或 从 GitHub 下载）
# ============================================================================
SRC=""
case "$0" in
    sh|-sh|dash|ash|*/sh|*bash) SELF_DIR="" ;;
    *) SELF_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || SELF_DIR="" ;;
esac
if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/pktcap_server.py" ]; then
    SRC="$SELF_DIR"
fi

TMPDL=""
if [ -z "$SRC" ]; then
    say "未在本地找到源码，从 GitHub 取（$REPO@$BRANCH）"
    TMPDL=$(mktemp -d 2>/dev/null || echo "/tmp/mitm-ctl-dl.$$")
    mkdir -p "$TMPDL"

    # ---- 方式一：整包 tarball（一次请求，最快）
    TAR_URL="${MITM_TARBALL:-https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz}"
    if fetch "$TAR_URL" "$TMPDL/src.tgz" && tar xzf "$TMPDL/src.tgz" -C "$TMPDL" 2>/dev/null; then
        if [ -f "$TMPDL/mitm-ctl-$BRANCH/pktcap_server.py" ]; then
            SRC="$TMPDL/mitm-ctl-$BRANCH"
            ok "已下载整包"
        fi
    fi

    # ---- 方式二：逐文件从 raw 取
    # 实测有些环境（如配了透明代理的路由器）直连 codeload 会 TLS 中断，
    # 而 raw.githubusercontent.com 通常正常，所以这里兜底。
    if [ -z "$SRC" ]; then
        dim "整包下载失败，改为逐文件下载（raw 主机通常更通）"
        RAW="${MITM_RAW:-https://raw.githubusercontent.com/$REPO/$BRANCH}"
        mkdir -p "$TMPDL/raw"
        MISS=0
        for rel in pktcap_server.py mitm_proxy.py body.html panel.html index.html \
                   CHEATSHEET.md bin/mitm-ctl bin/mitm-nft.sh bin/auto-bypass.default.txt \
                   initd/mitm initd/pktcap systemd/mitm.service systemd/pktcap.service; do
            mkdir -p "$TMPDL/raw/$(dirname "$rel")"
            if fetch "$RAW/$rel" "$TMPDL/raw/$rel"; then
                printf "      · %s\n" "$rel"
            else
                warn "取不到 $rel"
                MISS=$((MISS + 1))
            fi
        done
        if [ -f "$TMPDL/raw/pktcap_server.py" ] && [ -f "$TMPDL/raw/mitm_proxy.py" ]; then
            SRC="$TMPDL/raw"
        fi
        [ "$MISS" -gt 0 ] && dim "有 $MISS 个文件没取到（非必需的不影响安装）"
    fi

    if [ -z "$SRC" ]; then
        echo
        warn "从 GitHub 取源码失败。试试这几种办法："
        dim "1) 本机下好仓库再拷过去（最稳）："
        dim "   scp -r mitm-ctl root@<设备IP>:/tmp/ && ssh root@<设备IP> 'sh /tmp/mitm-ctl/install.sh'"
        dim "2) 走代理下载："
        dim "   https_proxy=http://<代理IP>:8080 sh install.sh"
        dim "3) 换镜像或分支："
        dim "   MITM_RAW=https://<你的镜像>/mitm-ctl/$BRANCH sh install.sh"
        dim "   MITM_BRANCH=main sh install.sh"
        die "无法获取源码"
    fi
    ok "已下载到 $SRC"
fi
[ -f "$SRC/pktcap_server.py" ] || die "源码目录缺少 pktcap_server.py：$SRC"

# ============================================================================
# 4. 安装文件（先拷到默认路径，再按需覆盖成自定义端口/账号）
# ============================================================================
say "安装程序文件"
mkdir -p "$APPDIR" "$MITMDIR" "$CONFDIR" /usr/libexec

for f in pktcap_server.py body.html panel.html index.html CHEATSHEET.md; do
    [ -f "$SRC/$f" ] || die "源码缺少 $f"
    cp "$SRC/$f" "$APPDIR/$f"
done
cp "$SRC/mitm_proxy.py" "$MITMDIR/mitm_proxy.py"
if [ -d "$SRC/legacy" ]; then
    mkdir -p "$APPDIR/legacy"
    cp "$SRC/legacy"/* "$APPDIR/legacy/" 2>/dev/null || true
fi
chmod 755 "$MITMDIR/mitm_proxy.py" "$APPDIR/pktcap_server.py"
ok "$APPDIR（网页 + 服务端）"
ok "$MITMDIR（解密代理）"

# 工具脚本
if [ -f "$SRC/bin/mitm-ctl" ]; then
    cp "$SRC/bin/mitm-ctl" "$CTL_BIN"; chmod 755 "$CTL_BIN"
    ok "$CTL_BIN"
fi
if [ -f "$SRC/bin/mitm-nft.sh" ]; then
    cp "$SRC/bin/mitm-nft.sh" "$NFT_SH"; chmod 755 "$NFT_SH"
    ok "$NFT_SH"
fi

# ============================================================================
# 5. CA 证书（幂等：已存在就沿用）
# ============================================================================
say "准备 CA 证书"
CA_CRT=""
CA_KEY=""
# 兼容老安装（squid 目录）+ 新安装（/etc/mitm/ca）
for cand in "/etc/squid/ssl/mitm-ca" "$CONFDIR/ca/mitm-ca"; do
    if [ -f "$cand.crt" ] && [ -f "$cand.key" ]; then
        CA_CRT="$cand.crt"; CA_KEY="$cand.key"; break
    fi
done
if [ -z "$CA_CRT" ]; then
    mkdir -p "$CONFDIR/ca"
    CA_CRT="$CONFDIR/ca/mitm-ca.crt"
    CA_KEY="$CONFDIR/ca/mitm-ca.key"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CA_KEY" -out "$CA_CRT" \
        -subj "/CN=mitm-ctl CA/O=mitm-ctl" >/dev/null 2>&1 \
        || die "生成 CA 证书失败（openssl 不可用？）"
    chmod 600 "$CA_KEY"; chmod 644 "$CA_CRT"
    ok "已生成新 CA：$CA_CRT"
else
    FP=$(openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | cut -c1-24)
    ok "沿用已有 CA（$CA_CRT）"
    dim "指纹 $FP…"
fi

# ============================================================================
# 6. 配置默认值（全部幂等，不覆盖用户已改的设置）
# ============================================================================
say "初始化配置"
mkdir -p "$CONFDIR"
[ -f "$CONFDIR/mode" ]            || echo "all"          > "$CONFDIR/mode"
[ -f "$CONFDIR/domains.txt" ]     || :                  > "$CONFDIR/domains.txt"
[ -f "$CONFDIR/logcfg" ]          || printf "2097152\n400\n" > "$CONFDIR/logcfg"
[ -f "$CONFDIR/autoclose" ]       || printf "1\n5\n"    > "$CONFDIR/autoclose"
[ -f "$CONFDIR/log-enable" ]      || echo "1"           > "$CONFDIR/log-enable"
if [ ! -s "$CONFDIR/auto-bypass.txt" ]; then
    if [ -f "$SRC/bin/auto-bypass.default.txt" ]; then
        cp "$SRC/bin/auto-bypass.default.txt" "$CONFDIR/auto-bypass.txt"
    else
        : > "$CONFDIR/auto-bypass.txt"
    fi
fi
[ -f "$CONFDIR/ifaces" ] || : > "$CONFDIR/ifaces"
mkdir -p /etc/squid
[ -f /etc/squid/mitm-targets ] || echo "10.0.0.0/24" > /etc/squid/mitm-targets
ok "配置目录 $CONFDIR（mode / domains / 日志上限 / 自动关闭 / 放行名单）"

# ============================================================================
# 7. 网络参数探测
# ============================================================================
LAN_IP=""
LAN_IF=""
LAN_NET=""
LAN_MSK=""

if [ "$OS" = "openwrt" ]; then
    LAN_IP=$(uci get network.lan.ipaddr 2>/dev/null | cut -d/ -f1) || LAN_IP=""
    # DSA（OpenWrt 21+）用 network.lan.device；老版本用 network.lan.ifname
    LAN_IF=$(uci get network.lan.ifname 2>/dev/null | awk '{print $1}') || LAN_IF=""
    if [ -z "$LAN_IF" ]; then
        LAN_IF=$(uci get network.lan.device 2>/dev/null) || LAN_IF=""
    fi
    LAN_MSK=$(uci get network.lan.netmask 2>/dev/null) || LAN_MSK=""
fi

# 用 LAN IP 反查它挂在哪个网卡上 —— 这一步最可靠
if [ -z "$LAN_IF" ] && [ -n "$LAN_IP" ]; then
    LAN_IF=$(ip -o -4 addr show 2>/dev/null \
             | awk -v ip="$LAN_IP" 'index($4, ip "/") == 1 {print $2; exit}') || LAN_IF=""
fi

DEF_IF=$(ip route show default 2>/dev/null \
         | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1) || DEF_IF=""
DEF_IP=$(ip route show default 2>/dev/null \
         | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1) || DEF_IP=""

# 非 OpenWrt：LAN = 除默认路由网卡外的第一个网卡
if [ -z "$LAN_IF" ]; then
    LAN_IF=$(ip -o -4 addr show 2>/dev/null \
             | awk -v d="$DEF_IF" '$2 != d && $2 != "lo" {print $2; exit}') || LAN_IF=""
fi
if [ -z "$LAN_IF" ]; then
    LAN_IF="$DEF_IF"
fi
if [ -z "$LAN_IF" ]; then
    LAN_IF="eth0"
fi

# 本机 LAN IP：优先取 LAN 网卡上的真实地址（绝不能用 WAN IP）
if [ -z "$LAN_IP" ]; then
    LAN_IP=$(ip -o -4 addr show "$LAN_IF" 2>/dev/null \
             | awk '{print $4}' | cut -d/ -f1 | head -1) || LAN_IP=""
fi
if [ -z "$LAN_IP" ]; then
    LAN_IP="$DEF_IP"
fi
if [ -z "$LAN_IP" ]; then
    LAN_IP="127.0.0.1"
fi

# 网段
case "$LAN_MSK" in
    255.255.255.0|24) LAN_NET="${LAN_IP%.*}.0/24" ;;
    255.255.0.0|16)   LAN_NET="${LAN_IP%.*.*}.0.0/16" ;;
    *)                LAN_NET="${LAN_IP%.*}.0/24" ;;
esac

if [ "$MODE" = "gateway" ]; then
    echo "$LAN_NET" > /etc/squid/mitm-targets
fi

# nft 规则要排除「访问本机自身」的流量，必须用 LAN IP；
# 写成 WAN IP 的话，局域网设备访问路由器管理页会被代理拦下
SELFIP="$LAN_IP"
echo "$SELFIP" > "$CONFDIR/self-ip"

# 透明模式标记（供 init 脚本判断要不要下发 nft 规则）
if [ "$MODE" = "gateway" ]; then
    echo "1" > "$CONFDIR/tproxy"
else
    rm -f "$CONFDIR/tproxy"
fi
ok "网卡 $LAN_IF · 网段 $LAN_NET · 本机 $SELFIP · 模式 $MODE"

# ============================================================================
# 8. 安装自启服务
# ============================================================================
render() {
    # render <模板> <目标>  —— 替换占位符
    sed -e "s|__CONF__|$CONFDIR|g" \
        -e "s|__CA_CRT__|$CA_CRT|g" \
        -e "s|__CA_KEY__|$CA_KEY|g" \
        -e "s|__LAN_IF__|$LAN_IF|g" \
        -e "s|__PORT__|$PORT|g" \
        -e "s|__USER__|$USER_|g" \
        -e "s|__PASS__|$PASS_|g" \
        "$1" > "$2"
    chmod 644 "$2"
}

if [ "$HAS_PROCD" = "1" ] && [ -f "$SRC/initd/mitm" ]; then
    say "安装 procd 服务 (/etc/init.d)"
    render "$SRC/initd/mitm"   /etc/init.d/mitm
    render "$SRC/initd/pktcap" /etc/init.d/pktcap
    chmod 755 /etc/init.d/mitm /etc/init.d/pktcap
    ok "/etc/init.d/mitm · /etc/init.d/pktcap"
elif [ "$HAS_SYSTEMD" = "1" ] && [ -f "$SRC/systemd/mitm.service" ]; then
    say "安装 systemd 服务 (/etc/systemd/system)"
    render "$SRC/systemd/mitm.service"   /etc/systemd/system/mitm.service
    render "$SRC/systemd/pktcap.service" /etc/systemd/system/pktcap.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    ok "/etc/systemd/system/{mitm,pktcap}.service"
else
    warn "跳过服务安装（没有 procd / systemd）"
fi

# 透明模式：开启转发 + 内核参数
if [ "$MODE" = "gateway" ]; then
    say "透明模式：开启 IP 转发"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    if [ -d /etc/sysctl.d ]; then
        printf "net.ipv4.ip_forward=1\n" > /etc/sysctl.d/99-mitm-ctl.conf
    elif [ -f /etc/sysctl.conf ]; then
        grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null \
            || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    ok "net.ipv4.ip_forward=1"
fi

# ============================================================================
# 9. 启动
# ============================================================================
say "启动服务"
if [ "$HAS_PROCD" = "1" ]; then
    /etc/init.d/mitm enable   >/dev/null 2>&1 || true
    /etc/init.d/pktcap enable >/dev/null 2>&1 || true
    /etc/init.d/mitm restart   >/dev/null 2>&1 || /etc/init.d/mitm start   >/dev/null 2>&1 || true
    /etc/init.d/pktcap restart >/dev/null 2>&1 || /etc/init.d/pktcap start >/dev/null 2>&1 || true
elif [ "$HAS_SYSTEMD" = "1" ]; then
    systemctl enable mitm pktcap  >/dev/null 2>&1 || true
    systemctl restart mitm        >/dev/null 2>&1 || systemctl start mitm   >/dev/null 2>&1 || true
    systemctl restart pktcap      >/dev/null 2>&1 || systemctl start pktcap >/dev/null 2>&1 || true
fi
i=0
while [ "$i" -lt 10 ]; do
    sleep 1
    i=$((i+1))
    if command -v curl >/dev/null 2>&1; then
        curl -s -o /dev/null -m 2 "http://127.0.0.1:$PORT/cert" 2>/dev/null && break
    elif netstat -ltn 2>/dev/null | grep -q ":$PORT "; then
        break
    else
        [ "$i" -ge 3 ] && break
    fi
done

# ============================================================================
# 10. 自检
# ============================================================================
say "自检"
if [ "$HAS_SYSTEMD" = "1" ]; then
    printf "    %-8s %s\n" "mitm"   "$(systemctl is-active mitm 2>/dev/null || echo inactive)"
    printf "    %-8s %s\n" "pktcap" "$(systemctl is-active pktcap 2>/dev/null || echo inactive)"
else
    printf "    %-8s %s\n" "mitm"   "$(ps w 2>/dev/null | grep -v grep | grep -q mitm_proxy && echo 运行中 || echo 未运行)"
    printf "    %-8s %s\n" "pktcap" "$(ps w 2>/dev/null | grep -v grep | grep -q pktcap_server && echo 运行中 || echo 未运行)"
fi

code() { curl -s -o /dev/null -w "%{http_code}" -u "$USER_:$PASS_" "http://127.0.0.1:$PORT$1" 2>/dev/null; }
C_WEB=$(code /body) || C_WEB="000"
C_CERT=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/cert" 2>/dev/null) || C_CERT="000"

# ============================================================================
# 11. 打印使用信息
# ============================================================================
HOST_IP=$(cat "$CONFDIR/self-ip" 2>/dev/null) || HOST_IP=""
[ -n "$HOST_IP" ] || HOST_IP="127.0.0.1"
BASE="http://$HOST_IP:$PORT"

echo
if [ "$C_WEB" = "200" ] && [ "$C_CERT" = "200" ]; then
    printf "%s==> 安装完成%s\n\n" "$C_OK" "$C_RST"
else
    printf "%s==> 安装完成，但网页自检未通过（HTTP $C_WEB）%s\n" "$C_WARN" "$C_RST"
    dim "排查：journalctl -u pktcap -n 50   或   logread | grep pktcap"
    echo
fi

printf "  %-16s %s\n" "控制台"     "$BASE/panel   （默认 $USER_ / $PASS_）"
printf "  %-16s %s\n" "解密内容"   "$BASE/body"
printf "  %-16s %s\n" "装证书"     "$BASE/cert    ← 设备先访问这里装 CA"
printf "  %-16s %s\n" "速查手册"   "$BASE/doc"
if [ "$MODE" = "proxy" ]; then
    printf "  %-16s %s\n" "代理地址" "${HOST_IP}:8080（HTTP/HTTPS 都填这个）"
fi
echo
if [ "$MODE" = "proxy" ]; then
    dim "显式代理模式：把浏览器/系统的 HTTP+HTTPS 代理填 $HOST_IP:8080 即可解密"
else
    dim "透明模式：已把 $LAN_NET 的 80/443 重定向到本机，设备无需设置代理"
fi
dim "开启/关闭解密：$CTL_BIN on | off | stop | status"
dim "抓包默认关闭，需要时在 /packets 页点「开始抓包」"
if [ "$PASS_" = "root" ]; then
    dim "提示：默认口令 root/root，建议安装时用 PKTCAP_PASS=xxx 覆盖"
fi

if [ -n "$TMPDL" ]; then
    rm -rf "$TMPDL" 2>/dev/null || true
fi
exit 0

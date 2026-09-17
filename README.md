# mitm-ctl

在 **OpenWrt / Kwrt 路由器**上做透明 HTTPS 解密抓包的轻量方案 —— 带网页控制台、实时流量表、可折叠的请求/响应查看器、类似 Apipost 的请求重放编辑器。

零第三方运行时依赖，不依赖 mitmproxy / squid ssl_bump，纯 Python 标准库 + 原生前端，**实测常驻内存 ~21MB**，也可跑在 Docker 里做显式代理。

```
┌──────────────┐  HTTP/HTTPS   ┌──────────────────────┐
│ 手机 / 电脑   │ ────────────▶ │  路由器 (OpenWrt)     │
│  (装 CA 证书) │               │                      │
└──────────────┘               │  nftables 重定向      │
                               │        ↓              │
                               │  mitm_proxy.py        │  ← 解密 + 记录
                               │   :8080 / :8443       │
                               │        ↓              │
                               │  pktcap_server.py     │  ← 网页 :7690
                               │   /body /panel /doc   │
                               └──────────────────────┘
```

---

## ✨ 特性

| 分类 | 能力 |
|---|---|
| **解密抓包** | 透明代理自动拦截网卡流量，支持 `全解` / `仅指定域名` / `全解+排除名单` 三种模式；按来源 IP、网卡过滤 |
| **请求查看** | 完整请求行 / 请求头 / 请求体 / 响应头 / 响应体，中文自动高亮 |
| **JSON 折叠树** | 左侧固定「行号 + 折叠三角」，淡色引导线按层级换色连到内容；**默认全部展开**，点整行任意位置即可折叠；可一键切「原始数据」纯文本 |
| **二进制预览** | 🖼 图片直接显示、📄 PDF 内嵌预览、Office 文档可下载；按内容哈希去重存储 |
| **主动发包** | 页面内「重放 / 编辑并发送」——类 Apipost 的简易请求编辑器，支持自定义方法/URL/头/体，可复制为 cURL |
| **流量抓包** | 独立的 tcpdump 实时表格（DNS / TLS / TCP / UDP 解析 + 域名反查），**按需启动** |
| **证书固定自愈** | 解密失败的域名自动放行（含父域名），避免拼多多/淘宝这类 App 被打挂 |
| **按需省电** | 解密、抓包、日志三个开关各自独立，默认关闭；无人查看自动停 |
| **自我保护** | 日志超限自动裁剪（`/tmp` 是内存盘）、图片缓存上限+LRU 回收、无框架无构建 |

---

## 📦 安装

### 方式一：一键脚本（推荐 · 自动识别系统）

**支持 OpenWrt / Kwrt、Debian / Ubuntu，以及其它 Linux。** 脚本会自动判断系统、装依赖、选 init 系统（procd / systemd）、挑合适的运行模式。

**在设备上直接跑**（无需先 clone）：

```sh
curl -fsSL https://raw.githubusercontent.com/ajxdp/mitm-ctl/main/install.sh | sh
```

**或者先下载仓库再装：**

```sh
git clone https://github.com/ajxdp/mitm-ctl
cd mitm-ctl
sh install.sh
```

**可选参数：**

```sh
sh install.sh --mode=proxy      # 显式代理模式（不装 nft 规则，零副作用）
sh install.sh --mode=gateway    # 透明模式（本机当网关，自动重定向 80/443）
sh install.sh --check           # 只做依赖自检，不安装
sh install.sh --uninstall       # 卸载

# 覆盖默认值
PKTCAP_PORT=8080 PKTCAP_PASS=你的密码 sh install.sh
```

**运行模式怎么选：**

| 系统 | 默认模式 | 说明 |
|---|---|---|
| OpenWrt / Kwrt | `gateway` | 它本来就是路由器，自动重定向设备流量，设备**无需任何设置** |
| Debian / Ubuntu / 其它 | `proxy` | 客户端手动填代理 `主机IP:8080`，不碰系统网络配置 |

脚本做的 10 件事：检查系统与 init → 探测依赖（含 python 模块级探测）→ 拷贝程序 → **生成/复用 CA 证书** → 写默认配置（幂等，不覆盖已有设置）→ 探测 LAN 网卡与网段 → 安装 procd/systemd 服务 → 透明模式下开 IP 转发 → 启动 → 自检并打印访问地址。

> 安装是**幂等**的：重复执行不会覆盖你已改的配置，也不会重新生成 CA（否则已装证书的设备要重装）。

### 方式二：ipk 包 / iStore（OpenWrt 专用，推荐）

到 [Releases](https://github.com/ajxdp/mitm-ctl/releases) 下载 `.ipk`，传到路由器：

```sh
# ① 程序本体（会自动拉依赖）
opkg install mitm-ctl_1.0.0-1_all.ipk

# ② iStore 应用信息（图标 + 描述，可选但推荐）
opkg install app-meta-mitm-ctl_1.0.0-1_all.ipk
```

装完即用：`/etc/init.d/mitm`、`/etc/init.d/pktcap` 已设为开机自启，LuCI 里会出现
**服务 → HTTPS 解密抓包**，网页在 `http://<路由器IP>:7690/`。

**也可以加成 opkg 源**（之后 `opkg upgrade` 能直接升级，iStore 的自定义源同理）：

```sh
echo 'src/gz mitmctl https://raw.githubusercontent.com/ajxdp/mitm-ctl/main/feed' \
    >> /etc/opkg/customfeeds.conf
opkg update
opkg install mitm-ctl app-meta-mitm-ctl
```

> 卸载：`opkg remove mitm-ctl`。**配置与 CA 证书会保留**（否则重装后所有设备都要重新装证书），
> 想彻底清理执行 `mitm-ctl purge`。

### 方式三：Docker（任意系统，无需 nftables）

```sh
git clone https://github.com/ajxdp/mitm-ctl
cd mitm-ctl

# 构建 + 启动（推荐）
docker compose up -d --build
docker compose logs -f            # 看日志
docker compose down               # 停止

# 或者不用 compose
docker build -t mitm-ctl .
docker run -d --name mitm-ctl \
  -p 8080:8080 -p 8443:8443 -p 7690:7690 \
  -v mitm-data:/data \
  -e PKTCAP_PASS=你的密码 \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  mitm-ctl
```

**容器里怎么用（3 步）：**

1. 访问 `http://宿主机IP:7690/cert` 下载 CA 证书，装到要抓包的设备上
2. 把该设备的 **HTTP 和 HTTPS 代理都设为 `宿主机IP:8080`**
3. 打开 `http://宿主机IP:7690/body` 看解密内容

> 容器内无法做 nftables 重定向，所以是**显式代理模式**。功能一个不少（解密、折叠 JSON、图片预览、重放编辑器），只是"只抓某台设备"改由你在客户端决定。
> CA 持久化在 `/data/ca/mitm-ca.crt`（命名卷），**别删卷**，否则设备要重新装证书。

### 方式四：Windows exe（显式代理，只用本机）

```sh
pip install pyinstaller cryptography
python tools/build-exe.py
# 产物：dist-exe/mitm-ctl.exe（约 13 MB）
```

直接双击，或：

```sh
mitm-ctl.exe                      # 自动设系统代理，退出时还原
mitm-ctl.exe --no-proxy           # 不碰系统代理，自己填 127.0.0.1:8080
mitm-ctl.exe --install-ca         # 顺便把 CA 装进「当前用户 · 受信任的根证书」
mitm-ctl.exe --port 7690 --proxy-port 8080
```

**能力边界（重要）**：

| 能做 | 做不到 |
|---|---|
| 抓**本机**浏览器/程序的流量（走系统代理） | 抓整个局域网的其它设备（Windows 上没有 nftables） |
| 解密、折叠 JSON、行号、图片/PDF 预览、重放 | 要抓全网设备得把本机做成网关 + WinDivert 重定向，属另一个量级的工程 |
| 证书/配置存在 `%LOCALAPPDATA%\mitm-ctl\` | 「抓包表格」页需要 tcpdump，Windows 上不可用（其余功能正常） |

> **curl 验证时的坑**：Windows 的 curl 用 schannel，会因「无法检查吊销状态」报
> `CERT_TRUST_ERROR_REVOCATION_STATUS_UNKNOWN`。要么先 `--install-ca` 把 CA 装进信任库，
> 要么测试时加 `--ssl-no-revoke`。浏览器不受影响（装完 CA 即可）。

### 方式五：手动

```sh
# ---------- OpenWrt ----------
opkg update
opkg install python3-light python3-openssl python3-cryptography openssl-util nftables tcpdump
mkdir -p /usr/share/pktcap /usr/share/mitm /etc/mitm /etc/squid/ssl
cp pktcap_server.py body.html panel.html index.html CHEATSHEET.md /usr/share/pktcap/
cp mitm_proxy.py /usr/share/mitm/
cp bin/mitm-ctl /usr/bin/ && chmod +x /usr/bin/mitm-ctl
cp bin/mitm-nft.sh /usr/libexec/ && chmod +x /usr/libexec/mitm-nft.sh
cp initd/mitm initd/pktcap /etc/init.d/ && chmod +x /etc/init.d/mitm /etc/init.d/pktcap
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout /etc/squid/ssl/mitm-ca.key -out /etc/squid/ssl/mitm-ca.crt \
  -subj "/CN=mitm-ctl CA/O=mitm-ctl"
/etc/init.d/mitm enable && /etc/init.d/pktcap enable && /usr/bin/mitm-ctl on

# ---------- Debian / Ubuntu ----------
apt install -y python3 python3-cryptography openssl curl tcpdump
mkdir -p /usr/share/pktcap /usr/share/mitm /etc/mitm/ca
cp pktcap_server.py body.html panel.html index.html CHEATSHEET.md /usr/share/pktcap/
cp mitm_proxy.py /usr/share/mitm/
cp systemd/mitm.service systemd/pktcap.service /etc/systemd/system/
# 编辑两个 service，把 __CONF__ / __CA_CRT__ / __CA_KEY__ 等占位符换成实际值
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout /etc/mitm/ca/mitm-ca.key -out /etc/mitm/ca/mitm-ca.crt \
  -subj "/CN=mitm-ctl CA/O=mitm-ctl"
systemctl daemon-reload && systemctl enable --now mitm pktcap
```


---

## 🚀 快速上手

### 1. 给设备装 CA 证书

浏览器打开 **`http://<设备IP>:7690/cert`** → 下载 `.crt` → 装成 **CA 证书 / 受信任的根证书**。

> 证书页**不需要登录**（手机装证书时没法带认证），页面上直接给了 Android / iOS / Windows / macOS / Firefox 各自的步骤和 CA 指纹。
> 不装证书的话，被解密的 HTTPS 会报证书错误（这也是判断"是否解密成功"的最快方法）。

### 2. 打开界面

| 页面 | 地址 | 干什么 |
|---|---|---|
| **解密内容** | `http://<设备IP>:7690/body` | 看解密后的请求/返回正文（**主界面**，也是 `/` 的默认落地页） |
| 控制台 | `http://<设备IP>:7690/panel` | 开关、范围、模式、日志、缓存管理 |
| 抓包表格 | `http://<设备IP>:7690/packets` | tcpdump 实时流量（需手动开始） |
| 装证书 | `http://<设备IP>:7690/cert` | CA 证书下载 + 各平台安装步骤 |
| 速查手册 | `http://<设备IP>:7690/doc` | 项目自带的手册（本项目 `CHEATSHEET.md`） |

默认账号密码 **`root` / `root`**（安装时用 `PKTCAP_PASS=xxx` 覆盖，或改 `initd/pktcap`、`systemd/pktcap.service`）。

从 LuCI 进：**服务 → 流量抓包**，默认落到「解密内容」。

### 3. 开始抓

控制台 → **① 抓哪些设备**（建议先只选自己那台）→ **② ③ 解密范围** → 保存。
然后回 `/body`，让设备产生点流量即可看到。

> **显式代理模式（Docker / Debian 默认）**：跳过上面这步，直接在客户端把 HTTP+HTTPS 代理设为 `设备IP:8080` 就行。

---

## 🎛 命令行

```sh
mitm-ctl on                 # 开启解密（拦截 + 解密）
mitm-ctl off                # 暂停拦截（所有设备恢复直连，代理进程留着可秒开）
mitm-ctl stop               # 完全停止（清 nft 规则 + 停进程，最省资源）
mitm-ctl only 10.0.0.102    # 只解密指定设备
mitm-ctl all                # 解密整个 LAN
mitm-ctl status             # 查看进程 / 监听 / 规则 / CA
```

---

## 🔌 HTTP API

所有接口都用 Basic Auth（默认 `root:root`）。

| 方法与路径 | 说明 |
|---|---|
| `GET  /api/mitm` | 解密状态（enabled / running / mode / targets / bypass / autoclose / viewers） |
| `POST /api/mitm` | 改配置：`{enabled, mode, domains, scope, ip, ifaces, autoclose_enabled, autoclose_minutes}` |
| `GET  /api/capture` | 抓包状态 |
| `POST /api/capture` | `{"action":"start"\|"stop"}`、`{"keepalive":true}` |
| `GET  /api/log` | 日志统计 + 开关状态 |
| `POST /api/log` | `{"action":"enable"\|"disable"\|"trim"\|"clear"\|"save"}` |
| `POST /api/send` | **主动发请求**：`{method, url, headers, body}` → 状态/头/体 |
| `GET  /api/blob` | 图片/文档缓存统计 |
| `POST /api/blob` | `{"action":"clear"}` |
| `GET  /blob/<id>` | 取缓存的图片/文档（`?dl=1` 下载） |
| `GET  /bstream` | 解密记录的 SSE 实时流 |
| `GET  /stream` | 抓包表格的 SSE 实时流 |
| `POST /api/ping` | 心跳（用于「无人查看自动关闭」判定） |

```sh
# 例：把解密范围收窄到自己手机
curl -u root:root -X POST -H 'Content-Type: application/json' \
  -d '{"enabled":true,"scope":"ip","ip":"10.0.0.102"}' \
  http://10.0.0.1:7690/api/mitm

# 例：主动发一个请求（会走真实网络）
curl -u root:root -X POST -H 'Content-Type: application/json' \
  -d '{"method":"GET","url":"https://example.com/","headers":{},"body":""}' \
  http://10.0.0.1:7690/api/send
```

---

## ⚙️ 配置文件

| 文件 | 内容 |
|---|---|
| `/etc/mitm/mode` | `all` / `list` / `exclude` |
| `/etc/mitm/domains.txt` | 域名名单（`list`/`exclude` 模式用，`example.com` 匹配所有子域） |
| `/etc/mitm/ifaces` | 只拦截哪些来源网卡（空 = 全部） |
| `/etc/squid/mitm-targets` | 解密哪些来源 IP/网段，如 `10.0.0.0/24` |
| `/etc/mitm/auto-bypass.txt` | **自动放行名单**（解密失败即写入，连带父域名） |
| `/etc/mitm/logcfg` | 日志上限：第 1 行字节数、第 2 行保留条数 |
| `/etc/mitm/log-enable` | 日志总开关 `1`/`0` |
| `/etc/mitm/autoclose` | 无人查看自动关闭：第 1 行是否启用、第 2 行分钟数 |

---

## 🧩 技术栈

| 层 | 用了什么 |
|---|---|
| 系统 | OpenWrt 25.12 / Kwrt（`MT7981` 双核 aarch64，512MB 内存足够）；也支持 Debian/Ubuntu 与 Docker |
| 运行时 | Python 3.13 `python3-light` + `python3-openssl` + `python3-cryptography` |
| 拦截 | `nftables`（nat prerouting 重定向 80→8080、443→8443，**drop UDP 443 禁用 QUIC**） |
| 代理 | 自写 `mitm_proxy.py`：裸 `socket` + `ssl` 做 CONNECT 中转、动态签发叶子证书 |
| Web | 自写 `pktcap_server.py`：裸 socket HTTP/1.1 + SSE，无 gunicorn/flask |
| 前端 | 原生 HTML/CSS/JS，无框架、无构建、无 CDN |
| 流量表 | `tcpdump` 子进程 + 自写 pcap 解析 |
| 证书 | OpenSSL 自签 CA，运行时按域名签发叶子证书 |

**约 5100 行，零第三方运行时依赖。**

> ⚠️ **头号约束**：OpenWrt 的 `python3-light` **没有 `email` 模块**，所以
> `http.server` / `http.client` / `urllib` **全部不可用** —— Web 服务、HTTP 客户端、SSE 都是裸 socket 手写的。
> 另外它缺 `encodings.idna`，`socket.create_connection()` 传字符串主机名会抛 `unknown encoding: idna`，
> **必须传 `bytes`**。这两条是迁移时最容易踩的坑。

### 为什么不用现成方案

| 方案 | 为什么不行 |
|---|---|
| mitmproxy | Python 依赖太重（要 `email`、`h11` 等），路由器上装不动 |
| squid `ssl_bump` | 能解密但**记不到响应正文**，只能看 URL |
| sslsplit | 多数 OpenWrt 仓库没有，且同样只记元数据 |
| Wireshark / tshark | 存储与内存都撑不住 |

---

## 📁 目录结构

```
mitm-ctl/
├── install.sh / uninstall.sh      一键安装 / 卸载（自动识别 OpenWrt / Debian）
├── README.md · LICENSE
├── .gitattributes · .gitignore     强制 LF（脚本要跑在 busybox 上）
├── pktcap_server.py               Web 服务 + API + 抓包（→ /usr/share/pktcap/）
├── mitm_proxy.py                  解密代理（→ /usr/share/mitm/）
├── body.html                      解密内容页
├── panel.html                     控制台
├── index.html                     流量表格页
├── CHEATSHEET.md                  速查手册（也可在 /doc 看）
├── Dockerfile                     容器镜像
├── docker-compose.yml             一键跑容器
├── docker/entrypoint.sh           容器入口（生成 CA + 拉起两个进程）
├── bin/
│   ├── mitm-ctl                   总控 CLI（→ /usr/bin/，兼容 procd/systemd）
│   ├── mitm-nft.sh                nftables 规则（→ /usr/libexec/）
│   └── auto-bypass.default.txt    证书固定域名兜底名单
├── initd/                         OpenWrt procd 服务（→ /etc/init.d/）
│   ├── mitm
│   └── pktcap
├── systemd/                       Debian/Ubuntu systemd 服务（→ /etc/systemd/system/）
│   ├── mitm.service
│   └── pktcap.service
├── luci/                          LuCI 入口（菜单 / ACL / iframe 视图）
├── icon/mitm-ctl.png              iStore 应用图标（纯 Python 生成，无第三方依赖）
├── feed/                          **opkg 源**：Packages(.gz) + 两个 ipk（Release 与在线源共用）
├── bin/mitm-ctl-setup             设备侧初始化脚本（install.sh 与 ipk 共用，保证结果一致）
├── windows/mitmctl.py             Windows 启动器（生成 CA + 起服务 + 设系统代理）
├── tools/
│   ├── deploy.sh                  **改完代码一键部署**（归一化 LF + 上传 + 重启 + 校验）
│   ├── restart-svc.sh             设备侧**确定性重启**（停干净→等端口释放→起→校验单实例）
│   ├── build-pkg.py               **构建 ipk + opkg 源索引**（含出厂自检）
│   ├── build-exe.py               **打包 Windows exe**（PyInstaller）
│   ├── smoke-test.sh              安装后回归验证（页面/接口/开关/解密链路）
│   ├── gen_preview.py             离线预览生成器（开发用）
│   └── test.pcap                  抓包页测试数据
├── docs/
│   ├── 使用说明.md
│   └── 技术总结与迁移方案.md        技术栈 / 难点 / 迁移与打包方案
└── legacy/https.html              已废弃页面（保留备查）
```

---

## 🔄 改完代码怎么部署

**推荐用自带脚本**（会先统一换行符 —— 见下方警告 —— 再上传、重启、跑一遍页面自检）：

```sh
sh tools/deploy.sh root@10.0.0.1
```

手动等价操作：

```sh
# 语法自检
python3 -m py_compile pktcap_server.py mitm_proxy.py

# 上传（改哪个传哪个）
scp pktcap_server.py root@10.0.0.1:/usr/share/pktcap/
scp mitm_proxy.py    root@10.0.0.1:/usr/share/mitm/
scp body.html panel.html index.html root@10.0.0.1:/usr/share/pktcap/

# 必做：重启对应服务（改了 py 不重启 = 没生效）
ssh root@10.0.0.1 '/etc/init.d/pktcap restart'
ssh root@10.0.0.1 '/etc/init.d/mitm restart'
```

> `mitm_proxy.py` → 重启 `mitm`；`pktcap_server.py` / `*.html` → 重启 `pktcap`。
> Debian 下把 `/etc/init.d/x restart` 换成 `systemctl restart x`。

> ⚠️ **Windows 开发必看**：编辑器/工具很容易把文件写成 **CRLF**，而 CRLF 的 shell 脚本拷到
> busybox 上会直接报 `not found` / 语法错误。仓库已用 `.gitattributes` 锁定 LF，
> 但**工作区**仍可能被写脏 —— `tools/deploy.sh` 每次都会先归一化，建议养成用它部署的习惯。
> 自查：`git ls-files --eol | grep w/crlf` 应为空。

> `tools/smoke-test.sh` 可在安装后跑一遍完整回归（5 个页面 + 证书页 + 解密链路 + 开关 + 主动发包）：
> `ssh root@10.0.0.1 'sh /tmp/smoke.sh'`

---

## 📦 自己打包（改完代码发新版本）

```sh
python3 tools/build-pkg.py --version 1.1.0
```

产出 `dist/*.ipk` + `feed/`（`Packages`、`Packages.gz` 与两个 ipk）。
`feed/` 入库后即可当 opkg 源用；把 `dist/` 里的 ipk 传到 GitHub Releases 供人下载。

打包器有两个防坑设计：
- **模板替换**：`initd/` 是模板（`install.sh` 用 sed 填值），打包时会先替换成真实默认值 ——
  否则会出现 `PKTCAP_PORT=__PORT__` → `int("__PORT__")` 让服务陷入崩溃重启（真机踩过）。
- **出厂自检**：把生成的 ipk 解回来扫一遍，发现任何未替换的 `__X__` 直接构建失败。

> ⚠️ **ipk 格式随 OpenWrt 版本而变**：OpenWrt 24.10+ / Kwrt 25.x 的 ipk 是
> **gzip 压缩的 tar**（内含 `./debian-binary` + `./data.tar.gz` + `./control.tar.gz`）；
> 23.05 及更早是 **ar 归档**。默认产出新格式，老系统用 `--format=ar`。

---

## 🩹 更新日志

### 1.0.1

**修复（都是真机上实测抓到的）**

- **「刚点开启解密，几秒后又自己关了」** —— 自动关闭的计时基准用的是「服务启动时刻」，
  所以服务跑够 N 分钟后再开解密，20 秒内就会被巡检关掉。现在**开启的那一刻重新计时**。
- **`mitm-ctl stop` 停不掉代理** —— 它会在调完服务框架后再强杀进程，而 procd 带 `respawn`，
  直接杀会被当成崩溃而重启；更糟的是 procd 的 teardown（含 `stop_service` 里的清规则）
  会迟到，把下一次 `on` 刚下发的规则抹掉。现在会**等 teardown 真正跑完**再返回，
  只在框架失效时才兜底杀进程。
- **procd 记账与实际脱节导致新实例 crash loop** —— 日志特征
  `OSError: [Errno 98] Address in use` + `procd: ... in a crash loop`，此时页面仍由
  那个孤儿进程撑着，服务其实已不受管理。现在 initd **启动前清理残留实例**自愈，
  并新增 `tools/restart-svc.sh` 做确定性重启（停干净 → 等端口释放 → 起 → 校验单实例）。

**功能与体验**

- **正文不再截断**：取消「只保留前 2 万字符」的上限，抓到的内容全部保留
  （转发给客户端的始终是完整内容）。日志改为按累计字节数触发裁剪，大响应的预算更准。
  实测一条 263460 字节 / 246017 字符的 JSON 完整保存（`resp_truncated=false`）。
- **JSON 折叠树重做**：每行最左侧固定「行号 + 三角」，用淡色引导线连到内容，
  引导线随层级加长；**默认全部展开**；点整行任意位置都能折叠；
  面板上新增「展开 / 收起 / **原始数据**」切换（点一下切成原始文本，再点切回折叠树）。

**其他**

- 部署脚本 `tools/deploy.sh` 改用确定性重启（`tools/restart-svc.sh`），
  并在末尾打印进程数供核对。

---

## 🧯 常见问题

**看不到任何内容？** 三个开关是独立的，逐个查：
① 解密是否开启（`/api/mitm` 的 `enabled`）；② 日志总开关是否关闭（`log_enabled`）；③ 模式与名单是否覆盖你在测的域名。

**某个 App 白屏 / 连不上？** 它做了证书固定，被自动放行的是"能连但不记内容"。
想强制看内容 → 控制台选「仅解密指定域名」填它 —— 但**它可能直接连不上**，这是二选一。

**浏览器一直报证书错误？** 手机/电脑没装 CA，去 `http://<设备IP>:7690/cert`（这个页面不需要登录）。

**其他设备受影响吗？** 解密开启时流量会过一道代理（透传很轻），QUIC 被禁用会退回 TCP。
想 100% 零影响 → 控制台选「只抓指定设备」填自己 IP，其他设备在 nft 层就被排除。

---

## ⚖️ 免责声明

本项目仅用于**你拥有或已获授权**的网络的调试、抓包与安全研究。
解密并查看**他人**流量可能违反法律法规与隐私政策，请自行承担使用风险。
请勿用于任何非法用途。

---

## 📄 License

[MIT](LICENSE)

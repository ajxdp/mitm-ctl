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
| **JSON 折叠树** | 递归折叠小三角、对象/数组计数徽标、默认展开两层、超长数组按需展开、可切回原始文本 |
| **二进制预览** | 🖼 图片直接显示、📄 PDF 内嵌预览、Office 文档可下载；按内容哈希去重存储 |
| **主动发包** | 页面内「重放 / 编辑并发送」——类 Apipost 的简易请求编辑器，支持自定义方法/URL/头/体，可复制为 cURL |
| **流量抓包** | 独立的 tcpdump 实时表格（DNS / TLS / TCP / UDP 解析 + 域名反查），**按需启动** |
| **证书固定自愈** | 解密失败的域名自动放行（含父域名），避免拼多多/淘宝这类 App 被打挂 |
| **按需省电** | 解密、抓包、日志三个开关各自独立，默认关闭；无人查看自动停 |
| **自我保护** | 日志超限自动裁剪（`/tmp` 是内存盘）、图片缓存上限+LRU 回收、无框架无构建 |

---

## 📦 安装

### 方式一：一键脚本（推荐）

把本仓库拷到路由器上（`scp` 或直接在路由器上 `git clone`），然后：

```sh
cd mitm-ctl
sh install.sh
```

脚本会：检查/安装依赖 → 生成 CA 证书 → 复制文件 → 初始化配置 → 设置开机自启 → 启动服务。

### 方式二：手动

```sh
# 1) 依赖
opkg update
opkg install python3-light python3-openssl python3-cryptography openssl-util nftables tcpdump

# 2) 程序
mkdir -p /usr/share/pktcap /usr/share/mitm /etc/mitm /etc/squid/ssl
cp pktcap_server.py body.html panel.html index.html CHEATSHEET.md /usr/share/pktcap/
cp mitm_proxy.py /usr/share/mitm/
cp bin/mitm-ctl /usr/bin/ && chmod +x /usr/bin/mitm-ctl
cp bin/mitm-nft.sh /usr/libexec/ && chmod +x /usr/libexec/mitm-nft.sh
cp initd/mitm initd/pktcap /etc/init.d/ && chmod +x /etc/init.d/mitm /etc/init.d/pktcap

# 3) CA 证书（10 年有效）
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout /etc/squid/ssl/mitm-ca.key -out /etc/squid/ssl/mitm-ca.crt \
  -subj "/CN=Kwrt MITM CA/O=Kwrt Home"

# 4) 开机自启 + 启动
/etc/init.d/mitm enable && /etc/init.d/pktcap enable
/usr/bin/mitm-ctl on
```

### 方式三：Docker（任意系统，无需 nftables）

```sh
# 构建并启动
docker compose up -d --build

# 或者不用 compose
docker build -t mitm-ctl .
docker run -d --name mitm-ctl \
  -p 8080:8080 -p 8443:8443 -p 7690:7690 \
  -v mitm-data:/data \
  mitm-ctl
```

> 容器内无法做 nftables 重定向，所以是**显式代理模式**：把客户端（浏览器/系统/App 的代理设置）指向 `主机IP:8080` 即可。
> 这种模式下**所有功能都可用**（解密、折叠 JSON、图片预览、重放编辑器），只是"只抓某台设备"由你自己在客户端决定。
> CA 证书在 `/data/ca/mitm-ca.crt`，用 `docker cp mitm-ctl:/data/ca/mitm-ca.crt .` 取出来装到设备上。

---

## 🚀 快速上手

### 1. 给设备装 CA 证书

浏览器打开 **`http://<路由器IP>/cert.html`** → 下载 `.crt` →
**设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书**。

> 不装证书的话，被解密的 HTTPS 会报证书错误（这也是判断"是否解密成功"的方法）。

### 2. 打开界面

| 页面 | 地址 | 干什么 |
|---|---|---|
| **解密内容** | `http://<路由器IP>:7690/body` | 看解密后的请求/返回正文（**主界面**） |
| 控制台 | `http://<路由器IP>:7690/panel` | 开关、范围、模式、日志、缓存管理 |
| 抓包表格 | `http://<路由器IP>:7690/packets` | tcpdump 实时流量（需手动开始） |
| 速查手册 | `http://<路由器IP>:7690/doc` | 项目自带的手册（本项目 `CHEATSHEET.md`） |

默认账号密码 **`root` / `root`**（在 `initd/pktcap` 里改 `PKTCAP_USER` / `PKTCAP_PASS`）。

从 LuCI 进：**服务 → 流量抓包**，默认落到「解密内容」。

### 3. 开始抓

控制台 → **① 抓哪些设备**（建议先只选自己那台）→ **② ③ 解密范围** → 保存。
然后回 `/body`，让设备产生点流量即可看到。

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
| 系统 | OpenWrt 25.12 / Kwrt（`MT7981` 双核 aarch64，512MB 内存足够） |
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
├── install.sh / uninstall.sh      安装 / 卸载
├── README.md · LICENSE · .gitignore
├── pktcap_server.py               Web 服务 + API + 抓包（→ /usr/share/pktcap/）
├── mitm_proxy.py                  解密代理（→ /usr/share/mitm/）
├── body.html                      解密内容页
├── panel.html                     控制台
├── index.html                     流量表格页
├── CHEATSHEET.md                  速查手册（也可在 /doc 看）
├── bin/
│   ├── mitm-ctl                   总控 CLI（→ /usr/bin/）
│   └── mitm-nft.sh                nftables 规则（→ /usr/libexec/）
├── initd/
│   ├── mitm                       procd 服务（→ /etc/init.d/）
│   └── pktcap
├── docs/
│   ├── 使用说明.md
│   ├── 技术总结与迁移方案.md        技术栈 / 难点 / 迁移与打包方案
│   └── gen_preview.py             离线预览生成器（开发用）
├── tools/test.pcap                抓包页测试数据
└── legacy/https.html              已废弃页面（保留备查）
```

---

## 🔄 改完代码怎么部署

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
> 细节与故障排查见 `CHEATSHEET.md`（网页版 `/doc`）。

---

## 🧯 常见问题

**看不到任何内容？** 三个开关是独立的，逐个查：
① 解密是否开启（`/api/mitm` 的 `enabled`）；② 日志总开关是否关闭（`log_enabled`）；③ 模式与名单是否覆盖你在测的域名。

**某个 App 白屏 / 连不上？** 它做了证书固定，被自动放行的是"能连但不记内容"。
想强制看内容 → 控制台选「仅解密指定域名」填它 —— 但**它可能直接连不上**，这是二选一。

**浏览器一直报证书错误？** 手机/电脑没装 CA，去 `http://<路由器IP>/cert.html`。

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

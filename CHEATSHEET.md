# Kwrt 解密抓包 · 速查手册

> 放在路由器本机：`/usr/share/pktcap/CHEATSHEET.md`
> 网页打开：`http://10.0.0.1:7690/doc` ｜ 控制台：`http://10.0.0.1:7690/panel`
> 本地源码镜像：`C:\Users\admin\WorkBuddy\2026-09-15-17-38-28\pktcap\`

---

## 零、技术栈

**运行环境（路由器侧）**

| 组件 | 版本 | 用途 | 备注 |
|---|---|---|---|
| Kwrt / OpenWrt | 25.12 | 系统 | 23.05+ 均可 |
| **Python** | 3.13.9（`python3-light`） | 两个服务的运行时 | ⚠️ **裁剪版**，见下方约束 |
| `python3-openssl` | 随系统 | TLS 终结（`ssl` 模块） | 必装 |
| `python3-cryptography` | 随系统 | 动态签发叶子证书 | 唯一的"重"依赖 |
| tcpdump | 4.99.6 | 抓原始包（仅 `/packets` 用） | **可选**，不装不影响解密 |
| OpenSSL | 3.5.7 | 生成 MITM CA | `openssl-util` 包 |
| nftables | 内核自带 | 透明重定向 80/443 | OpenWrt 22.03+ 默认 nft |
| nginx | 随固件 | 仅托管证书下载页（80 端口） | 解密本身不需要它 |

**前端**：纯原生 HTML/CSS/JS —— **无框架、无构建步骤、无外部 CDN**（路由器环境常断外网）；
实时推送用 **SSE**（比 WebSocket 简单且够用）。

**代码规模**：约 5000 行（Python ~2600 + HTML ~2400），**零第三方运行时依赖**。

### ⚠️ 头号约束：`python3-light` 是裁剪版

| 缺失 | 后果 | 我们的对策 |
|---|---|---|
| **`email` 模块** | `http.server` / `http.client` / `urllib.request` **全部 import 失败** | Web 服务和 HTTP 客户端**全部裸 socket 手写** |
| **`encodings.idna`** | `getaddrinfo`/`ssl` 传 **str 主机名** 会抛 `unknown encoding: idna` | 主机名一律传 **bytes** |
| `ssl`（默认不带） | 无法做 TLS | 装 `python3-openssl` |

> 这几条最反直觉：在标准 Python 上能跑的代码，到这里全挂。迁到普通 Linux（Debian/Alpine）后约束自动消失。

### 为什么不用现成方案

| 方案 | 为什么没用 |
|---|---|
| mitmproxy | OpenWrt 仓库没打包，依赖重（aiohttp、h2…），路由器装不动 |
| squid + ssl_bump | 试过，**只记 URL、抓不到正文**，满足不了需求（已替换掉） |
| sslsplit | 仓库没有；且只解密不做 HTTP 语义解析，正文还得另写 |
| Wireshark / tshark | 路由器跑不动，且是离线分析工具 |

**结论：在 OpenWrt 这个生态里，"自建"是唯一可行路径。** 全部用标准库手写 → 零 pip 依赖、
约 90KB 代码 + 2 个进程、内存 ~30MB、可完整迁移。


## 一、30 秒上手

| 我想干什么 | 怎么做 |
|---|---|
| 看解密后的请求/返回 | 打开 `http://10.0.0.1:7690`（自动进 `/body`）；**没数据就先点「▶ 开启解密」** |
| 开关解密 | 控制台 `/panel` →「▶ 开启解密 / ⏸ 暂停拦截 / ■ 完全停止」 |
| 抓原始包（tcpdump） | `/packets` →「▶ 开始抓包」；**默认关闭**，无人看 60 秒自动停 |
| 证书下载（给设备装） | `http://10.0.0.1/cert.html`（**80 端口**，不是 7690） |
| 重放/改包再发 | `/body` 里展开任意一条 →「↻ 重放」或「✎ 编辑发送」 |
| **看抓到的图片/文档** | `/body` 展开对应记录，图片直接显示、PDF 内嵌预览、其它文档可下载 |
| **看很长的 JSON** | 响应体是**可折叠树**：点左边小三角逐层展开/收起；超过 200 项的数组点「还有 N 项」展开；右上角可切「≡ 原始」文本 |

命令行等价：

```sh
mitm-ctl on      # 开启解密（拦截+解密）
mitm-ctl off     # 暂停拦截（代理留着，秒开）
mitm-ctl stop    # 完全停止（清规则+停进程，最省）
mitm-ctl all     # 解密范围＝整个 LAN
mitm-ctl only 10.0.0.102   # 只抓某台设备
mitm-ctl status  # 看进程/监听/规则/CA
```

---

## 二、文件地图（改东西去这里）

### 运行时代码

| 文件 | 干什么 | 改什么来这里 |
|---|---|---|
| `/usr/share/mitm/mitm_proxy.py` | **核心代理**：透明+显式 MITM、动态签发证书、流式转发、记录正文、自动放行 | 转发逻辑、证书生成、记录格式、`is_target` 域名判定 |
| `/usr/share/pktcap/pktcap_server.py` | Web/API（7690）：SSE 推送、筛选、重放、抓包与解密启停、日志管理、`/doc` 文档页 | 加接口、改路由、改抓包逻辑、加统计 |
| `/usr/share/pktcap/body.html` | 解密内容页（列表+筛选+详情+请求编辑器） | 前端样式、筛选维度、编辑器 |
| `/usr/share/pktcap/panel.html` | 控制台（开关、范围、域名、自动关闭、日志） | 控制项 |
| `/usr/share/pktcap/index.html` | 抓包表格页（tcpdump 原始包） | 包列表展示 |
| `/usr/share/pktcap/legacy/https.html` | **已废弃**（`/https` 现 302 到 `/body`） | 不用管 |

### 配置（都在 `/etc/mitm/`）

| 文件 | 内容 | 默认 |
|---|---|---|
| `mode` | `all` / `list` / `exclude` | `all` |
| `domains.txt` | 域名名单（`#` 注释，填 `a.com` 匹配所有子域） | — |
| `ifaces` | 来源网卡过滤（空＝全部） | `br-lan` |
| `/etc/squid/mitm-targets` | 抓哪些设备（IP 或 CIDR） | `10.0.0.0/24` |
| `auto-bypass.txt` | 自动放行名单（证书固定自愈） | 内置主流 App |
| `autoclose` | 无人监听自动关闭：第 1 行 `1/0`，第 2 行分钟数 | `1` / `5` |
| `logcfg` | 第 1 行字节上限，第 2 行保留条数 | 2MB / 400 |
| `log-enable` | 日志总开关 `1/0`（**关＝不记录也不抓正文**） | `1` |
| 图片缓存目录 | `/tmp/mitm-blobs/`（抓到的图片/PDF/文档，`MITM_BLOB_DIR`） | 单个 ≤1MB · 总量 ≤16MB，超了删最旧的 |

### 服务与脚本

| 文件 | 作用 |
|---|---|
| `/etc/init.d/pktcap` | procd 服务（Web/API 7690） |
| `/etc/init.d/mitm` | procd 服务（代理 8080/8443） |
| `/usr/bin/mitm-ctl` | 解密总控（on/off/stop/all/only/status） |
| `/usr/libexec/mitm-nft.sh` | 下发/清除 nft 重定向规则 |
| `/etc/squid/ssl/mitm-ca.{crt,key}` | MITM 根证书（**私钥勿外传**） |
| `/www/cert.html`、`/www/mitm-ca.crt` | 给设备下载证书的页面（80 端口） |
| `/www/luci-static/resources/view/capture/*.js` | LuCI 里的 iframe 页面 |
| `/usr/share/luci/menu.d/luci-app-capture.json` | LuCI 菜单（默认进「解密内容」） |

---

## 三、改完代码怎么部署（最常用流程）

本地改 `C:\Users\admin\WorkBuddy\2026-09-15-17-38-28\pktcap\` 下的源文件，然后：

```bash
cd /path/to/mitm-ctl

# 1) 语法自检（Python 用托管解释器；HTML 抽 <script> 给 node --check）
PY=python3
NODE=node
"$PY" -m py_compile pktcap_server.py mitm_proxy.py

# 2) 上传（注意：cat 有时候会静默失败，务必比对 md5）
ssh root@10.0.0.1 'cat > /usr/share/pktcap/pktcap_server.py' < pktcap_server.py
ssh root@10.0.0.1 'cat > /usr/share/mitm/mitm_proxy.py'   < mitm_proxy.py
ssh root@10.0.0.1 'cat > /usr/share/pktcap/body.html'     < body.html
ssh root@10.0.0.1 'cat > /usr/share/pktcap/panel.html'    < panel.html
ssh root@10.0.0.1 'cat > /usr/share/pktcap/index.html'    < index.html

# 3) md5 校验（本地 vs 远端必须一致）
"$PY" -c "import hashlib;print(hashlib.md5(open('pktcap_server.py','rb').read()).hexdigest())"
ssh root@10.0.0.1 'md5sum /usr/share/pktcap/pktcap_server.py'

# 4) 重启（改了 py 必须重启；只改 html 刷新即可）
ssh root@10.0.0.1 '/etc/init.d/pktcap restart; /etc/init.d/mitm restart; sleep 3'

# 5) 冒烟验证
ssh root@10.0.0.1 'for u in / /body /panel /packets /doc; do printf "%s=%s\n" $u $(curl -s -u root:root -o /dev/null -w "%{http_code}" http://127.0.0.1:7690$u); done'
```

> ⚠️ 三个反复踩过的坑：
> 1. **改了 py 不重启 = 没生效**（会白白排查半天）。
> 2. **只重启 pktcap 不够**——改 `mitm_proxy.py` 要重启 `mitm`。
> 3. **`cat > file` 上传偶尔静默失败**，永远比对 md5。

---

## 四、API 速查（都需 Basic Auth `root:root`）

```sh
B=http://10.0.0.1:7690

# 解密状态 / 开关 / 范围 / 域名 / 自动关闭
curl -u root:root $B/api/mitm
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"enabled":true}'            $B/api/mitm
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"enabled":false,"stop_mode":"stop"}' $B/api/mitm
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"mode":"list","domains":"a.com"}'    $B/api/mitm
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"scope":"ip","ip":"10.0.0.102"}'     $B/api/mitm
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"autoclose_enabled":true,"autoclose_minutes":5}' $B/api/mitm
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"action":"clearbypass"}'    $B/api/mitm

# 日志：状态 / 开关 / 裁剪 / 清空 / 改上限
curl -u root:root $B/api/log
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"action":"disable"}' $B/api/log
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"action":"enable"}'  $B/api/log
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"action":"trim"}'    $B/api/log
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"action":"save","max_bytes":2097152,"keep_lines":400}' $B/api/log

# 抓包（tcpdump）状态 / 起停 / 无人观看保持
curl -u root:root $B/api/capture
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"action":"start"}' $B/api/capture
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"action":"stop"}'  $B/api/capture

# 主动发请求（重放 / 请求编辑器）
curl -u root:root -X POST -H 'Content-Type: application/json' \
  -d '{"method":"GET","url":"https://example.com/","headers":{},"body":""}' $B/api/send

# 解密页心跳（前端每 30s 一次，用于「无人监听自动关闭」）
curl -u root:root $B/api/ping

# 抓到的图片/文档：/blob/<id> 在线看，?dl=1 下载
curl -u root:root -o /tmp/a.png $B/blob/24e457462c1a8d93.png
curl -u root:root $B/api/blob                                   # 缓存统计
curl -u root:root -X POST -H 'Content-Type: application/json' -d '{"action":"clear"}' $B/api/blob
```

其它：`/bstream`（解密记录 SSE）、`/stream`（抓包 SSE）、`/last`（最后一条包）、`/doc`（本手册）。

---

## 五、故障速查表

| 症状 | 先查什么 | 处理 |
|---|---|---|
| **解密页一条都没有** | `curl -u root:root $B/api/log` 看 `enabled` | 日志关了 → `{"action":"enable"}`；或页面顶部橙色提示条点「开启日志记录」 |
| 解密页没反应但日志是开的 | `$B/api/mitm` 看 `enabled` | 无人监听 5 分钟会自动关 → 点「▶ 开启解密」 |
| 只看到部分域名 | `cat /etc/mitm/mode` | `list` 模式**只解密名单内**域名；要抓全部就切 `all` |
| **某个 App 连不上** | `cat /etc/mitm/auto-bypass.txt` | 证书固定的 App：控制台「④ 自动放行名单」看有没有它；没有就切 `list` 模式 + 填域名，或等它自愈一次 |
| 抓包表格是空的 | `$B/api/capture` | 抓包默认关 → `/packets` 点「▶ 开始抓包」 |
| 抓包自己停了 | — | 无人看这一页 60 秒会自动停；要一直抓就勾「无人观看也保持」 |
| 证书页 404 | 确认用的是 **80 端口** | `http://10.0.0.1/cert.html`（不是 `:7690/cert.html`） |
| 页面样式没变 | 浏览器缓存 | **Ctrl+F5** 强刷 |
| 记录让内存变大 | `$B/api/log` 看 bytes | 有 2MB 上限会自动裁；也可手动「立即裁剪/清空」 |
| **图片看不到内容** | 该条有没有 `blob` 字段 | 有＝图片已缓存，展开详情即可看到；没有＋`blob_partial`＝文件超 1MB 或分块传输，未缓存 |
| 图片缓存占内存 | `$B/api/blob` 看 bytes | 总量上限 16MB 自动删最旧；控制台可一键清空 |
| 代理进程没了 | `mitm-ctl status` | `mitm-ctl on` 拉起 |
| 路由器整体变慢 | `/proc/*/comm` 数进程 | 正常应只有 **2 个 python3 + 0 个 tcpdump** |

排查通用三连：

```sh
cat /etc/mitm/mode; grep -v '^#' /etc/mitm/domains.txt; cat /etc/squid/mitm-targets   # 当前配置
mitm-ctl status                                                                        # 进程/监听/规则/CA
logread | grep '\[mitm\]' | tail -20                                                   # 代理日志
tail -3 /tmp/mitm-body.jsonl | cut -c1-150                                             # 最新记录
for d in /proc/[0-9]*; do cat $d/comm 2>/dev/null; done | sort | uniq -c               # 真实进程统计
```

---

## 六、端口与进程（正常状态）

| 端口 | 用途 |
|---|---|
| **7690** | Web/API（控制台、解密内容、抓包表格、`/doc`） |
| 8080 / 8443 | 透明代理：HTTP / HTTPS（同时兼显式代理 8080） |
| 80 | 路由器 Web（LuCI + 证书下载页） |
| 7681 | LuCI 终端（ttyd） |

正常应有：**2 个 `python3`**（`pktcap_server` + `mitm_proxy`）、**0 个 `tcpdump`**（未手动开抓包时）。

> 用 `netstat -ltn | grep -E '8080|8443'` 看监听；用 `/proc/*/comm` 统计进程（**别用 `ps|grep`，会匹配到自己的命令行**）。

---

## 六点五、图片 / 文档 / 媒体是怎么处理的

| 类型 | 处理方式 |
|---|---|
| 文本 / JSON / HTML | 抓前 256KB，解码后留前 2 万字符，页面里美化显示 |
| **图片（png/jpg/gif/webp/bmp/svg/ico/avif/heic）** | 完整抓下来存 `/tmp/mitm-blobs/<sha1前16位>.<ext>`，页面里**直接显示**，可点开原图 / 下载 |
| **PDF** | 同上，页面里**内嵌预览**，也可新窗口打开 / 下载 |
| **文档（doc/docx/xls/xlsx/ppt/pptx）** | 存下来，给「新窗口打开」「下载」 |
| 视频 / 音频 / 其它二进制 | 只记大小（体积太大，不缓存） |

要点：

- 存文件的前提是**完整且未被截断**：有 `Content-Length`、实际长度相符、且没超 1MB。
  分块（chunked）响应的原始字节里含分块头，直接存会得到损坏文件，所以跳过并标 `blob_partial`。
- 文件名是**内容哈希**，天然去重；同一张图抓多次只占一份。
- 目录在 `/tmp`（内存盘），**总量上限 16MB**，超了按时间删最旧的；控制台有「清空图片/文档缓存」。
- 日志总开关关闭时，**图片也不抓**（`cap = 0`），一分资源都不占。
- 页面上按类型筛选：`🖼 图片` / `📄 文档·PDF` / `🎬 视频音频` / `其它二进制`。

## 七、架构一句话

```
设备 → nft 重定向(80/443) → 代理(8080/8443)
     → 域名判定：需解密 → 动态签证书 + 解密 + 流式转发 + 记前缀
                  不需解密 → 原样透传(splice)
     → 记录写 /tmp/mitm-body.jsonl（tmpfs，2MB 上限自动裁）
     → pktcap_server 用 SSE 推到网页
```

**三种域名模式**

- `all`：全部解密（证书固定的自动放行）
- `list`：**只解密名单内**（最省，推荐只盯某几个接口时用）
- `exclude`：名单外全解密

**两个"按需"开关**（都是为了不长期占 CPU）

- 解密：`enabled` + 无人监听 N 分钟自动 `stop`
- 抓包：默认关，点了才跑 tcpdump

---

## 八、已知限制（不是 bug）

1. 不做中间人就看不到 HTTPS 正文（TLS 原理）。
2. 证书固定的 App 永远解不了正文（但会被自动放行，App 正常用）。
3. Android 7+ 用户装的 CA 只对浏览器生效，多数 App 需要 root 装系统证书。
4. 页面正文只保留前 2 万字符（**转发给 App 的始终完整**）。
5. 强制 ALPN `http/1.1`，WebSocket 只能看到握手。
6. `/api/send` 是"路由器代发请求"，本质内网 SSRF 面 —— 别把它暴露到公网。

---

## 九、要动代码时，先看这几处

| 想改 | 看哪 |
|---|---|
| 域名该不该解密 | `mitm_proxy.py` → `is_target()` |
| 证书固定自愈 | `mitm_proxy.py` → `mark_bypass()` / `handle_tls_error()` |
| 响应转发（**别再加截断**） | `mitm_proxy.py` → `forward_http()`（流式，只抓前缀） |
| 记录里放什么字段 | `mitm_proxy.py` → `forward_http()` 里组 `entry` + `emit()` |
| 哪些类型要缓存成可预览文件 | `mitm_proxy.py` → `blob_kind()`（缓存上限 `BLOB_MAX`/`BLOB_TOTAL`） |
| 图片/文档怎么发给浏览器 | `pktcap_server.py` → `serve_blob()` + 路由 `/blob/`（id 严格正则校验，防穿越） |
| 新增 API | `pktcap_server.py` → `client_thread()` 的路由链 |
| 前端筛选 / 编辑器 | `body.html`（`match()` 加维度 / `openCompose()`） |
| 抓包起停 | `pktcap_server.py` → `class Capture` |
| 自动关闭解密 | `pktcap_server.py` → `autoclose_monitor()` |
| nft 规则 | `/usr/libexec/mitm-nft.sh` |

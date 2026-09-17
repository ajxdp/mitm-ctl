#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 github.com:443 不可达的环境下，改用 GitHub REST API 推送本地提交。

背景：git 的 smart-HTTP 走 github.com，而本机/局域网可能只有 api.github.com 可达
（本例：路由器上跑着 sing-box，api.github.com / codeload 能通，github.com 时好时坏）。
于是用 git data 接口把提交在服务端重建：
  blobs → tree(base_tree=远端当前 tree) → commit(parents=[远端当前 commit]) → 更新 ref

用法：
  GH_TOKEN=xxx python tools/push-via-api.py [--dry-run] ["提交说明"]
环境变量：
  GH_TOKEN   必填，GitHub token（不要写进文件）
  GH_PROXY   可选，如 http://10.0.0.1:8080
  GH_REMOTE  可选，默认 ajxdp/mitm-ctl

注意：API 建出来的提交对象 SHA 会与本地不同（作者时间戳等元数据由服务端生成），
但 **tree 是逐字节一致的**，所以脚本用 tree 哈希而不是 commit SHA 来对齐两边。
"""
import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
API = "https://api.github.com"
REPO = os.environ.get("GH_REMOTE", "ajxdp/mitm-ctl")
TOKEN = os.environ.get("GH_TOKEN", "")
PROXY = os.environ.get("GH_PROXY", "")
DRY = "--dry-run" in sys.argv
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]

BIN_EXT = (".ipk", ".gz", ".png", ".jpg", ".pdf", ".exe", ".zip", ".pcap")


def sh(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True).stdout.strip()


def api(method, path, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": "Bearer " + TOKEN,
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "mitm-ctl-push"}
    if data:
        headers["Content-Type"] = "application/json"
    handlers = []
    if PROXY:
        handlers.append(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
    # 实测代理对 api.github.com 是纯隧道（对端是 GitHub 真证书），用系统证书库即可
    handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    op = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with op.open(req, timeout=120) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


def tree_of(rev):
    return sh("git", "rev-parse", "%s^{tree}" % rev)


def main():
    if not TOKEN:
        print("  ✗ 缺少 GH_TOKEN")
        return 1

    head = sh("git", "rev-parse", "HEAD")
    local_tree = tree_of(head)
    print("  本地 HEAD : %s  (tree %s)" % (head[:12], local_tree[:12]))

    st, ref = api("GET", "/repos/%s/git/ref/heads/main" % REPO)
    if st != 200:
        print("  ✗ 取远端 ref 失败: %s %s" % (st, ref))
        return 1
    remote_sha = ref["object"]["sha"]
    st, rcommit = api("GET", "/repos/%s/git/commits/%s" % (REPO, remote_sha))
    if st != 200:
        print("  ✗ 取远端提交失败: %s" % st)
        return 1
    remote_tree = rcommit["tree"]["sha"]
    print("  远端 main : %s  (tree %s)" % (remote_sha[:12], remote_tree[:12]))

    if remote_tree == local_tree:
        print("  ✓ 远端 tree 与本地一致，无需推送")
        return 0

    # 在本地历史里找一个「tree 与远端一致」的提交作为锚点：
    # 两边内容对齐后，要推的就是 anchor..HEAD 的差异。
    anchor = None
    for c in sh("git", "log", "--format=%H", "-n", "80").splitlines():
        if tree_of(c) == remote_tree:
            anchor = c
            break
    if anchor is None:
        print("  ✗ 本地历史里找不到与远端 tree 一致的提交，无法安全对齐（拒绝推送）")
        return 1
    print("  锚点提交  : %s（tree 与远端一致）" % anchor[:12])

    out = sh("git", "diff", "--name-status", anchor, head) if anchor != head else ""
    changes = []
    for ln in (out or "").splitlines():
        p = ln.split("\t")
        if len(p) >= 2:
            changes.append((p[0][0], p[-1]))
    if not changes:
        print("  ✓ 没有差异")
        return 0
    print("  待推送    : %d 个文件" % len(changes))

    entries = []
    for status, path in changes:
        if status == "D":
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            print("    D  %s" % path)
            continue
        content = subprocess.run(["git", "show", "%s:%s" % (head, path)],
                                 cwd=ROOT, capture_output=True).stdout
        ls = sh("git", "ls-tree", head, "--", path).split()
        mode = ls[0] if ls else "100644"
        b64 = path.lower().endswith(BIN_EXT) or b"\x00" in content[:8000]
        body = ({"content": base64.b64encode(content).decode("ascii"), "encoding": "base64"}
                if b64 else {"content": content.decode("utf-8"), "encoding": "utf-8"})
        if DRY:
            print("    %s  %s (%d B%s)" % (status, path, len(content), ", base64" if b64 else ""))
            continue
        st, r = api("POST", "/repos/%s/git/blobs" % REPO, body=body)
        if st not in (200, 201):
            print("    ✗ blob 失败 %s: %s %s" % (path, st, r))
            return 1
        entries.append({"path": path, "mode": mode, "type": "blob", "sha": r["sha"]})
        print("    %s  %-34s %7d B -> %s" % (status, path, len(content), r["sha"][:8]))

    if DRY:
        print("\n  （--dry-run，到此为止）")
        return 0

    st, tree = api("POST", "/repos/%s/git/trees" % REPO,
                   body={"base_tree": remote_tree, "tree": entries})
    if st not in (200, 201):
        print("  ✗ 建 tree 失败: %s %s" % (st, tree))
        return 1

    msg = ARGS[0] if ARGS else sh("git", "log", "-1", "--format=%B").rstrip("\n")
    an, ae = sh("git", "config", "user.name") or "xiao", sh("git", "config", "user.email") or "363720749@qq.com"
    st, commit = api("POST", "/repos/%s/git/commits" % REPO, body={
        "message": msg, "tree": tree["sha"], "parents": [remote_sha],
        "author": {"name": an, "email": ae}, "committer": {"name": an, "email": ae}})
    if st not in (200, 201):
        print("  ✗ 建 commit 失败: %s %s" % (st, commit))
        return 1

    st, r = api("PATCH", "/repos/%s/git/refs/heads/main" % REPO,
                body={"sha": commit["sha"], "force": False})
    if st not in (200, 201):
        print("  ✗ 更新 ref 失败: %s %s" % (st, r))
        return 1
    print("  ✓ 远端 main -> %s（tree %s）" % (r["object"]["sha"][:12], tree["sha"][:12]))
    print("  提示：远端提交 SHA 与本地不同（API 生成），内容一致；")
    print("        之后推送请继续用本脚本，它会用 tree 对齐。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

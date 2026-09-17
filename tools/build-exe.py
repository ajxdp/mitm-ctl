#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 mitm-ctl 打包成 Windows 单文件 exe（显式代理模式）。

用法：
    pip install pyinstaller cryptography
    python tools/build-exe.py                 # 产物 dist-exe/mitm-ctl.exe
    python tools/build-exe.py --onedir        # 目录版（启动更快）

说明：Windows 上没有 nftables，做不了透明重定向，所以 exe 是「显式代理」模式
     —— 启动后自动把系统代理指向 127.0.0.1:8080，只能抓本机流量。
     （要抓整个局域网需要 WinDivert + 本机做网关 + IP 转发，属另一个量级的工程。）
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 构建中间产物放到系统临时目录：仓库工作区内的文件删除可能被安全策略拦截
BUILD_TMP = os.path.join(tempfile.gettempdir(), "mitm-ctl-exe-build")


def main():
    onedir = "--onedir" in sys.argv
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit("请先安装：pip install pyinstaller cryptography")

    # 被一起打进 exe 的运行期资源
    datas = ["body.html", "panel.html", "index.html", "CHEATSHEET.md"]
    for d in datas:
        if not os.path.isfile(os.path.join(ROOT, d)):
            sys.exit("缺少资源文件：" + d)

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",   # 不加 --clean：它会删除 workpath，在有回收站限制的环境里会失败
        "--onefile" if not onedir else "--onedir",
        "--console",
        "--name", "mitm-ctl",
        "--paths", ROOT,
        "--hidden-import", "mitm_proxy",
        "--hidden-import", "pktcap_server",
        "--distpath", os.path.join(BUILD_TMP, "dist"),
        "--workpath", os.path.join(BUILD_TMP, "work"),
        "--specpath", BUILD_TMP,
    ]
    # 注意：--add-data 的相对路径是相对 spec 目录（build/）解析的，必须给绝对路径
    for d in datas:
        args += ["--add-data", "%s%s." % (os.path.join(ROOT, d), os.pathsep)]

    # Windows 上顺便带个图标（用 iStore 那张，尺寸够）
    ico = os.path.join(ROOT, "icon", "mitm-ctl.ico")
    if os.path.isfile(ico):
        args += ["--icon", ico]

    args.append(os.path.join(ROOT, "windows", "mitmctl.py"))

    print("运行：\n  " + " ".join(args[:8]) + " …\n")
    r = subprocess.run(args, cwd=ROOT)
    if r.returncode != 0:
        sys.exit("PyInstaller 构建失败（退出码 %s）" % r.returncode)

    built = os.path.join(BUILD_TMP, "dist", "mitm-ctl.exe")
    if not os.path.isfile(built):
        sys.exit("构建结束但没找到 exe：" + built)
    dst_dir = os.path.join(ROOT, "dist-exe")
    os.makedirs(dst_dir, exist_ok=True)
    out = os.path.join(dst_dir, "mitm-ctl.exe")
    shutil.copy2(built, out)
    print("\n构建完成：%s（%.1f MB）" % (out, os.path.getsize(out) / 1048576))
    print("直接双击运行，或用： %s --no-proxy" % out)


if __name__ == "__main__":
    main()

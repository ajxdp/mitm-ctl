#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成离线预览副本 + 无头截图，用于校验前端样式（不影响路由器）。
用法：python gen_preview.py [--shot out.png] [--mode list|modal]
"""
import os
import sys
import json
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = "_prev_tmp"


def samples():
    now = time.strftime("%H:%M:%S")
    ts = time.time()
    return [
        {
            "n": 1, "t": now, "ts": ts, "client": "10.0.0.102", "scheme": "https",
            "host": "api.example.com", "port": 443, "method": "GET", "status": "200",
            "target": "/third/forum/recommend_list?page=1&limit=10&type=1",
            "req_headers": {"Host": "api.example.com",
                            "authorization": "07904807a56dd88b469c365813b67ae869b3cee7af4f",
                            "Content-Type": "application/json",
                            "User-Agent": "Mozilla/5.0 (Linux; Android 16; PJX110)",
                            "Accept-Encoding": "gzip"},
            "req_body": "", "req_len": 0, "req_ctype": "",
            "resp_headers": {"Content-Type": "application/json;charset=UTF-8",
                             "Server": "nginx", "Content-Length": "263460"},
            "resp_body": json.dumps({
                "code": 1, "msg": "获取成功",
                "data": {"list": [
                    {"id": 1600, "title": "喜报｜申庭教育获多家权威媒体深度报道", "author": "新华日报",
                     "tags": ["非遗", "教育"], "hot": 2381, "free": True},
                    {"id": 1601, "title": "苏绣技艺传承人访谈：一针一线里的非遗密码", "author": "江苏非遗网",
                     "tags": ["苏绣", "人物"], "hot": 1207, "free": False}],
                    "total": 2, "hasMore": False},
                "timestamp": 1789527308}, ensure_ascii=False, indent=2),
            "resp_len": 263460, "resp_truncated": True,
            "resp_ctype": "application/json;charset=UTF-8",
            "resp_cjk": ["获取成功", "申庭教育获多家权威媒体深度报道", "新华日报", "苏绣技艺传承人访谈"],
        },
        {
            "n": 2, "t": now, "ts": ts, "client": "10.0.0.102", "scheme": "https",
            "host": "api.example.com", "port": 443, "method": "POST", "status": "200",
            "target": "/third/user/login",
            "req_headers": {"Host": "api.example.com", "Content-Type": "application/json"},
            "req_body": '{\n  "phone": "13800000000",\n  "code": "123456"\n}',
            "req_len": 92, "req_ctype": "application/json",
            "resp_headers": {"Content-Type": "application/json"},
            "resp_body": '{"code":1,"msg":"登录成功","data":{"token":"eyJhbGciOi...","uid":8801}}',
            "resp_len": 84, "resp_ctype": "application/json",
            "resp_cjk": ["登录成功"],
        },
        {
            "n": 3, "t": now, "ts": ts, "client": "10.0.0.102", "scheme": "https",
            "host": "wx.qlogo.cn", "port": 443, "method": "GET", "status": "200",
            "target": "/mmhead/Q3auHgzwzM4ib22QDZu1IrNG/132",
            "req_headers": {"Host": "wx.qlogo.cn"}, "req_body": "", "req_len": 0,
            "resp_headers": {"Content-Type": "image/png"},
            "resp_body": None, "resp_len": 20481, "resp_ctype": "image/png", "resp_cjk": [],
        },
        {
            "n": 4, "t": now, "ts": ts, "client": "10.0.0.150", "scheme": "http",
            "host": "cdn.example.com", "port": 80, "method": "GET", "status": "404",
            "target": "/missing.json", "req_headers": {"Host": "cdn.example.com"},
            "req_body": "", "req_len": 0,
            "resp_headers": {"Content-Type": "text/html"},
            "resp_body": "<html><body><h1>404 Not Found</h1><p>页面不存在</p></body></html>",
            "resp_len": 62, "resp_ctype": "text/html", "resp_cjk": ["页面不存在"],
        },
        {
            "n": 5, "t": now, "ts": ts, "client": "10.0.0.102", "scheme": "https",
            "host": "updates.example.org", "port": 443, "method": "POST", "status": "500",
            "target": "/v1/report", "req_headers": {"Host": "updates.example.org"},
            "req_body": '{"err":"timeout"}', "req_len": 17, "req_ctype": "application/json",
            "resp_headers": {"Content-Type": "application/json"},
            "resp_body": '{"error":"internal","trace":"abc"}',
            "resp_len": 41, "resp_ctype": "application/json", "resp_cjk": [],
        },
    ]


FAKE_ES = """<script>
(function(){
  var SAMPLE = %s;
  window.EventSource = function(url){
    var self = this;
    this.readyState = 1;
    this.close = function(){ self.readyState = 2; };
    setTimeout(function(){
      if(self.onopen) self.onopen();
      SAMPLE.forEach(function(d, i){
        setTimeout(function(){ if(self.onmessage) self.onmessage({data: JSON.stringify(d)}); }, 40 + i*70);
      });
    }, 30);
  };
})();
</script>
"""


def build(page, mode):
    src = open(os.path.join(HERE, page), encoding="utf-8").read()
    inject = FAKE_ES % json.dumps(samples(), ensure_ascii=False)
    tail = ""
    if mode == "list":
        tail = ("<script>setTimeout(function(){"
                "var b=document.getElementById('moreBtn'); if(b) b.click();"
                "}, 1000);</script>\n")
    elif mode == "detail":
        tail = ("<script>setTimeout(function(){"
                "var tr=document.querySelector('#tbody tr'); if(tr) tr.click();"
                "}, 1000);</script>\n")
    elif mode == "modal":
        tail = ("<script>setTimeout(function(){"
                "var tr=document.querySelector('#tbody tr'); if(tr) tr.click();"
                "setTimeout(function(){"
                "  var b=document.querySelectorAll('.dactions button[data-act]');"
                "  for(var i=0;i<b.length;i++){ if(b[i].getAttribute('data-act')==='edit'){ b[i].click(); break; } }"
                "}, 500);"
                "}, 1000);</script>\n")
    out = src.replace("<body>", "<body>\n" + inject, 1)
    i = out.rfind("</body>")
    out = out[:i] + tail + out[i:]
    os.makedirs(TMP, exist_ok=True)
    name = "%s_%s.html" % (os.path.splitext(page)[0], mode)
    open(os.path.join(TMP, name), "w", encoding="utf-8").write(out)
    return name


if __name__ == "__main__":
    mode = "list"
    page = "body.html"
    if "--mode" in sys.argv:
        mode = sys.argv[sys.argv.index("--mode") + 1]
    if "--page" in sys.argv:
        page = sys.argv[sys.argv.index("--page") + 1]
    print(build(page, mode))

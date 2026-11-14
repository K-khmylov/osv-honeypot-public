import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

LOG = os.environ.get("WEBTRAP_LOG", "/var/log/webtrap/webtrap.json")
MAX_BODY = 65536
lock = threading.Lock()

STYLE = """<style>body{background:#f0f0f1;font-family:sans-serif}
#box{width:320px;margin:8% auto}form{background:#fff;padding:26px 24px;border:1px solid #c3c4c7}
input{width:100%;padding:6px;margin:4px 0 14px;font-size:18px;box-sizing:border-box}
.btn{background:#2271b1;color:#fff;border:0;padding:8px 12px;font-size:14px;width:auto}
.err{border-left:4px solid #d63638;background:#fff;padding:12px;margin-bottom:16px}</style>"""

WP_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Log In &lsaquo; Firma &#8212; WordPress</title>""" + STYLE + """</head>
<body><div id="box"><h1 style="text-align:center">WordPress</h1>%ERROR%
<form method="post" action="/wp-login.php">
<label>Username or Email Address</label><input name="log" type="text">
<label>Password</label><input name="pwd" type="password">
<input class="btn" type="submit" value="Log In"></form></div></body></html>"""

PMA_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>phpMyAdmin</title>""" + STYLE + """</head>
<body><div id="box"><h1 style="text-align:center">phpMyAdmin</h1>%ERROR%
<form method="post" action="/phpmyadmin/index.php">
<label>Username</label><input name="pma_username" type="text">
<label>Password</label><input name="pma_password" type="password">
<input class="btn" type="submit" value="Log in"></form></div></body></html>"""

INDEX_PAGE = """<!DOCTYPE html><html><head><title>Apache2 Ubuntu Default Page: It works</title></head>
<body><h1>It works!</h1><p>This is the default welcome page used to test the correct
operation of the Apache2 server after installation on Ubuntu systems.</p></body></html>"""

NOT_FOUND = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head>
<title>404 Not Found</title></head><body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p><hr>
<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address></body></html>"""

WP_ERROR = '<div class="err"><b>Error:</b> The password you entered is incorrect.</div>'
PMA_ERROR = '<div class="err">Cannot log in to the MySQL server</div>'


class Trap(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def record(self, eventid, **extra):
        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "eventid": eventid,
            "src_ip": self.client_address[0],
            "method": self.command,
            "path": self.path[:500],
            "user_agent": self.headers.get("User-Agent", "")[:300],
        }
        rec.update(extra)
        with lock, open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def reply(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def page_for(self, path):
        p = path.split("?")[0].lower()
        if p == "/":
            return INDEX_PAGE
        if p.startswith("/wp-login") or p.startswith("/wp-admin"):
            return WP_PAGE.replace("%ERROR%", "")
        if p.startswith("/phpmyadmin") or p.startswith("/pma"):
            return PMA_PAGE.replace("%ERROR%", "")
        return None

    def do_GET(self):
        self.record("web.request")
        page = self.page_for(self.path)
        self.reply(200, page) if page else self.reply(404, NOT_FOUND)

    def do_POST(self):
        length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(body)
        p = self.path.split("?")[0].lower()
        if p.startswith("/wp-login"):
            self.record("web.login", app="wordpress",
                        username=form.get("log", [""])[0][:200],
                        password=form.get("pwd", [""])[0][:200])
            self.reply(200, WP_PAGE.replace("%ERROR%", WP_ERROR))
        elif p.startswith("/phpmyadmin") or p.startswith("/pma"):
            self.record("web.login", app="phpmyadmin",
                        username=form.get("pma_username", [""])[0][:200],
                        password=form.get("pma_password", [""])[0][:200])
            self.reply(200, PMA_PAGE.replace("%ERROR%", PMA_ERROR))
        else:
            self.record("web.request", body=body[:500])
            self.reply(404, NOT_FOUND)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Trap).serve_forever()

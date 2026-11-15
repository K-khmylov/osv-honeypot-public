import html
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
LOG = os.environ.get("COWRIE_LOG", "/var/log/cowrie/cowrie.json")
GEOIP_DB = os.environ.get("GEOIP_DB", "/etc/geoip/GeoLite2-City.mmdb")
LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")
SPIKE_THRESHOLD = int(os.environ.get("SPIKE_THRESHOLD", "50"))
SPIKE_WINDOW = 600
COOLDOWN = int(os.environ.get("ALERT_COOLDOWN", "1800"))
DIGEST_TIME = os.environ.get("DIGEST_TIME", "20:00")
TZ = ZoneInfo(os.environ.get("TZ_NAME", "Europe/Bratislava"))
API = f"https://api.telegram.org/bot{TOKEN}"
VT_URL = "https://www.virustotal.com/gui/file/"

# period key -> (Loki range, heading text)
PERIODS = {
    "24h": ("24h", "posledných 24 hodín"),
    "7d": ("168h", "posledných 7 dní"),
    "30d": ("720h", "posledných 30 dní"),
}
BUTTONS = [("24h", "1 deň"), ("7d", "7 dní"), ("30d", "30 dní")]

try:
    import maxminddb
    geo = maxminddb.open_database(GEOIP_DB)
except Exception as exc:
    print("GeoIP disabled:", exc, flush=True)
    geo = None


def country(ip):
    if geo is None:
        return "?"
    try:
        rec = geo.get(ip) or {}
        return rec.get("country", {}).get("iso_code", "?")
    except Exception:
        return "?"


def flag(cc):
    """ISO country code -> flag emoji (BG -> two regional indicator letters)."""
    if len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in cc.upper())
    return "\U0001F3F3️"


def fmt(n):
    return f"{n:,}".replace(",", " ")


# ---------- Telegram API ----------

def tg(method, params, timeout=10):
    data = urllib.parse.urlencode(params).encode()
    with urllib.request.urlopen(f"{API}/{method}", data, timeout=timeout) as resp:
        return json.load(resp)


def _params(text, buttons, parse_html):
    params = {"chat_id": CHAT_ID, "text": text[:4000], "disable_web_page_preview": "true"}
    if parse_html:
        params["parse_mode"] = "HTML"
    if buttons:
        params["reply_markup"] = json.dumps({"inline_keyboard": buttons})
    return params


def send(text, buttons=None, parse_html=False):
    try:
        return tg("sendMessage", _params(text, buttons, parse_html))["result"]["message_id"]
    except urllib.error.HTTPError as exc:
        print("Telegram error:", exc.read().decode(errors="replace"), flush=True)
    except Exception as exc:
        print("Telegram error:", exc, flush=True)
    return None


def edit(message_id, text, buttons=None, parse_html=False):
    params = _params(text, buttons, parse_html)
    params["message_id"] = message_id
    try:
        tg("editMessageText", params)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        if "not modified" not in body:
            print("Edit error:", body, flush=True)
    except Exception as exc:
        print("Edit error:", exc, flush=True)


# ---------- statistics from Loki ----------

def loki(query):
    url = LOKI_URL + "/loki/api/v1/query?" + urllib.parse.urlencode({"query": query})
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.load(resp)["data"]["result"]


def scalar(query):
    res = loki(query)
    return int(float(res[0]["value"][1])) if res else 0


def top_items(query, label, n=5):
    res = loki(query)
    items = sorted(
        ((r["metric"].get(label, "?"), int(float(r["value"][1]))) for r in res),
        key=lambda x: -x[1],
    )
    return items[:n]


def ranked(items):
    if not items:
        return ["–"]
    return [f"{i}. <code>{html.escape(k) or '(prázdne)'}</code> – {fmt(v)}"
            for i, (k, v) in enumerate(items, 1)]


def build_stats(period):
    rng, label = PERIODS[period]
    c = '{job="cowrie", eventid="cowrie.session.connect"}'
    s = '{job="cowrie", eventid="cowrie.login.success"}'
    cmd = '{job="cowrie", eventid="cowrie.command.input"}'
    logins = '{job="cowrie", eventid=~"cowrie.login.(success|failed)"}'
    web = '{job="webtrap", eventid="web.login"}'
    dl = '{job="cowrie", eventid="cowrie.session.file_download"}'

    connects = scalar(f"sum(count_over_time({c}[{rng}]))")
    ips = scalar(f"count(sum by (src_ip) (count_over_time({c} | json [{rng}])))")
    success = scalar(f"sum(count_over_time({s}[{rng}]))")
    commands = scalar(f"sum(count_over_time({cmd}[{rng}]))")
    web_logins = scalar(f"sum(count_over_time({web}[{rng}]))")
    files = scalar(f"sum(count_over_time({dl}[{rng}]))")
    files_unique = scalar(f'count(sum by (shasum) (count_over_time({dl} | json shasum="shasum" [{rng}])))')
    countries = top_items(f"sum by (country) (count_over_time({c}[{rng}]))", "country")
    passwords = top_items(f"sum by (password) (count_over_time({logins} | json [{rng}]))", "password")
    users = top_items(f"sum by (username) (count_over_time({logins} | json [{rng}]))", "username")
    files_top = top_items(f'sum by (shasum) (count_over_time({dl} | json shasum="shasum" [{rng}]))', "shasum", 3)

    lines = [
        f"\U0001F4CA <b>Štatistika – {label}</b>",
        "",
        f"\U0001F50C Pripojenia: <b>{fmt(connects)}</b>",
        f"\U0001F310 Unikátne IP: <b>{fmt(ips)}</b>",
        f"\U0001F513 Prihlásenia do pasce: <b>{fmt(success)}</b>",
        f"⌨️ Zadané príkazy: <b>{fmt(commands)}</b>",
        f"\U0001F578️ Web pasca – prihlásenia: <b>{fmt(web_logins)}</b>",
        f"☣️ Súbory v karanténe: <b>{fmt(files)}</b> (unikátne: {fmt(files_unique)})",
        "",
        "\U0001F30D <b>Top krajiny</b>",
    ]
    lines += [f"{flag(k)} {html.escape(k)} – {fmt(v)}" for k, v in countries] or ["–"]
    lines += ["", "\U0001F511 <b>Top heslá</b>"] + ranked(passwords)
    lines += ["", "\U0001F464 <b>Top mená</b>"] + ranked(users)
    if files_top:
        lines += ["", "☣️ <b>Top súbory</b> (odkaz na VirusTotal)"]
        lines += [f'{n}. <a href="{VT_URL}{html.escape(h)}">{html.escape(h[:12])}…</a> – {fmt(v)}'
                  for n, (h, v) in enumerate(files_top, 1)]
    lines += ["", f"\U0001F552 <i>Aktualizované {datetime.now(TZ):%d.%m. %H:%M}</i>"]
    return "\n".join(lines)


def stats_buttons(active):
    return [[{"text": ("✅ " if key == active else "") + text,
              "callback_data": f"stats:{key}"} for key, text in BUTTONS]]


def show_stats(period, message_id=None):
    loading = "⏳ Počítam…"
    if message_id is None:
        message_id = send(loading)
        if message_id is None:
            return
    else:
        edit(message_id, loading)
    try:
        text = build_stats(period)
    except Exception as exc:
        print("Stats error:", repr(exc), flush=True)
        edit(message_id, "⚠️ Štatistiku sa nepodarilo vytvoriť", stats_buttons(period))
        return
    edit(message_id, text, stats_buttons(period), parse_html=True)


def digest_loop():
    hour, minute = (int(x) for x in DIGEST_TIME.split(":"))
    while True:
        now = datetime.now(TZ)
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        time.sleep((target - now).total_seconds())
        show_stats("24h")


# ---------- Telegram commands and buttons ----------

HELP_TEXT = ("Príkazy:\n"
             "/stats – štatistika (1 deň, 7 dní, 30 dní)\n"
             "/help – zoznam príkazov")


def commands_loop():
    offset = None
    while True:
        params = {"timeout": 50}
        if offset is not None:
            params["offset"] = offset
        try:
            updates = tg("getUpdates", params, timeout=60).get("result", [])
        except Exception as exc:
            print("Polling error:", exc, flush=True)
            time.sleep(5)
            continue
        for upd in updates:
            offset = upd["update_id"] + 1
            try:
                handle_update(upd)
            except Exception as exc:
                print("Update error:", repr(exc), flush=True)


def handle_update(upd):
    cq = upd.get("callback_query")
    if cq:
        msg = cq.get("message", {})
        try:
            tg("answerCallbackQuery", {"callback_query_id": cq["id"]})
        except Exception:
            pass
        data = cq.get("data", "")
        if str(msg.get("chat", {}).get("id")) == str(CHAT_ID) and data.startswith("stats:"):
            period = data.split(":", 1)[1]
            if period in PERIODS:
                show_stats(period, msg.get("message_id"))
        return

    msg = upd.get("message") or {}
    if str(msg.get("chat", {}).get("id")) != str(CHAT_ID):
        return
    cmd = (msg.get("text") or "").strip().split("@")[0]
    if cmd == "/stats":
        show_stats("24h")
    elif cmd in ("/start", "/help"):
        send(HELP_TEXT)


# ---------- real-time alerts (reads Cowrie log) ----------

def follow(path):
    """Read new lines from the log, survive daily rotation."""
    f, inode, buf = None, None, ""
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(2)
            continue
        if f is None or st.st_ino != inode:
            if f:
                f.close()
            f = open(path, "r", encoding="utf-8", errors="replace")
            if inode is None:
                f.seek(0, os.SEEK_END)
            inode, buf = st.st_ino, ""
        elif st.st_size < f.tell():
            f.seek(0)
            buf = ""
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith("\n"):
                yield buf
                buf = ""
        else:
            time.sleep(1)


last_alert = {}


def cooldown_ok(key):
    now = time.time()
    if now - last_alert.get(key, 0) >= COOLDOWN:
        last_alert[key] = now
        return True
    return False


def main():
    threading.Thread(target=digest_loop, daemon=True).start()
    threading.Thread(target=commands_loop, daemon=True).start()
    sessions = {}
    attempts = deque()
    send(f"\U0001F7E2 Honeypot bot spustený)"
    for raw in follow(LOG):
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        eid = e.get("eventid", "")
        sid = e.get("session")
        ip = e.get("src_ip", "?")
        if len(sessions) > 5000:
            sessions.clear()
        s = sessions.setdefault(sid, {"ip": ip, "user": None, "pw": None, "cmds": [], "ok": False})

        if eid in ("cowrie.login.failed", "cowrie.login.success"):
            now = time.time()
            attempts.append(now)
            while attempts and now - attempts[0] > SPIKE_WINDOW:
                attempts.popleft()
            if len(attempts) >= SPIKE_THRESHOLD and cooldown_ok("spike"):
                send(f"\U0001F4C8 Nárast útokov: {len(attempts)} pokusov o prihlásenie za posledných 10 minút")

        if eid == "cowrie.login.success":
            s.update(user=e.get("username"), pw=e.get("password"), ok=True)
        elif eid == "cowrie.command.input":
            s["cmds"].append(e.get("input") or "")
        elif eid == "cowrie.session.file_download":
            sha = e.get("shasum", "")
            source = e.get("url") or e.get("destfile") or e.get("outfile") or "príkaz v termináli"
            send(f"☣️ Útočník {ip} {flag(country(ip))} uložil súbor do pasce\n"
                 f"Zdroj: {source}\n"
                 f"SHA256: {sha or '?'}\n"
                 f"VirusTotal: {VT_URL}{sha}")
        elif eid == "cowrie.session.closed":
            s = sessions.pop(sid, None)
            if s and s["ok"] and cooldown_ok(("session", s["ip"])):
                cmds = s["cmds"]
                preview = "\n".join(f"$ {c[:120]}" for c in cmds[:10])
                more = f"\n… a ďalších {len(cmds) - 10}" if len(cmds) > 10 else ""
                cc = country(s["ip"])
                send(f"\U0001F513 Prihlásenie do pasce\n"
                     f"IP: {s['ip']} {flag(cc)} {cc}\n"
                     f"Účet: {s['user']} / {s['pw']}\n"
                     f"Príkazy: {len(cmds)}\n{preview}{more}")


if __name__ == "__main__":
    main()

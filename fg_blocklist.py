#!/usr/bin/env python3
"""fg_blocklist.py - nạp danh sách chặn (StevenBlack + domain bổ sung) vào FamilyGuard
qua TCP/9000 (NDJSON, lệnh ADD_BLACKLIST). KHÔNG sửa dns_forwarder.cpp.

Chạy một lần (nên chạy NGAY TRÊN VPS, host 127.0.0.1):
    python3 fg_blocklist.py
Chạy nền, tự nạp lại khi daemon restart hoặc app Parent ghi đè blacklist:
    python3 fg_blocklist.py --daemon
Chỉ tạo file domain, không động tới server:
    python3 fg_blocklist.py --dry-run

Nếu server yêu cầu AUTH: đặt biến môi trường FG_AUTH_JSON='{"action":"AUTH",...}'
(đúng như JavaFX gửi). Script không chứa mật khẩu nào.
"""
import argparse
import collections
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

STEVENBLACK_URL = ("https://raw.githubusercontent.com/StevenBlack/hosts/master/"
                   "alternates/fakenews-gambling-porn/hosts")
HERE = os.path.dirname(os.path.abspath(__file__))
LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
SKIP_NAMES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
    "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
    "ip6-allhosts", "0.0.0.0",
}


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


# ----------------------------------------------------------------- domain utils
def norm(d):
    d = d.strip().lower()
    return d[:-1] if d.endswith(".") else d


def valid(d):
    """Cùng luật với is_valid_domain() của server: <=253 ký tự, nhãn <=63, chỉ a-z 0-9 '-'."""
    if not d or len(d) > 253 or "." not in d:
        return False
    return all(LABEL_RE.match(label) for label in d.split("."))


def is_ip(s):
    try:
        ipaddress.ip_address(s.split("%")[0])
        return True
    except ValueError:
        return False


def covered(d, S):
    """True nếu d hoặc một domain cha của d nằm trong S."""
    parts = d.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in S:
            return True
    return False


def parse_hosts(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        p = line.split()
        if len(p) < 2 or p[0] not in ("0.0.0.0", "127.0.0.1"):
            continue
        out.extend(p[1:])
    return out


def parse_plain(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("*."):
            line = line[2:]
        if line:
            out.append(line.split()[0])
    return out


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def fetch_hosts(args):
    cache = args.cache
    if not args.offline:
        try:
            log(f"Tải {args.source}")
            req = urllib.request.Request(args.source, headers={"User-Agent": "fg-blocklist/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read().decode("utf-8", errors="replace")
            if "0.0.0.0" not in data:
                raise ValueError("nội dung tải về không giống file hosts")
            tmp = cache + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(data)
            os.replace(tmp, cache)
            return data
        except Exception as e:  # noqa: BLE001
            log(f"CẢNH BÁO: không tải được ({e}).")
            if not os.path.exists(cache):
                raise SystemExit("Không có bản cache để dùng. Thêm --source <file> hoặc kiểm tra mạng.")
            log(f"Dùng bản cache {cache}")
    return read_text(cache)


def build_list(args):
    stats = collections.OrderedDict()
    hosts_text = read_text(args.source) if os.path.isfile(args.source) else fetch_hosts(args)
    raw = parse_hosts(hosts_text)
    stats["dòng domain trong hosts"] = len(raw)
    extra = []
    for path in args.extra:
        if os.path.exists(path):
            extra += parse_plain(read_text(path))
        else:
            log(f"CẢNH BÁO: không thấy file bổ sung {path}")
    stats["domain bổ sung"] = len(extra)

    seen, domains, bad = set(), [], []
    for d in raw + extra:
        d = norm(d)
        if d in SKIP_NAMES or is_ip(d):
            continue
        if not valid(d):
            bad.append(d)
            continue
        if d not in seen:
            seen.add(d)
            domains.append(d)
    stats["bỏ vì sai định dạng (server cũng từ chối)"] = len(bad)
    stats["domain duy nhất hợp lệ"] = len(domains)

    allow = set()
    for path in args.allow:
        if os.path.exists(path):
            allow |= {norm(x) for x in parse_plain(read_text(path))}
    if allow:
        before = len(domains)
        domains = [d for d in domains if not covered(d, allow)]
        stats["loại theo allow.txt"] = before - len(domains)

    if args.compress:
        before = len(domains)
        kept = set()
        for d in sorted(domains, key=lambda x: x.count(".")):
            if not covered(d, kept):
                kept.add(d)
        domains = sorted(kept)
        stats["gộp (bỏ subdomain đã được domain cha phủ)"] = before - len(domains)

    if args.max:
        domains = domains[: args.max]
    stats["SẼ NẠP"] = len(domains)
    return domains, stats, bad


# ----------------------------------------------------------------- server I/O
class Conn:
    def __init__(self, host, port, timeout=20):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""
        self.pushed = 0  # số bản tin SYNC_* server tự đẩy trên kết nối này

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def send(self, objs):
        data = b"".join(json.dumps(o, separators=(",", ":"), ensure_ascii=False).encode() + b"\n" for o in objs)
        self.s.sendall(data)

    def _line(self):
        while b"\n" not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("server đã đóng kết nối")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        try:
            return json.loads(line)
        except ValueError:
            return {"success": False, "error": "BAD_JSON_FROM_SERVER"}

    def replies(self, n):
        out = []
        while len(out) < n:
            o = self._line()
            if str(o.get("action", "")).startswith("SYNC_"):
                self.pushed += 1  # bản tin đồng bộ tự đẩy, không phải trả lời lệnh
                continue
            out.append(o)
        return out

    def request(self, obj):
        self.send([obj])
        return self.replies(1)[0]


def find_key(o, key):
    if isinstance(o, dict):
        if key in o:
            return o[key]
        for v in o.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def open_conn(args):
    c = Conn(args.host, args.port)
    auth = os.environ.get("FG_AUTH_JSON")
    if auth:
        r = c.request(json.loads(auth))
        if r.get("success") is not True:
            c.close()
            raise SystemExit(f"AUTH thất bại: {r}")
    return c


def server_rss_mb():
    """RSS (MB) của dns_forwarder nếu chạy trên cùng máy; None nếu không đọc được."""
    try:
        pid = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "familyguard.service"],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        if not pid or pid == "0":
            pid = subprocess.run(["pgrep", "-x", "dns_forwarder"], capture_output=True, text=True,
                                 timeout=5).stdout.split()[0]
        for line in open(f"/proc/{int(pid)}/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except Exception:  # noqa: BLE001
        return None
    return None


def push(c, domains, args):
    ok = fail = 0
    errors = collections.Counter()
    t0 = time.time()
    # Thăm dò 1 domain trước: sai tên trường/handler thì dừng ngay, không bắn 160k lệnh lỗi.
    first = c.request({"action": "ADD_BLACKLIST", args.field: domains[0]})
    if first.get("success") is not True:
        raise SystemExit(
            f"Server từ chối lệnh thăm dò ADD_BLACKLIST: {first}\n"
            f"-> Kiểm tra tên trường: grep -n -A14 '\"ADD_BLACKLIST\"' dns_forwarder.cpp, rồi chạy lại với --field <tên>.")
    ok += 1
    rest = domains[1:]
    for i in range(0, len(rest), args.chunk):
        part = rest[i:i + args.chunk]
        c.send([{"action": "ADD_BLACKLIST", args.field: d} for d in part])
        for r in c.replies(len(part)):
            if r.get("success") is True:
                ok += 1
            else:
                fail += 1
                errors[str(r.get("error", "?"))] += 1
        done = i + len(part) + 1
        if (i // args.chunk) % 200 == 0:
            log(f"  đã gửi {done}/{len(domains)}")
    return ok, fail, errors, time.time() - t0


def load_once(args, domains):
    rss0 = server_rss_mb()
    with open_conn(args) as c:
        st = c.request({"action": "GET_STATUS"})
        before = find_key(st, "blacklist_count")
        log(f"Trạng thái trước: blacklist_count={before}, filter_enabled={find_key(st, 'filter_enabled')}")
        ok, fail, errors, secs = push(c, domains, args)
        after = find_key(c.request({"action": "GET_STATUS"}), "blacklist_count")
        pushed = c.pushed
    rss1 = server_rss_mb()
    log(f"Xong sau {secs:.1f}s: thành công {ok}, lỗi {fail}" + (f" {dict(errors)}" if errors else ""))
    log(f"blacklist_count: {before} -> {after}")
    if rss0 is not None and rss1 is not None:
        log(f"RAM dns_forwarder (RSS): {rss0:.1f} MB -> {rss1:.1f} MB (+{rss1 - rss0:.1f} MB)")
    else:
        log("RAM: không đọc được (chạy script trên VPS để đo). Tự kiểm tra: ps -o rss= -p $(pidof dns_forwarder)")
    if pushed:
        log(f"LƯU Ý: kết nối này nhận {pushed} bản tin SYNC_* server tự đẩy; log trong lô đó có thể không tới Parent. "
            f"Hãy chạy trên VPS (127.0.0.1) hoặc tăng --chunk để nạp dưới 60 giây.")
    elif secs > 45:
        log("CẢNH BÁO: nạp mất > 45s, gần chu kỳ đồng bộ 60s của server. Nên chạy trên VPS.")
    return fail == 0 and (after is None or before is None or after >= before)


def daemon(args):
    domains, stats, _ = build_list(args)
    threshold = int(len(domains) * 0.9)
    last_refresh = time.time()
    log(f"Chế độ nền: kiểm tra mỗi {args.interval}s; nạp lại khi blacklist_count < {threshold}")
    delay = 5
    while True:
        try:
            if args.refresh_hours and time.time() - last_refresh > args.refresh_hours * 3600:
                domains, stats, _ = build_list(args)
                threshold = int(len(domains) * 0.9)
                last_refresh = time.time()
                load_once(args, domains)
            with open_conn(args) as c:
                cnt = find_key(c.request({"action": "GET_STATUS"}), "blacklist_count")
            if cnt is None:
                raise SystemExit("GET_STATUS không có blacklist_count; dùng chế độ chạy một lần.")
            if cnt < threshold:
                log(f"blacklist_count={cnt} < {threshold}: nạp lại danh sách")
                load_once(args, domains)
            delay = 5
            time.sleep(args.interval)
        except (OSError, ConnectionError) as e:
            log(f"Chưa kết nối được ({e}); thử lại sau {delay}s")
            time.sleep(delay)
            delay = min(delay * 2, 60)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--field", default="domain", help="tên trường domain trong ADD_BLACKLIST (mặc định: domain)")
    ap.add_argument("--source", default=STEVENBLACK_URL, help="URL hoặc đường dẫn file hosts")
    ap.add_argument("--cache", default=os.path.join(HERE, "hosts.txt"))
    ap.add_argument("--offline", action="store_true", help="chỉ dùng file cache, không tải")
    ap.add_argument("--extra", action="append", default=None, help="file domain bổ sung (mặc định extra_domains.txt)")
    ap.add_argument("--allow", action="append", default=None, help="file domain KHÔNG được chặn (mặc định allow.txt)")
    ap.add_argument("--compress", action="store_true",
                    help="bỏ subdomain đã có domain cha trong danh sách (chỉ an toàn nếu server khớp suffix)")
    ap.add_argument("--chunk", type=int, default=100, help="số lệnh mỗi lần gửi (mặc định 100)")
    ap.add_argument("--max", type=int, default=0, help="chỉ nạp N domain đầu (để thử)")
    ap.add_argument("--dry-run", action="store_true", help="chỉ ghi file domain, không kết nối server")
    ap.add_argument("--out", default=os.path.join(HERE, "domains.txt"))
    ap.add_argument("--daemon", action="store_true")
    ap.add_argument("--interval", type=int, default=120)
    ap.add_argument("--refresh-hours", type=int, default=24)
    args = ap.parse_args()
    args.extra = args.extra or [os.path.join(HERE, "extra_domains.txt")]
    args.allow = args.allow or [os.path.join(HERE, "allow.txt")]

    if args.daemon:
        return daemon(args)

    domains, stats, bad = build_list(args)
    for k, v in stats.items():
        log(f"{k}: {v}")
    if bad:
        log(f"  ví dụ domain bị bỏ: {bad[:5]}")
    if not domains:
        raise SystemExit("Danh sách rỗng.")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(domains) + "\n")
    log(f"Đã ghi {args.out}")
    if args.dry_run:
        return 0
    try:
        good = load_once(args, domains)
    except (OSError, ConnectionError) as e:
        raise SystemExit(f"Không kết nối được {args.host}:{args.port}: {e}")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())

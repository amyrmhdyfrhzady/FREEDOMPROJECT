import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import threading
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "configs"
WORK = ROOT / ".work"
OUTPUT = ROOT / "output"
PROTO = ("vmess", "vless", "trojan", "ss", "ssr", "tuic", "hysteria2", "socks")
MAX_EXTERNAL = max(0, int(os.getenv("MAX_EXTERNAL", "2500")))
MAX_PER_PROTOCOL = max(0, int(os.getenv("MAX_PER_PROTOCOL", "100")))
WORKERS = max(1, int(os.getenv("VALIDATION_WORKERS", "24")))
TIMEOUT = max(2, int(os.getenv("VALIDATION_TIMEOUT", "8")))
HISTORY_LIMIT = max(1, int(os.getenv("HISTORY_LIMIT", "30")))
LOG_LOCK = threading.Lock()


def log(message):
    with LOG_LOCK:
        print(message, flush=True)


def read_sources():
    path = CONFIGS / "external-sources.list"
    if not path.exists():
        raise RuntimeError("configs/external-sources.list is missing")
    values, seen = [], set()
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        value = raw.strip()
        if not value or value.startswith("#") or value in seen:
            continue
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue
        seen.add(value)
        values.append(value)
    return values


def download():
    WORK.mkdir(exist_ok=True)
    folder = WORK / "external"
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    sources = read_sources()
    statuses = []
    for index, url in enumerate(sources, 1):
        target = folder / f"external_{index:04d}.txt"
        status = {"url": url, "status": "failed", "bytes": 0}
        for attempt in range(3):
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "FreedomSubscription/2.0"})
                with urllib.request.urlopen(request, timeout=20) as response:
                    if response.status != 200:
                        raise RuntimeError(f"HTTP {response.status}")
                    data = response.read(20 * 1024 * 1024 + 1)
                    if len(data) > 20 * 1024 * 1024:
                        raise RuntimeError("file exceeds 20 MiB")
                    if not data:
                        raise RuntimeError("empty response")
                    target.write_bytes(data)
                status.update(status="success", bytes=len(data))
                break
            except Exception as exc:
                status["error"] = str(exc)[:180]
                time.sleep(attempt + 1)
        statuses.append(status)
    (WORK / "download_status.json").write_text(json.dumps(statuses, ensure_ascii=False, indent=2), encoding="utf-8")
    successful = sum(x["status"] == "success" for x in statuses)
    print(f"Sources: {len(statuses)}, successful: {successful}")
    if sources and successful == 0:
        raise RuntimeError("all external sources failed; previous subscriptions were not changed")


def decode_base64_text(text):
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 16 or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        return None
    compact += "=" * ((4 - len(compact) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            result = decoder(compact + "==")
            decoded = result.decode("utf-8-sig", errors="strict")
            if re.search(r"(?im)^(?:vmess|vless|trojan|ss|ssr|tuic|hysteria2|hy2|socks5|socks)://", decoded):
                return decoded
            if "proxies:" in decoded or "outbounds:" in decoded:
                return decoded
        except Exception:
            pass
    return None


def parse_uri(uri):
    uri = uri.strip()
    match = re.match(r"^(vmess|vless|trojan|ss|ssr|tuic|hysteria2|hy2|socks5|socks)://", uri, re.I)
    if not match:
        return None
    proto = match.group(1).lower()
    try:
        parsed = urllib.parse.urlsplit(uri)
        # Accessing hostname/port can also raise ValueError for malformed IPv6.
        _ = parsed.hostname
        _ = parsed.port
    except ValueError:
        return None
    if proto == "hy2":
        proto = "hysteria2"
    if proto == "socks5":
        proto = "socks"
    if proto == "ssr":
        payload = uri.split("://", 1)[1].split("#", 1)[0].split("/?", 1)[0]
        try:
            decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
            core = decoded.split("/?", 1)[0].split("/", 1)[0]
            parts = core.split(":", 5)
            if len(parts) != 6:
                return None
            host, port = parts[0], int(parts[1])
            return {"uri": uri, "protocol": proto, "host": host, "port": port, "name": urllib.parse.unquote(parsed.fragment)}
        except Exception:
            return None
    if proto == "vmess":
        payload = uri.split("://", 1)[1].split("#", 1)[0]
        try:
            raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
            obj = json.loads(raw)
            host = obj.get("add") or obj.get("host")
            port = int(obj.get("port"))
            if not host or not port:
                return None
            return {"uri": uri, "protocol": proto, "host": host, "port": port, "name": obj.get("ps", "")}
        except Exception:
            return None
    try:
        parsed = urllib.parse.urlsplit(uri)
        if proto == "ss":
            authority = parsed.netloc.rsplit("@", 1)
            if len(authority) == 2:
                serverpart = authority[1]
                host, port = serverpart.rsplit(":", 1)
            else:
                raw = parsed.netloc
                decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
                hostpart = decoded.rsplit("@", 1)[-1]
                host, port = hostpart.rsplit(":", 1)
            return {"uri": uri, "protocol": proto, "host": host.strip("[]"), "port": int(port), "name": urllib.parse.unquote(parsed.fragment)}
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        return {"uri": uri, "protocol": proto, "host": host, "port": port, "name": urllib.parse.unquote(parsed.fragment), "username": urllib.parse.unquote(parsed.username or ""), "password": urllib.parse.unquote(parsed.password or ""), "query": urllib.parse.parse_qs(parsed.query)}
    except Exception:
        return None


def quote(value):
    return urllib.parse.quote(str(value), safe="")


def clash_to_uri(item):
    if not isinstance(item, dict):
        return None
    kind = str(item.get("type", "")).lower()
    name = quote(item.get("name", ""))
    server = item.get("server")
    port = item.get("port")
    if not server or not port:
        return None
    q = {}
    if kind == "vmess":
        ws_opts = item.get("ws-opts") or {}
        obj = {"v": "2", "ps": item.get("name", ""), "add": server, "port": str(port), "id": item.get("uuid", ""), "aid": str(item.get("alterId", 0)), "scy": item.get("cipher", "auto"), "net": item.get("network", "tcp"), "type": "none", "host": item.get("servername", ws_opts.get("headers", {}).get("Host", "")), "path": ws_opts.get("path", ""), "tls": "tls" if item.get("tls") else ""}
        encoded = base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()
        return "vmess://" + encoded
    if kind in ("vless", "trojan"):
        user = item.get("uuid", "") if kind == "vless" else item.get("password", "")
        q["type"] = item.get("network", "tcp")
        if item.get("reality-opts"):
            reality = item.get("reality-opts", {})
            q["security"] = "reality"
            q["pbk"] = reality.get("public-key", "")
            q["sid"] = reality.get("short-id", "")
            q["sni"] = item.get("servername", "")
            q["fp"] = item.get("client-fingerprint", "chrome")
        elif item.get("tls"):
            q["security"] = "tls"
            if item.get("servername"):
                q["sni"] = item["servername"]
            if item.get("client-fingerprint"):
                q["fp"] = item["client-fingerprint"]
        if item.get("flow"):
            q["flow"] = item["flow"]
        if item.get("network") == "ws":
            ws = item.get("ws-opts") or {}
            q["path"] = ws.get("path", "/")
            headers = ws.get("headers", {})
            if headers.get("Host"):
                q["host"] = headers["Host"]
        return f"{kind}://{quote(user)}@{server}:{port}?{urllib.parse.urlencode(q)}#{name}"
    if kind in ("ss", "ssr"):
        if kind == "ssr":
            password = base64.urlsafe_b64encode(str(item.get("password", "")).encode()).decode().rstrip("=")
            remarks = base64.urlsafe_b64encode(str(item.get("name", "")).encode()).decode().rstrip("=")
            fields = [server, str(port), str(item.get("protocol", "origin")), str(item.get("cipher", "aes-128-ctr")), str(item.get("obfs", "plain")), password]
            query = urllib.parse.urlencode({"remarks": remarks, "protoparam": base64.urlsafe_b64encode(str(item.get("protocol-param", "")).encode()).decode().rstrip("="), "obfsparam": base64.urlsafe_b64encode(str(item.get("obfs-param", "")).encode()).decode().rstrip("=")})
            payload = base64.urlsafe_b64encode(":".join(fields).encode()).decode().rstrip("=")
            return "ssr://" + payload + "/?" + query
        method, password = item.get("cipher", ""), item.get("password", "")
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port}#{name}"
    if kind in ("hysteria2", "hy2"):
        password = item.get("password", "")
        if item.get("sni"):
            q["sni"] = item["sni"]
        if item.get("skip-cert-verify"):
            q["insecure"] = "1"
        if item.get("obfs"):
            q["obfs"] = item["obfs"]
        if item.get("obfs-password"):
            q["obfs-password"] = item["obfs-password"]
        return f"hysteria2://{quote(password)}@{server}:{port}?{urllib.parse.urlencode(q)}#{name}"
    if kind == "tuic":
        q["congestion_control"] = item.get("congestion-controller", "bbr")
        q["udp_relay_mode"] = item.get("udp-relay-mode", "native")
        if item.get("sni"):
            q["sni"] = item["sni"]
        return f"tuic://{quote(item.get('uuid',''))}:{quote(item.get('password',''))}@{server}:{port}?{urllib.parse.urlencode(q)}#{name}"
    if kind in ("socks5", "socks"):
        auth = ""
        if item.get("username"):
            auth = quote(item["username"]) + ":" + quote(item.get("password", "")) + "@"
        return f"socks://{auth}{server}:{port}#{name}"
    return None


def extract_text(text, source, personal):
    text = text.lstrip("\ufeff")
    records = []
    for line in text.splitlines():
        line = line.strip().strip("\x00")
        if not line:
            continue
        parsed = parse_uri(line)
        if parsed:
            records.append({**parsed, "source": source, "personal": personal})
    if records:
        return records
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            for node in data["proxies"]:
                uri = clash_to_uri(node)
                parsed = parse_uri(uri) if uri else None
                if parsed:
                    records.append({**parsed, "source": source, "personal": personal})
    except Exception:
        pass
    if records:
        return records
    decoded = decode_base64_text(text)
    if decoded and decoded != text:
        return extract_text(decoded, source, personal)
    return records


def parse_all():
    WORK.mkdir(exist_ok=True)
    personal = []
    personal_files = [p for p in CONFIGS.glob("*.txt") if not re.fullmatch(r"external_\d+\.txt", p.name)]
    def commit_time(path):
        result = subprocess.run(["git", "log", "-1", "--format=%ct", "--", str(path.relative_to(ROOT))], cwd=ROOT, capture_output=True, text=True)
        try:
            return int(result.stdout.strip())
        except Exception:
            return 0
    personal_files.sort(key=lambda p: (commit_time(p), p.name), reverse=True)
    for path in personal_files:
        try:
            personal.extend(extract_text(path.read_text(encoding="utf-8", errors="ignore"), path.name, True))
        except OSError:
            continue
    external = []
    ext_dir = WORK / "external"
    if ext_dir.exists():
        for path in sorted(ext_dir.glob("*.txt")):
            try:
                external.extend(extract_text(path.read_text(encoding="utf-8", errors="ignore"), path.name, False))
            except OSError:
                continue
    log(f"[PARSE] Extracted before deduplication: personal={len(personal)}, external={len(external)}, total={len(personal) + len(external)}")
    unique_personal, unique_external, raw_records, seen = [], [], [], set()
    for record in personal + external:
        try:
            parsed_uri = urllib.parse.urlsplit(record["uri"])
            canonical = urllib.parse.urlunsplit((parsed_uri.scheme.lower(), parsed_uri.netloc, parsed_uri.path, "&".join(sorted(parsed_uri.query.split("&"))) if parsed_uri.query else "", ""))
        except ValueError:
            continue
        if record["protocol"] == "vmess":
            payload = record["uri"].split("://", 1)[1].split("#", 1)[0]
            try:
                vmess_obj = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
                canonical = json.dumps(vmess_obj, sort_keys=True, separators=(",", ":"))
            except Exception:
                pass
        key = hashlib.sha256(canonical.encode()).hexdigest()
        record["id"] = key
        raw_records.append(record)
        if key in seen:
            continue
        seen.add(key)
        (unique_personal if record["personal"] else unique_external).append(record)
    if not unique_personal and not unique_external:
        raise RuntimeError("no configurations were extracted; previous subscriptions were not changed")
    (WORK / "records.json").write_text(json.dumps({"personal": unique_personal, "external": unique_external, "all_sources": raw_records}, ensure_ascii=False), encoding="utf-8")
    unique_total = len(unique_personal) + len(unique_external)
    duplicate_total = len(raw_records) - unique_total
    log(f"[PARSE] Ready for validation: personal={len(unique_personal)}, external={len(unique_external)}, total={unique_total}, duplicates_removed={duplicate_total}")
    if unique_total:
        by_protocol = {}
        for item in unique_personal + unique_external:
            by_protocol[item["protocol"]] = by_protocol.get(item["protocol"], 0) + 1
        log("[PARSE] Protocol distribution: " + json.dumps(by_protocol, sort_keys=True))


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def xray_config(record, port):
    uri = record["uri"]
    parsed = urllib.parse.urlsplit(uri)
    proto = record["protocol"]
    server = {"address": parsed.hostname, "port": parsed.port}
    if proto == "vmess":
        raw = uri.split("://", 1)[1].split("#", 1)[0]
        obj = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        server = {"address": obj.get("add") or obj.get("host"), "port": int(obj.get("port")), "users": [{"id": obj.get("id", ""), "alterId": int(obj.get("aid", 0)), "security": obj.get("scy", "auto")}]} 
        vmess_network = obj.get("net", "tcp")
        outbound = {"protocol": "vmess", "settings": {"vnext": [server]}, "streamSettings": {"network": "raw" if vmess_network == "tcp" else vmess_network}}
        if obj.get("tls"):
            outbound["streamSettings"]["security"] = "tls"
            outbound["streamSettings"]["tlsSettings"] = {"serverName": obj.get("sni") or obj.get("host") or parsed.hostname, "allowInsecure": False}
        if vmess_network == "ws":
            outbound["streamSettings"]["wsSettings"] = {"path": obj.get("path", "/"), "headers": {"Host": obj.get("host", "")}}
        elif vmess_network == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {"serviceName": obj.get("path", "")}
    elif proto in ("vless", "trojan"):
        q = urllib.parse.parse_qs(parsed.query)
        user = {"id": urllib.parse.unquote(parsed.username or ""), "encryption": "none"}
        if proto == "trojan":
            server["password"] = urllib.parse.unquote(parsed.username or "")
            outbound = {"protocol": "trojan", "settings": {"servers": [server]}}
        else:
            if q.get("flow"):
                user["flow"] = q["flow"][0]
            server["users"] = [user]
            outbound = {"protocol": "vless", "settings": {"vnext": [server]}}
        network = q.get("type", ["tcp"])[0]
        outbound["streamSettings"] = {"network": "raw" if network == "tcp" else network}
        security = q.get("security", [""])[0]
        if security == "tls":
            outbound["streamSettings"]["security"] = "tls"
            outbound["streamSettings"]["tlsSettings"] = {"serverName": q.get("sni", [parsed.hostname])[0], "allowInsecure": q.get("insecure", ["0"])[0] == "1", "fingerprint": q.get("fp", [""])[0]}
        elif security == "reality":
            outbound["streamSettings"]["security"] = "reality"
            outbound["streamSettings"]["realitySettings"] = {"serverName": q.get("sni", [parsed.hostname])[0], "fingerprint": q.get("fp", ["chrome"])[0], "password": q.get("pbk", [""])[0], "shortId": q.get("sid", [""])[0], "spiderX": q.get("spx", ["/"])[0]}
        if outbound["streamSettings"]["network"] == "ws":
            outbound["streamSettings"]["wsSettings"] = {"path": q.get("path", ["/"])[0], "headers": {"Host": q.get("host", [""])[0]}}
        elif outbound["streamSettings"]["network"] == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {"serviceName": q.get("serviceName", [""])[0]}
    elif proto == "ss":
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo, _ = netloc.rsplit("@", 1)
            try:
                decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
            except Exception:
                decoded = urllib.parse.unquote(userinfo)
            method, password = decoded.split(":", 1)
        else:
            decoded = base64.urlsafe_b64decode(netloc + "=" * (-len(netloc) % 4)).decode()
            auth, _ = decoded.rsplit("@", 1)
            method, password = auth.split(":", 1)
        outbound = {"protocol": "shadowsocks", "settings": {"servers": [{**server, "method": method, "password": password}]}}
    elif proto == "socks":
        users = []
        if parsed.username:
            users = [{"user": urllib.parse.unquote(parsed.username), "pass": urllib.parse.unquote(parsed.password or "")}]
        outbound = {"protocol": "socks", "settings": {"servers": [{**server, "users": users}]}}
    else:
        raise ValueError("protocol not supported by Xray")
    return {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": True}}], "outbounds": [outbound]}


def singbox_config(record, port):
    uri = urllib.parse.urlsplit(record["uri"])
    proto = record["protocol"]
    q = urllib.parse.parse_qs(uri.query)
    outbound = {"type": proto, "tag": "proxy", "server": uri.hostname, "server_port": uri.port}
    if proto == "vmess":
        obj = json.loads(base64.b64decode(record["uri"].split("://", 1)[1].split("#", 1)[0] + "=" * (-len(record["uri"].split("://", 1)[1].split("#", 1)[0]) % 4)))
        outbound.update(uuid=obj.get("id", ""), alter_id=int(obj.get("aid", 0)), security=obj.get("scy", "auto"))
    elif proto == "vless":
        outbound["uuid"] = urllib.parse.unquote(uri.username or "")
        if q.get("flow"):
            outbound["flow"] = q["flow"][0]
    elif proto == "trojan":
        outbound["password"] = urllib.parse.unquote(uri.username or "")
    elif proto == "ss":
        netloc = uri.netloc
        userinfo = netloc.rsplit("@", 1)[0]
        decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
        method, password = decoded.split(":", 1)
        outbound.update(method=method, password=password)
    elif proto == "socks":
        if uri.username:
            outbound.update(username=urllib.parse.unquote(uri.username), password=urllib.parse.unquote(uri.password or ""))
    elif proto == "hysteria2":
        outbound["password"] = urllib.parse.unquote(uri.username or "")
        if q.get("obfs"):
            outbound["obfs"] = {"type": q["obfs"][0], "password": q.get("obfs-password", [""])[0]}
    elif proto == "tuic":
        outbound.update(uuid=urllib.parse.unquote(uri.username or ""), password=urllib.parse.unquote(uri.password or ""), congestion_control=q.get("congestion_control", ["bbr"])[0], udp_relay_mode=q.get("udp_relay_mode", ["native"])[0])
    else:
        raise ValueError("protocol not supported by sing-box")
    if q.get("security", [""])[0] == "tls" or proto in ("tuic", "hysteria2"):
        tls = {"enabled": True, "server_name": q.get("sni", [uri.hostname])[0], "insecure": q.get("insecure", ["0"])[0] == "1"}
        outbound["tls"] = tls
    network = q.get("type", [""])[0]
    if network == "ws":
        outbound["transport"] = {"type": "ws", "path": q.get("path", ["/"])[0], "headers": {"Host": q.get("host", [""])[0]}}
    return {"log": {"disabled": True}, "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}], "outbounds": [outbound]}


def _run_test(record):
    proto = record["protocol"]
    if proto == "ssr":
        return {"id": record["id"], "status": "unsupported", "latency_ms": None, "reason": "SSR core is not installed"}
    core = "xray" if proto in ("vmess", "vless", "trojan", "ss", "socks") else "sing-box"
    binary = shutil.which(core)
    if not binary:
        return {"id": record["id"], "status": "unknown", "latency_ms": None, "reason": f"{core} binary unavailable"}
    port = free_port()
    temp = tempfile.TemporaryDirectory()
    config_path = Path(temp.name) / "config.json"
    process = None
    try:
        config = xray_config(record, port) if core == "xray" else singbox_config(record, port)
        config_path.write_text(json.dumps(config), encoding="utf-8")
        check_command = [binary, "check", "-c", str(config_path)] if core == "sing-box" else [binary, "run", "-test", "-c", str(config_path)]
        checked = subprocess.run(check_command, capture_output=True, text=True, timeout=5)
        if checked.returncode != 0:
            reason = (checked.stderr or checked.stdout or "invalid core configuration").strip().splitlines()[-1]
            return {"id": record["id"], "status": "unhealthy", "latency_ms": None, "reason": reason[:160]}
        command = [binary, "run", "-c", str(config_path)]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        start = time.monotonic()
        ready = False
        while time.monotonic() - start < 2:
            if process.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        if not ready:
            return {"id": record["id"], "status": "unhealthy", "latency_ms": None, "reason": "core failed to start"}
        curl = subprocess.run(["curl", "--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}|%{time_starttransfer}|%{time_total}", "--max-time", str(TIMEOUT), "--proxy", f"socks5h://127.0.0.1:{port}", "https://www.gstatic.com/generate_204"], capture_output=True, text=True, timeout=TIMEOUT + 2)
        parts = curl.stdout.strip().split("|")
        http_code = parts[0] if parts else ""
        try:
            latency_ms = round(float(parts[1]) * 1000) if len(parts) > 1 else None
            response_ms = round(float(parts[2]) * 1000) if len(parts) > 2 else None
        except (TypeError, ValueError):
            latency_ms, response_ms = None, None
        if curl.returncode == 0 and http_code in ("204", "200", "301", "302"):
            return {"id": record["id"], "status": "healthy", "latency_ms": latency_ms, "response_ms": response_ms, "reason": "https probe succeeded"}
        elapsed = round((time.monotonic() - start) * 1000)
        http_code = http_code or "no HTTP response"
        detail = (curl.stderr or "").strip().splitlines()[-1:]
        reason = f"probe failed: curl_exit={curl.returncode}, http={http_code}"
        if detail:
            reason += f", detail={detail[0][:100]}"
        return {"id": record["id"], "status": "unhealthy", "latency_ms": elapsed, "reason": reason[:160]}
    except subprocess.TimeoutExpired:
        return {"id": record["id"], "status": "unhealthy", "latency_ms": None, "reason": "probe timeout"}
    except Exception as exc:
        return {"id": record["id"], "status": "unhealthy", "latency_ms": None, "reason": str(exc)[:160]}
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=1)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        temp.cleanup()


def run_test(record, index=None, total=None):
    if index is not None and total is not None:
        source = record.get("source", "unknown")
        log(f"[TEST START] {index}/{total} | {record.get('protocol', 'unknown')} | source={source} | id={record.get('id', '')[:12]}")
    result = _run_test(record)
    if index is not None and total is not None:
        latency = result.get("latency_ms")
        latency_text = f"{latency} ms" if latency is not None else "n/a"
        reason = result.get("reason", "")
        log(f"[TEST RESULT] {index}/{total} | {result.get('status', 'unknown').upper()} | latency={latency_text} | reason={reason}")
    return result


def validate():
    data = json.loads((WORK / "records.json").read_text(encoding="utf-8"))
    records = data["personal"] + data["external"]
    total = len(records)
    personal_count = len(data["personal"])
    external_count = len(data["external"])
    results = {}
    log(f"[VALIDATION] Queue prepared: total={total}, personal={personal_count}, external={external_count}, workers={WORKERS}, timeout={TIMEOUT}s")
    if not records:
        raise RuntimeError("no configurations available for validation")
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(run_test, item, index, total): item for index, item in enumerate(records, 1)}
        done = 0
        counts = {"healthy": 0, "unhealthy": 0, "unsupported": 0, "unknown": 0}
        for future in concurrent.futures.as_completed(futures):
            item = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"id": item["id"], "status": "unknown", "latency_ms": None, "reason": str(exc)[:160]}
                log(f"[TEST RESULT] id={item['id'][:12]} | UNKNOWN | reason={result['reason']}")
            results[result["id"]] = result
            status = result.get("status", "unknown")
            counts[status] = counts.get(status, 0) + 1
            done += 1
            log(f"[VALIDATION PROGRESS] completed={done}/{total} | healthy={counts['healthy']} unhealthy={counts['unhealthy']} unsupported={counts['unsupported']} unknown={counts['unknown']} | remaining={total-done}")
    (WORK / "validation.json").write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
    log(f"[VALIDATION COMPLETE] total={len(results)} | " + json.dumps(counts, sort_keys=True))


def _config_sort_key(record, validation):
    result = validation.get(record["id"], {})
    latency = result.get("latency_ms")
    response = result.get("response_ms")
    return (
        latency is None,
        latency if latency is not None else float("inf"),
        response is None,
        response if response is not None else float("inf"),
        record.get("protocol", ""),
        record.get("id", ""),
    )


def _sort_records(records, validation):
    return sorted(records, key=lambda item: _config_sort_key(item, validation))


def source_stats(records, validation):
    stats = {}
    for record in records:
        source = record.get("source", "unknown")
        item = stats.setdefault(source, {
            "configs": 0, "healthy": 0, "unhealthy": 0,
            "unsupported": 0, "unknown": 0, "_latencies": [],
            "_responses": [],
        })
        item["configs"] += 1
        result = validation.get(record["id"], {})
        status = result.get("status", "unknown")
        if status in ("healthy", "unhealthy", "unsupported", "unknown"):
            item[status] += 1
        if status == "healthy":
            if isinstance(result.get("latency_ms"), (int, float)):
                item["_latencies"].append(result["latency_ms"])
            if isinstance(result.get("response_ms"), (int, float)):
                item["_responses"].append(result["response_ms"])
    for item in stats.values():
        tested = item["healthy"] + item["unhealthy"]
        item["score"] = round(item["healthy"] / tested * 100, 2) if tested else 0
        item["average_latency_ms"] = round(sum(item["_latencies"]) / len(item["_latencies"]), 2) if item["_latencies"] else None
        item["average_response_ms"] = round(sum(item["_responses"]) / len(item["_responses"]), 2) if item["_responses"] else None
        del item["_latencies"]
        del item["_responses"]
    ranked = sorted(stats.items(), key=lambda pair: (
        -pair[1]["score"],
        pair[1]["average_latency_ms"] is None,
        pair[1]["average_latency_ms"] if pair[1]["average_latency_ms"] is not None else float("inf"),
        -pair[1]["healthy"],
        pair[0],
    ))
    for rank, (_, item) in enumerate(ranked, 1):
        item["rank"] = rank
    return stats


def _write_b64(path, items):
    raw = "\n".join(item["uri"] for item in items)
    if raw:
        raw += "\n"
    path.write_bytes(base64.b64encode(raw.encode("utf-8")))


def _prune_zero_health_sources(download_status, quality):
    if os.getenv("REMOVE_ZERO_HEALTH_SOURCES", "false").lower() not in ("1", "true", "yes", "on"):
        return []
    source_path = CONFIGS / "external-sources.list"
    if not source_path.exists():
        return []
    remove_urls = {
        entry.get("url")
        for index, entry in enumerate(download_status, 1)
        if entry.get("status") == "success"
        and quality.get(f"external_{index:04d}.txt", {}).get("healthy", 0) == 0
        and entry.get("url")
    }
    if not remove_urls:
        return []
    kept, removed = [], []
    for raw in source_path.read_text(encoding="utf-8-sig").splitlines():
        if raw.strip() in remove_urls:
            removed.append(raw.strip())
        else:
            kept.append(raw)
    if removed:
        source_path.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")
    return sorted(set(removed))

def publish():
    data = json.loads((WORK / "records.json").read_text(encoding="utf-8"))
    validation = json.loads((WORK / "validation.json").read_text(encoding="utf-8"))
    personal, external = data["personal"], data["external"]
    all_records = personal + external
    raw_records = data.get("all_sources", all_records)

    healthy = _sort_records(
        [item for item in all_records if validation.get(item["id"], {}).get("status") == "healthy"],
        validation,
    )
    healthy_personal = [item for item in healthy if item.get("personal")]
    healthy_external = [item for item in healthy if not item.get("personal")]
    main_records = healthy[:MAX_EXTERNAL]
    status_records = {
        status: _sort_records(
            [item for item in all_records if validation.get(item["id"], {}).get("status", "unknown") == status],
            validation,
        )
        for status in ("healthy", "unhealthy", "unsupported", "unknown")
    }

    stage_output = ROOT / ".output-staging"
    if stage_output.exists():
        shutil.rmtree(stage_output)
    stage_output.mkdir()
    _write_b64(stage_output / "subscribe.txt", main_records)
    for status, items in status_records.items():
        _write_b64(stage_output / f"{status}.txt", items)
    proto_files = {}
    for proto in PROTO:
        candidates = [item for item in healthy if item.get("protocol") == proto]
        proto_files[proto] = candidates[:MAX_PER_PROTOCOL]
        _write_b64(stage_output / f"subscribe-{proto}.txt", proto_files[proto])

    if all_records and not main_records:
        shutil.rmtree(stage_output)
        raise RuntimeError("no healthy configurations were found; previous subscriptions were not changed")

    download_status = json.loads((WORK / "download_status.json").read_text(encoding="utf-8")) if (WORK / "download_status.json").exists() else []
    counts = {status: len(items) for status, items in status_records.items()}
    tested = counts["healthy"] + counts["unhealthy"]
    old_stats_path = ROOT / "stats.json"
    try:
        old = json.loads(old_stats_path.read_text(encoding="utf-8")) if old_stats_path.exists() else {}
    except Exception:
        old = {}
    history = old.get("history", [])
    for snapshot in history:
        if isinstance(snapshot, dict):
            snapshot.pop("added", None)
            snapshot.pop("removed", None)
    old.get("current", {}).pop("fingerprints", None)
    quality = source_stats(raw_records, validation)
    for index, entry in enumerate(download_status, 1):
        source = f"external_{index:04d}.txt"
        quality.setdefault(source, {
            "configs": 0, "healthy": 0, "unhealthy": 0, "unsupported": 0,
            "unknown": 0, "score": 0, "average_latency_ms": None,
            "average_response_ms": None,
        })
        quality[source].update(download_status=entry["status"], url=entry["url"], download_bytes=entry["bytes"])
        if entry.get("error"):
            quality[source]["download_error"] = entry["error"]

    ranked_sources = sorted(quality.items(), key=lambda pair: (
        pair[1].get("rank", 10**9), pair[0]
    ))
    zero_output_sources = [
        {"source": source, "url": item.get("url"), "download_status": item.get("download_status", "unknown"),
         "configs": item.get("configs", 0), "healthy": item.get("healthy", 0)}
        for source, item in quality.items()
        if source.startswith("external_") and item.get("healthy", 0) == 0
    ]
    current = {
        "sources": {
            "total": len(download_status),
            "successful": sum(x["status"] == "success" for x in download_status),
            "failed": sum(x["status"] != "success" for x in download_status),
            "zero_healthy": len(zero_output_sources),
        },
        "configs": {
            "discovered": len(raw_records), "unique": len(all_records), "tested": tested,
            "healthy": counts["healthy"], "unhealthy": counts["unhealthy"],
            "unsupported": counts["unsupported"], "unknown": counts["unknown"],
            "health_percentage": round(counts["healthy"] / len(all_records) * 100, 2) if all_records else 0,
            "tested_success_percentage": round(counts["healthy"] / tested * 100, 2) if tested else 0,
        },
        "published": {
            "main": len(main_records), "main_limit": MAX_EXTERNAL,
            "per_protocol_limit": MAX_PER_PROTOCOL,
            "by_protocol": {key: len(value) for key, value in proto_files.items()},
        },
        "source_quality": quality,
        "ranked_sources": [
            {"rank": item.get("rank"), "source": source, "url": item.get("url"),
             "score": item.get("score", 0), "healthy": item.get("healthy", 0),
             "average_latency_ms": item.get("average_latency_ms")}
            for source, item in ranked_sources
        ],
        "zero_output_sources": zero_output_sources,
    }
    (WORK / "ranked-records.json").write_text(json.dumps(status_records, ensure_ascii=False), encoding="utf-8")
    history.append({
        "date": datetime.now(timezone.utc).isoformat(),
        "discovered": len(raw_records), "unique": len(all_records),
        "healthy": counts["healthy"], "unhealthy": counts["unhealthy"],
        "unsupported": counts["unsupported"], "unknown": counts["unknown"],
        "published": len(main_records),
    })
    stats = {
        "project": "Freedom", "last_updated": datetime.now(timezone.utc).isoformat(),
        "current": current, "history": history[-HISTORY_LIMIT:],
    }
    temp_stats = ROOT / ".stats.json.tmp"
    temp_stats.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")

    backup_output = ROOT / ".output-previous"
    if backup_output.exists():
        shutil.rmtree(backup_output)
    if OUTPUT.exists():
        OUTPUT.replace(backup_output)
    try:
        stage_output.replace(OUTPUT)
    except Exception:
        if backup_output.exists() and not OUTPUT.exists():
            backup_output.replace(OUTPUT)
        raise
    if backup_output.exists():
        shutil.rmtree(backup_output)
    shutil.copyfile(OUTPUT / "subscribe.txt", ROOT / "subscribe.txt")
    temp_stats.replace(old_stats_path)
    (ROOT / ".timestamp").write_text(
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") + " - Subscription updated\n",
        encoding="utf-8",
    )
    removed = _prune_zero_health_sources(download_status, quality)
    if removed:
        log(f"[SOURCE CLEANUP] Removed {len(removed)} zero-healthy sources from external-sources.list")
    print(f"Main published: {len(main_records)} (limit {MAX_EXTERNAL})")
    print("Per-protocol: " + json.dumps({key: len(value) for key, value in proto_files.items()}))
    print("Status files: " + json.dumps({key: len(value) for key, value in status_records.items()}))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("download", "parse", "validate", "publish"))
    stage = parser.parse_args().stage
    {"download": download, "parse": parse_all, "validate": validate, "publish": publish}[stage]()

if __name__ == "__main__":
    main()
